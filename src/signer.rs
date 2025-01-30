use musig2::{
    errors::{DecodeError, RoundContributionError, RoundFinalizeError, SignerIndexError},
    secp::errors::InvalidScalarString,
    CompactSignature, FirstRound, KeyAggContext, PartialSignature, PubNonce, SecNonceSpices,
    SecondRound,
};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::aux::random;

#[derive(Serialize, Deserialize)]
pub enum Protocol {
    Intro {
        pubkey: String,
    },
    Setup {
        pubkeys: Vec<String>,
        message: String,
    },
    Nonce {
        pubkey: String,
        pubnonce: String,
    },
    ParSig {
        pubkey: String,
        parsig: String,
    },
    AggSig {
        aggsig: String,
    },
}

pub struct Signer {
    parties: usize,
    pubkey: PublicKey,
    seckey: SecretKey,
    message: String,
    known: Vec<PublicKey>,
    round1: Option<FirstRound>,
    round2: Option<SecondRound<String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("secp256k1 error: {0}")]
    Crypto(#[from] secp256k1::Error),
    #[error("signer error: {0}")]
    Signer(#[from] SignerIndexError),
    #[error("round 1 error: {0}")]
    R1Contribution(#[from] RoundContributionError),
    #[error("pub nonce error: {0}")]
    Nonce(#[from] DecodeError<PubNonce>),
    #[error("par sig error: {0}")]
    ParSig(#[from] InvalidScalarString),
    #[error("round 1 finalize")]
    R1Finalize(#[from] RoundFinalizeError),
}

impl Signer {
    pub fn new(parties: usize, pubkey: PublicKey, seckey: SecretKey, message: String) -> Self {
        let mut known = Vec::with_capacity(parties);
        known.push(pubkey);
        Self {
            parties,
            pubkey,
            seckey,
            message,
            known,
            round1: None,
            round2: None,
        }
    }

    fn r1_done(&self) -> bool {
        self.round1
            .as_ref()
            .map(|r| r.is_complete())
            .unwrap_or_default()
    }

    fn r2_done(&self) -> bool {
        self.round2
            .as_ref()
            .map(|r| r.is_complete())
            .unwrap_or_default()
    }

    pub fn accept(&mut self, json: &str) -> Result<Vec<Protocol>, Error> {
        let protocol: Protocol = serde_json::from_str(json)?;
        match protocol {
            Protocol::Intro { pubkey } if self.known.len() < self.parties => {
                let pubkey = PublicKey::from_str(&pubkey)?;
                self.known.push(pubkey);
                if self.known.len() == self.parties {
                    let signer_index = index_of(&self.known, &self.pubkey).unwrap();
                    let key_agg_ctx = KeyAggContext::new(self.known.clone()).unwrap();
                    let mut round1 = FirstRound::new(
                        key_agg_ctx.clone(),
                        random(),
                        signer_index,
                        SecNonceSpices::new()
                            .with_seckey(self.seckey)
                            .with_message(&self.message),
                    )?;
                    let pubnonce = round1.our_public_nonce();
                    round1.receive_nonce(signer_index, pubnonce.clone())?;
                    self.round1 = Some(round1);

                    let setup = Protocol::Setup {
                        pubkeys: self.known.iter().map(|pk| pk.to_string()).collect(),
                        message: self.message.clone(),
                    };
                    let nonce = Protocol::Nonce {
                        pubkey: self.pubkey.to_string(),
                        pubnonce: hex::encode(pubnonce.serialize()),
                    };
                    return Ok(vec![setup, nonce]);
                }
            }
            Protocol::Setup { pubkeys, message }
                if self.round1.is_none() && self.round2.is_none() =>
            {
                let pubkeys: Result<Vec<PublicKey>, _> = pubkeys
                    .into_iter()
                    .map(|pk| PublicKey::from_str(&pk))
                    .collect();
                let pubkeys = pubkeys?;
                self.known = pubkeys;
                self.message = message;

                let signer_index = index_of(&self.known, &self.pubkey).unwrap();
                let key_agg_ctx = KeyAggContext::new(self.known.clone()).unwrap();
                let mut round1 = FirstRound::new(
                    key_agg_ctx.clone(),
                    random(),
                    signer_index,
                    SecNonceSpices::new()
                        .with_seckey(self.seckey)
                        .with_message(&self.message),
                )?;
                let pubnonce = round1.our_public_nonce();
                round1.receive_nonce(signer_index, pubnonce.clone())?;
                self.round1 = Some(round1);

                let nonce = Protocol::Nonce {
                    pubkey: self.pubkey.to_string(),
                    pubnonce: hex::encode(pubnonce.serialize()),
                };
                return Ok(vec![nonce]);
            }
            Protocol::Nonce { pubkey, pubnonce } if !self.r1_done() => {
                let pubkey = PublicKey::from_str(&pubkey)?;
                let pubnonce = PubNonce::from_hex(&pubnonce)?;
                let mut round1 = self.round1.take().unwrap();

                let signer_index = index_of(&self.known, &pubkey).unwrap();
                round1.receive_nonce(signer_index, pubnonce)?;

                if !round1.is_complete() {
                    self.round1 = Some(round1);
                    return Ok(vec![]);
                }
                let round2 = round1.finalize(self.seckey, self.message.clone())?;
                let sig: PartialSignature = round2.our_signature();
                self.round2 = Some(round2);

                let parsig = Protocol::ParSig {
                    pubkey: self.pubkey.to_string(),
                    parsig: hex::encode(sig.serialize()),
                };
                return Ok(vec![parsig]);
            }
            Protocol::ParSig { pubkey, parsig } if !self.r2_done() => {
                let pubkey = PublicKey::from_str(&pubkey)?;
                let parsig: PartialSignature = PartialSignature::from_hex(&parsig)?;

                let mut round2 = self.round2.take().unwrap();
                let signer_index = index_of(&self.known, &pubkey).unwrap();
                round2.receive_signature(signer_index, parsig)?;

                if !round2.is_complete() {
                    self.round2 = Some(round2);
                    return Ok(vec![]);
                }

                let sig: CompactSignature = round2.finalize()?;
                let fullsig = Protocol::AggSig {
                    aggsig: hex::encode(sig.serialize()),
                };
                return Ok(vec![fullsig]);
            }
            _ => (),
        };
        Ok(vec![])
    }
}

fn index_of<'a, T>(items: &'a [T], item: &'a T) -> Option<usize>
where
    &'a T: PartialEq<&'a T> + 'a,
{
    items
        .iter()
        .enumerate()
        .find(|(_, x)| x == &item)
        .map(|(idx, _)| idx)
}
