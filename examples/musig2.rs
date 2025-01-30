use musig2::{
    secp::Scalar, CompactSignature, FirstRound, KeyAggContext, PartialSignature, PubNonce,
    SecNonceSpices, SecondRound,
};
use musig2_over_websockets::aux::random;
use secp256k1::{schnorr::Signature, PublicKey, Secp256k1, SecretKey};

fn main() {
    let secp = Secp256k1::new();

    let seckeys = [
        SecretKey::from_byte_array(&random()).expect("seckey 0"),
        SecretKey::from_byte_array(&random()).expect("seckey 1"),
        SecretKey::from_byte_array(&random()).expect("seckey 2"),
    ];

    let pubkeys = [
        seckeys[0].public_key(&secp),
        seckeys[1].public_key(&secp),
        seckeys[2].public_key(&secp),
    ];
    for (i, pk) in pubkeys.iter().enumerate() {
        println!("pub key {i}: {pk}");
    }
    println!("---");

    let signer_seckey = seckeys[2].clone();
    let signer_index = 2;

    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    println!("agg pub key: {aggregated_pubkey:?}");

    let seckeys_as_scalars = seckeys
        .iter()
        .map(|key| Scalar::from_slice(&key.secret_bytes()).unwrap())
        .collect::<Vec<_>>();
    let aggregated_seckey: SecretKey = key_agg_ctx.aggregated_seckey(seckeys_as_scalars).unwrap();
    println!(
        "agg SEC KEY: {}",
        hex::encode(&aggregated_seckey.secret_bytes())
    );
    println!("---");

    let message = "{\"question\": null, \"answer\": 42}";
    let nonce_seed: [u8; 32] = random();

    let mut first_round = FirstRound::new(
        key_agg_ctx.clone(),
        nonce_seed,
        signer_index,
        SecNonceSpices::new()
            .with_seckey(signer_seckey)
            .with_message(&message),
    )
    .unwrap();

    let signer_public_nonce: PubNonce = first_round.our_public_nonce();
    println!("signer pub nonce: {signer_public_nonce}");
    assert_eq!(first_round.holdouts(), &[0, 1]);

    let peer0_nonce_seed: [u8; 32] = random();
    let peer0_public_nonce: PubNonce = {
        let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
        let first_round = FirstRound::new(
            key_agg_ctx,
            peer0_nonce_seed,
            0,
            SecNonceSpices::new()
                .with_seckey(seckeys[0])
                .with_message(&message),
        )
        .unwrap();
        first_round.our_public_nonce()
    };
    println!("peer 0 pub nonce: {peer0_public_nonce}");

    let peer1_nonce_seed: [u8; 32] = random();
    let peer1_public_nonce: PubNonce = {
        let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
        let first_round = FirstRound::new(
            key_agg_ctx,
            peer1_nonce_seed,
            1,
            SecNonceSpices::new()
                .with_seckey(seckeys[1])
                .with_message(&message),
        )
        .unwrap();
        first_round.our_public_nonce()
    };
    println!("peer 1 pub nonce: {peer1_public_nonce}");

    first_round
        .receive_nonce(0, peer0_public_nonce.clone())
        .unwrap();
    first_round
        .receive_nonce(1, peer1_public_nonce.clone())
        .unwrap();
    first_round
        .receive_nonce(2, signer_public_nonce.clone())
        .unwrap();
    assert!(first_round.is_complete(), "first round");
    println!("---");

    let mut second_round: SecondRound<&str> = first_round.finalize(signer_seckey, message).unwrap();

    let signer_partial_signature: PartialSignature = second_round.our_signature();
    let aggregated_nonce = second_round.aggregated_nonce();
    musig2::verify_partial(
        &key_agg_ctx,
        signer_partial_signature,
        aggregated_nonce,
        pubkeys[2],
        &signer_public_nonce,
        message,
    )
    .expect("signer: valid partial signature");

    let peer0_partial_signature: PartialSignature = {
        let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
        let mut first_round = FirstRound::new(
            key_agg_ctx.clone(),
            peer0_nonce_seed,
            0,
            SecNonceSpices::new()
                .with_seckey(seckeys[0])
                .with_message(&message),
        )
        .unwrap();
        first_round
            .receive_nonce(0, first_round.our_public_nonce())
            .unwrap();
        first_round
            .receive_nonce(1, peer1_public_nonce.clone())
            .unwrap();
        first_round
            .receive_nonce(2, signer_public_nonce.clone())
            .unwrap();
        let second_round = first_round.finalize(seckeys[0], message).unwrap();
        let partial_signature = second_round.our_signature();

        let aggregated_nonce = second_round.aggregated_nonce();
        musig2::verify_partial(
            &key_agg_ctx,
            partial_signature,
            aggregated_nonce,
            pubkeys[0],
            &peer0_public_nonce,
            message,
        )
        .expect("peer 0: valid partial signature");
        partial_signature
    };
    println!(
        "peer 0 par sig: {}",
        hex::encode(&peer0_partial_signature.serialize())
    );

    let peer1_partial_signature: PartialSignature = {
        let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
        let mut first_round = FirstRound::new(
            key_agg_ctx.clone(),
            peer1_nonce_seed,
            1,
            SecNonceSpices::new()
                .with_seckey(seckeys[1])
                .with_message(&message),
        )
        .unwrap();
        first_round
            .receive_nonce(0, peer0_public_nonce.clone())
            .unwrap();
        first_round
            .receive_nonce(1, first_round.our_public_nonce())
            .unwrap();
        first_round
            .receive_nonce(2, signer_public_nonce.clone())
            .unwrap();
        let second_round = first_round.finalize(seckeys[1], message).unwrap();
        let partial_signature = second_round.our_signature();

        let aggregated_nonce = second_round.aggregated_nonce();
        musig2::verify_partial(
            &key_agg_ctx,
            partial_signature,
            aggregated_nonce,
            pubkeys[1],
            &peer1_public_nonce,
            message,
        )
        .expect("peer 1: valid partial signature");
        partial_signature
    };
    println!(
        "peer 1 par sig: {}",
        hex::encode(&peer1_partial_signature.serialize())
    );

    second_round
        .receive_signature(0, peer0_partial_signature)
        .unwrap();
    second_round
        .receive_signature(1, peer1_partial_signature)
        .unwrap();
    assert!(second_round.is_complete(), "second round");

    let final_signature: CompactSignature = second_round.finalize().unwrap();
    println!("---");
    println!("agg sig: {}", hex::encode(final_signature.serialize()));

    musig2::verify_single(aggregated_pubkey, final_signature, message).expect("final sig");
    println!("agg sig: OK");

    let msg = message.as_bytes();
    let sig = Signature::from_byte_array(final_signature.serialize());
    let pubkey = aggregated_pubkey.x_only_public_key().0;
    secp.verify_schnorr(&sig, msg, &pubkey)
        .expect("Schnorr signature is valid");
    println!("Schnorr: OK");
}
