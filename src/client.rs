use futures::{SinkExt, StreamExt};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::aux::random;
use crate::signer::{Protocol, Signer};

pub async fn start(addr: &str, tag: &str) -> String {
    let url = format!("ws://{addr}/ws");
    let (stream, _) = connect_async(&url)
        .await
        .expect("Failed to connect to server");
    println!("Connected to WebSocket server.");
    let (mut tx, mut rx) = stream.split();

    let secp = Secp256k1::new();
    let seckey = SecretKey::from_byte_array(&random()).expect("seckey");
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);

    let intro = Protocol::Intro {
        pubkey: hex::encode(pubkey.serialize()),
    };
    let json = serde_json::to_string(&intro).unwrap();

    tx.send(Message::Text(json.clone().into()))
        .await
        .expect("Failed to send message");
    println!("[{tag}] sent: {json}");

    let message = "The answer is 42".to_owned();
    let mut signer = Signer::new(3, pubkey, seckey, message);

    while let Some(Ok(Message::Text(text))) = rx.next().await {
        println!("[{tag}] rcvd: {}", text);
        let messages = signer.accept(&text).unwrap();
        for message in messages {
            if let Protocol::AggSig { aggsig } = message {
                println!("[{tag}] AGG SIG: {aggsig}");
                return aggsig;
            } else {
                let json = serde_json::to_string(&message).unwrap();
                tx.send(Message::Text(json.clone().into())).await.unwrap();
                println!("[{tag}] sent: {json}");
            }
        }
    }
    println!("Server closed connection.");
    "¯\\_(ツ)_/¯".to_owned()
}
