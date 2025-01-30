use futures::future::join_all;
use musig2_over_websockets::{client, server};
use std::collections::HashSet;

#[tokio::test]
pub async fn musig2() {
    let addr = "127.0.0.1:8080";

    tokio::spawn(async {
        server::start(addr).await;
    });

    const N: u64 = 3;
    let results = join_all((0..N).into_iter().map(|i| async move {
        sleep(i * 200).await;
        let tag = format!("client {i}");
        client::start(addr, &tag).await
    }))
    .await;

    let set = results.into_iter().collect::<HashSet<_>>();
    assert_eq!(
        set.len(),
        1,
        "aggregated signature must match for all clients"
    );
    let one = set.into_iter().next().unwrap();
    let hex = hex::decode(&one).unwrap();
    assert_eq!(
        hex.len(),
        64,
        "aggregated signature must be 64 bytes hex string"
    );
}

async fn sleep(secs: u64) {
    tokio::time::sleep(std::time::Duration::from_millis(secs)).await;
}
