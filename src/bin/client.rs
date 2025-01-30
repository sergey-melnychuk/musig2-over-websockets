use musig2_over_websockets::client;

#[tokio::main]
async fn main() {
    client::start("127.0.0.1:8080", "client").await;
}
