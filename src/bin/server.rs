use musig2_over_websockets::server;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    server::start("127.0.0.1:8080").await;
}
