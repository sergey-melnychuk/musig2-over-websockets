use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{stream::SplitSink, SinkExt, StreamExt};
use std::{collections::HashMap, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex};

type Ctx = Arc<Mutex<Context>>;

type Sink = SplitSink<WebSocket, Message>;

#[derive(Default)]
pub struct Context {
    seq: usize,
    clients: HashMap<usize, Sink>,
}

impl Context {
    fn add(&mut self, sender: Sink) -> usize {
        self.seq += 1;
        self.clients.insert(self.seq, sender);
        self.seq
    }
}

async fn ws_handler(ws: WebSocketUpgrade, app: Ctx) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, app))
}

async fn handle_socket(socket: WebSocket, app: Ctx) {
    let (tx, mut rx) = socket.split();
    let id = app.lock().await.add(tx);

    while let Some(Ok(Message::Text(text))) = rx.next().await {
        tracing::debug!("Received: {}", text);
        let message = Message::Text(text);
        for (sink_id, sink) in app.lock().await.clients.iter_mut() {
            if id == *sink_id {
                continue;
            }
            let _ = sink.send(message.clone()).await;
        }
    }

    app.lock().await.clients.remove(&id);
    tracing::debug!("Client disconnected");
}

pub async fn start(addr: &str) {
    let clients = Arc::new(Mutex::new(Context::default()));

    let service = Router::new().route("/ws", get(move |ws| ws_handler(ws, clients.clone())));

    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::info!("WebSocket server running on ws://{addr}/ws");

    axum::serve(listener, service).await.expect("axum server")
}
