use anyhow::Result;
use k8s_openapi::api::core::v1::Namespace;
use kube::{Api, Client};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) async fn serve_health(
    address: SocketAddr,
    healthy: Arc<AtomicBool>,
    client: Client,
    namespace: String,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(address).await?;
    loop {
        let (mut socket, _) = listener.accept().await?;
        let healthy = healthy.clone();
        let client = client.clone();
        let namespace = namespace.clone();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            let Ok(Ok(size)) =
                tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer)).await
            else {
                return;
            };
            let request = String::from_utf8_lossy(&buffer[..size]);
            let ready = if request.starts_with("GET /readyz ") {
                healthy.load(Ordering::Relaxed)
                    && tokio::time::timeout(
                        Duration::from_secs(2),
                        Api::<Namespace>::all(client).get(&namespace),
                    )
                    .await
                    .is_ok_and(|r| r.is_ok())
            } else if request.starts_with("GET /healthz ") {
                true
            } else {
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                return;
            };
            let response = if ready {
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n".as_slice()
            } else {
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
            };
            let _ = socket.write_all(response).await;
        });
    }
}
