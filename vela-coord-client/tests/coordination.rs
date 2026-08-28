use std::time::Duration;
use tokio::net::TcpListener;
use vela_coord::CoordServer;
use vela_coord_client::CoordinationClient;
use vela_crypto::Identity;

#[tokio::test]
async fn client_registers_with_invite_and_verifies_server_credential() {
    let base = std::env::temp_dir().join(format!("vela-coord-client-test-{}", std::process::id()));
    let db = base.with_extension("db");
    let signer = base.with_extension("key");
    let server = CoordServer::open(&db, &signer, "integration").unwrap();
    let token = server.create_invite(60).unwrap();
    let server_key = server.server_public_key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move { server.serve(listener).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut client = CoordinationClient::connect(format!("ws://{address}/ws"))
        .await
        .unwrap();
    client.trust_server_key(server_key);
    let registration = client
        .register(&Identity::generate(), Some(&token), None, Vec::new())
        .await
        .unwrap();
    assert_eq!(registration.credential.tenant, "integration");

    server_task.abort();
    let _ = std::fs::remove_file(db);
    let _ = std::fs::remove_file(signer);
}
