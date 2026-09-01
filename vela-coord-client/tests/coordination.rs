use std::time::Duration;
use tokio::net::TcpListener;
use vela_coord::CoordServer;
use vela_coord_client::CoordinationClient;
use vela_crypto::Identity;
use vela_proto::ControlMessage;

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

#[tokio::test]
async fn client_reconnects_and_reregisters_with_existing_credential() {
    let base = std::env::temp_dir().join(format!(
        "vela-coord-client-reconnect-test-{}",
        std::process::id()
    ));
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
    let identity = Identity::generate();
    let registration = client
        .register(&identity, Some(&token), None, Vec::new())
        .await
        .unwrap();

    let reconnected = client
        .reconnect(
            &identity,
            1,
            Some(&registration.credential),
            Vec::new(),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(reconnected.credential.node_id, identity.public().node_id);
    assert_eq!(reconnected.credential.tenant, "integration");

    server_task.abort();
    let _ = std::fs::remove_file(db);
    let _ = std::fs::remove_file(signer);
}

#[tokio::test]
async fn clients_discover_online_peers_and_receive_connect_signal() {
    let base = std::env::temp_dir().join(format!(
        "vela-coord-client-discovery-test-{}",
        std::process::id()
    ));
    let db = base.with_extension("db");
    let signer = base.with_extension("key");
    let server = CoordServer::open(&db, &signer, "integration").unwrap();
    let token_a = server
        .create_invite_with_metadata("laptop-a", "", 60)
        .unwrap()
        .invite_token;
    let token_b = server
        .create_invite_with_metadata("laptop-b", "", 60)
        .unwrap()
        .invite_token;
    let server_key = server.server_public_key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move { server.serve(listener).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut client_a = CoordinationClient::connect(format!("ws://{address}/ws"))
        .await
        .unwrap();
    client_a.trust_server_key(server_key);
    let identity_a = Identity::generate();
    let registration_a = client_a
        .register(&identity_a, Some(&token_a), None, Vec::new())
        .await
        .unwrap();

    let mut client_b = CoordinationClient::connect(format!("ws://{address}/ws"))
        .await
        .unwrap();
    client_b.trust_server_key(server_key);
    let identity_b = Identity::generate();
    let registration_b = client_b
        .register(&identity_b, Some(&token_b), None, Vec::new())
        .await
        .unwrap();
    assert!(
        registration_b
            .peers
            .iter()
            .any(|peer| peer.node_id == identity_a.public().node_id)
    );
    assert!(
        registration_b
            .snapshot
            .online_peers
            .contains(&identity_a.public().node_id)
    );
    assert!(
        registration_b
            .snapshot
            .online_peers
            .contains(&identity_b.public().node_id)
    );

    client_b.update_candidates(Vec::new()).await.unwrap();
    let snapshot_a = tokio::time::timeout(Duration::from_secs(1), client_a.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(snapshot_a, ControlMessage::Snapshot { .. }));

    let peers = client_b.list_peers().await.unwrap();
    assert!(peers.iter().any(|peer| {
        peer.node_id == identity_a.public().node_id
            && peer.name == "laptop-a"
            && peer.online
            && peer.virtual_ipv4
                == registration_b
                    .snapshot
                    .peers
                    .iter()
                    .find(|value| value.node_id == identity_a.public().node_id)
                    .and_then(|value| value.virtual_ipv4)
    }));
    assert!(matches!(
        client_b.recv().await.unwrap(),
        ControlMessage::Snapshot { .. }
    ));

    let target = client_b
        .lookup_peer(identity_a.public().node_id)
        .await
        .unwrap();
    assert_eq!(target.node_id, identity_a.public().node_id);
    let signal = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let ControlMessage::ConnectSignal { from, to } = client_a.recv().await.unwrap() {
                break (from, to);
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(signal.0.node_id, identity_b.public().node_id);
    assert_eq!(signal.1, identity_a.public().node_id);

    let mut client_a_control = CoordinationClient::connect(format!("ws://{address}/ws"))
        .await
        .unwrap();
    client_a_control.trust_server_key(server_key);
    client_a_control
        .register(
            &identity_a,
            None,
            Some(&registration_a.credential),
            Vec::new(),
        )
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), client_b.recv())
            .await
            .unwrap()
            .unwrap(),
        ControlMessage::Snapshot { .. }
    ));
    drop(client_a_control);
    tokio::time::sleep(Duration::from_millis(20)).await;

    drop(client_a);
    let offline_snapshot = tokio::time::timeout(Duration::from_secs(1), client_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        offline_snapshot,
        ControlMessage::Snapshot { ref snapshot }
            if !snapshot.online_peers.contains(&identity_a.public().node_id)
    ));

    let peers = client_b.list_peers().await.unwrap();
    assert!(
        peers
            .iter()
            .any(|peer| { peer.node_id == identity_a.public().node_id && !peer.online })
    );

    server_task.abort();
    let _ = std::fs::remove_file(db);
    let _ = std::fs::remove_file(signer);
}
