//! Actual C1 runtime handlers, bounded peer3 bytes and once-only producer/receiver phases.
use super::*;
use crate::native_poash::application::phase_evidence as producer_phases;
use crate::native_transfer::phase_evidence as native_phases;
use tempfile::TempDir;
fn key(n: u8) -> SigningKey {
    let mut b = [0; 32];
    b[31] = n;
    SigningKey::from_slice(&b).unwrap()
}
fn g() -> Genesis {
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native_poash_eligibility.json"
    ))
    .unwrap();
    Genesis::from_bytes(
        &hex::decode(
            f["genesis"]["hex_parts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<String>(),
        )
        .unwrap(),
    )
    .unwrap()
}
fn node(d: &Path, g: &Genesis, signer: Option<(&Path, &str, u8)>) -> Node {
    let store = PoashTrialStore::create(d.join("c1.sqlite"), g).unwrap();
    let signer =
        signer.map(|(root, id, n)| SigningAuthority::create(root, g, id, key(n), &store).unwrap());
    Node {
        id: "test-node".into(),
        g: g.clone(),
        store,
        signer,
        plan: vec![vec![]; 200],
        peers: vec![],
        request: 0,
        halted: false,
        available: true,
        timings: vec![],
        _archive_fence: OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(d.join("process.lock"))
            .unwrap(),
    }
}
fn signed_block(g: &Genesis, block: app::Block, n: u8) -> Vec<u8> {
    let signature = crate::block_authentication::sign_digest(
        &key(n),
        &block.claim().signing_digest(g.network_id()),
    )
    .unwrap();
    app::Envelope::from_parts(block, g.network_id(), signature).wire_bytes()
}
fn reset() {
    native_phases::reset();
    producer_phases::reset();
    super::super::signing::phase_evidence::reset();
}
#[test]
fn independent_peer3_frames_and_strict_dispatch_widths_do_not_reinterpret_m1() {
    let g = g();
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native_poash_signing.json"
    ))
    .unwrap();
    for v in f["frames"].as_array().unwrap() {
        let bytes = hex::decode(
            v["wire_parts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect::<String>(),
        )
        .unwrap();
        let message = Message::from_bytes(&bytes, &g).unwrap();
        assert_eq!(message.bytes(&g), bytes);
        assert_eq!(message.kind() as u64, v["kind"]);
        assert_eq!(hex::encode(message.body()), v["body"]);
        assert_eq!(
            hex::encode(crate::block_commitment::keccak256(&bytes)),
            v["keccak"]
        );
        for n in 0..bytes.len() {
            assert!(Message::from_bytes(&bytes[..n], &g).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Message::from_bytes(&extra, &g).is_err());
        for offset in [0, 7, 8, 10, 12, 16, 20, 24, 32, 72, 75, 76, 127] {
            let mut bad = bytes.clone();
            bad[offset] ^= 0x80;
            assert!(
                Message::from_bytes(&bad, &g).is_err(),
                "{} offset={offset}",
                v["name"]
            );
        }
    }
    assert!(Message::new(Kind::Get, 1, 0u64.to_be_bytes().to_vec()).is_err());
    assert!(Message::new(Kind::Get, 1, 201u64.to_be_bytes().to_vec()).is_err());
    assert!(Message::new(Kind::Status, 0, vec![]).is_err());
    let mut old = Message::new(Kind::Status, 1, vec![]).unwrap().bytes(&g);
    old[8] = 1;
    assert!(Message::from_bytes(&old, &g).is_err());
    old[8] = 2;
    assert!(Message::from_bytes(&old, &g).is_err());
}
#[test]
fn pacing_cannot_choose_a_producer_ticket_hash_or_skip_and_nonselected_has_no_native_effects() {
    let d = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = g();
    let mut b = node(d.path(), &g, Some((root.path(), "trial-B", 5)));
    let old = b.store.snapshot().unwrap().clone();
    reset();
    assert_eq!(
        b.handle(Command::Advance { slot: 1 })["result"]["outcome"],
        "not_selected"
    );
    assert_eq!(native_phases::stages(), 0);
    assert_eq!(producer_phases::count(), 0);
    assert_eq!(super::super::signing::phase_evidence::count(), 0);
    assert_eq!(b.store.snapshot().unwrap(), &old);
    for extra in [
        json!({"command":"advance","slot":1,"producer":"trial-B"}),
        json!({"command":"advance","slot":1,"hash":"00"}),
        json!({"command":"advance","slot":1,"ticket":255}),
        json!({"command":"stop","unexpected":1}),
    ] {
        assert!(serde_json::from_value::<Command>(extra).is_err());
    }
    assert_eq!(b.handle(Command::Advance { slot: 2 })["ok"], false);
    assert_eq!(b.store.snapshot().unwrap(), &old);
    assert_eq!(
        b.handle(Command::State {
            offset: 0,
            length: 1025
        })["ok"],
        false
    );
}
#[test]
fn authenticated_nonselected_and_duplicate_live_receives_do_not_change_economics_or_originals() {
    let d = TempDir::new().unwrap();
    let g = g();
    let mut o = node(d.path(), &g, None);
    let selection = o.store.slot_start().unwrap().select().unwrap();
    let selected = o
        .store
        .prepare_next(selection.producer(), selection.ticket_id(), &[])
        .unwrap()
        .block()
        .clone();
    let mut h = selected.claim().header().clone();
    h.proposer_id = crate::block_commitment::proposer_id("trial-B");
    h.ticket_id = 255;
    let wrong = app::Block::from_parts(
        h,
        "trial-B".into(),
        crate::block_commitment::ProtocolData::empty(),
        vec![],
    )
    .unwrap();
    let wrong = signed_block(&g, wrong, 5);
    let old = o.store.snapshot().unwrap().clone();
    reset();
    assert!(o.receive(&wrong, 0, "test_receive").is_err());
    assert_eq!(producer_phases::count(), 1);
    assert_eq!(native_phases::stages(), 0);
    assert_eq!(o.store.snapshot().unwrap(), &old);
    assert!(!o.halted);
    let bytes = signed_block(&g, selected, 2);
    reset();
    assert_eq!(o.receive(&bytes, 0, "test_receive").unwrap()[72], 1);
    assert_eq!(producer_phases::count(), 1);
    assert_eq!(native_phases::stages(), 1);
    let expected = o.store.snapshot().unwrap().clone();
    reset();
    assert_eq!(o.receive(&bytes, 0, "test_receive").unwrap()[72], 0);
    assert_eq!(producer_phases::count(), 1);
    assert_eq!(native_phases::stages(), 0);
    assert_eq!(o.store.snapshot().unwrap(), &expected);
    assert_eq!(o.store.export_envelope(1).unwrap(), bytes);
}
#[test]
fn protected_runtime_commits_before_socket_publication_and_replies_retain_original_without_signing()
{
    let a_dir = TempDir::new().unwrap();
    let r_dir = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = g();
    let mut a = node(a_dir.path(), &g, Some((root.path(), "trial-A", 2)));
    let receiver_path = r_dir.path().to_owned();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    a.peers.push(PeerConfig {
        id: "observer".into(),
        address,
    });
    let g2 = g.clone();
    let worker = thread::spawn(move || {
        // The SQLite owner stays on its creating thread, exactly as in the process runtime.
        let mut receiver = node(&receiver_path, &g2, None);
        reset();
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().unwrap();
            let end = Instant::now() + peer::IO_TIMEOUT;
            let message = peer::read(&mut socket, &g2, end).unwrap();
            let response = receiver.peer(message, 0).unwrap();
            peer::write(&mut socket, &g2, &response, end).unwrap();
        }
        (
            receiver.store.snapshot().unwrap().clone(),
            producer_phases::count(),
            native_phases::stages(),
        )
    });
    reset();
    let reply = a.handle(Command::Advance { slot: 1 });
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["result"]["outcome"], "committed");
    assert_eq!(super::super::signing::phase_evidence::count(), 1);
    assert_eq!(native_phases::stages(), 1);
    assert_eq!(producer_phases::count(), 1);
    let duplicate = a.handle(Command::Advance { slot: 1 });
    assert_eq!(duplicate["result"]["outcome"], "retained_committed");
    assert_eq!(super::super::signing::phase_evidence::count(), 1);
    assert_eq!(native_phases::stages(), 1);
    assert_eq!(producer_phases::count(), 1);
    a.publish(1).unwrap();
    let (snapshot, auth, stage) = worker.join().unwrap();
    assert_eq!((auth, stage), (2, 1));
    assert_eq!(a.store.snapshot().unwrap(), &snapshot);
    assert_eq!(a.timings[0].action, "advance");
    assert!(a.timings[0].commit_ns > 0);
    assert!(a.timings[0].publication_ns > 0);
}
#[test]
fn partial_peer_frame_has_one_absolute_operational_deadline_without_owner_work() {
    let g = g();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let client = thread::spawn(move || {
        let mut s = std::net::TcpStream::connect(address).unwrap();
        s.write_all(&peer::MAGIC[..1]).unwrap();
        thread::sleep(Duration::from_millis(100));
    });
    let (mut socket, _) = listener.accept().unwrap();
    let start = Instant::now();
    assert!(peer::read(&mut socket, &g, start + Duration::from_millis(30)).is_err());
    assert!(start.elapsed() < Duration::from_millis(100));
    client.join().unwrap();
}
