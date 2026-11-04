//! S4 uses the actual serialized transport/operator owner, not a second mutation implementation.
//! Faults below occur in SQLite's real platform callbacks. The small rollback case deliberately
//! flushes dirty pages before rollback; it is not a natural-spill/capacity or power-loss claim.
use super::worker_s2::{
    approve, build, evidence, inputs, prepare_proposal, profile, reset_all, worker,
};
use super::*;
use crate::durable_fixture::tests::vfs::Harness;
use rusqlite::ffi;
use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use worker::transport::{TestRuntime, codec};

fn config(d: &Path) -> (PathBuf, u16) {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserve.local_addr().unwrap().port();
    drop(reserve);
    let path = d.join("peers.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({"format":"eternix-fixture-peers-v1","node_id":3,
        "listen":format!("127.0.0.1:{port}"),"peers":[{"node_id":2,"endpoint":"127.0.0.1:1"}]}))
        .unwrap(),
    )
    .unwrap();
    (path, port)
}
fn command(r: &mut TestRuntime, name: &str) -> Value {
    r.command(json!({"command":name}))
}
fn until(r: &mut TestRuntime, mut done: impl FnMut(&mut TestRuntime) -> bool) {
    let start = Instant::now();
    while !done(r) {
        assert!(start.elapsed() < Duration::from_secs(10));
        r.tick();
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn peer(r: &mut TestRuntime, port: u16) -> TcpStream {
    let mut s = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(
        &codec::encode(
            &codec::Context::new(2, &profile()),
            codec::Kind::Status,
            &codec::status(profile().anchor_tip()),
        )
        .unwrap(),
    )
    .unwrap();
    until(r, |r| {
        command(r, "peer_status")["result"]["connections"][0]["ready"] == true
    });
    // Drain the source's handshake. The next read is always the explicit session's request.
    for _ in 0..3 {
        r.tick();
    }
    read_frame(&mut s);
    s
}
fn read_frame(s: &mut impl Read) -> Vec<u8> {
    let mut h = [0; 144];
    s.read_exact(&mut h).unwrap();
    let n = u32::from_be_bytes(h[8..12].try_into().unwrap()) as usize;
    assert!(n <= 3664);
    let mut body = vec![0; n];
    s.read_exact(&mut body).unwrap();
    body
}
fn blocked(r: &mut TestRuntime) {
    for v in [
        json!({"command":"status"}),
        json!({"command":"account","address":"00".repeat(20)}),
        json!({"command":"inspect","section":"records","offset":0,"limit":1}),
        json!({"command":"export","revision":1}),
        json!({"command":"pool","offset":0,"limit":16}),
        json!({"command":"prepare"}),
        json!({"command":"propose"}),
        json!({"command":"commit_prepared","selection":1}),
        json!({"command":"publish","revision":1}),
        json!({"command":"retransmit","node_id":2,"revision":1}),
    ] {
        assert_eq!(r.command(v)["ok"], false);
    }
    let s = command(r, "peer_status");
    assert_eq!(s["result"]["owner_available"], false);
    assert_eq!(s["result"]["connections"], json!([]));
    assert_eq!(s["result"]["buffered_bytes"], 0);
    assert_eq!(s["result"]["fresh_publications"], 0);
}

#[test]
fn actual_owner_commit_rollback_and_recovery_barrier_io_failures_reconcile_exact_attempts() {
    for mode in ["commit", "rollback", "durable_publication_gap"] {
        let d = TempDir::new_in("target").unwrap();
        let p = profile();
        let v = Harness::new(); // MUST outlive the store/runtime, including failed recovery connections.
        let path = d.path().join("archive.sqlite");
        let mut store =
            AuthenticatedFixtureStore::create_inner(&path, &p.manifest, Some(v.name()), |_| Ok(()))
                .unwrap();
        let handle = unsafe { store.conn().handle() };
        let mut commit_fault = v.arm_next_callback("xsync", ffi::SQLITE_IOERR_FSYNC, false);
        let mut rollback_fault = v.arm_next_callback("xwrite", ffi::SQLITE_IOERR_WRITE, true);
        let mut barrier_fault = v.arm_next_callback("xsync", ffi::SQLITE_IOERR_FSYNC, true);
        let barrier = Arc::new(AtomicBool::new(true));
        let gate = barrier.clone();
        let mut fired = false;
        store.hook = Some(Box::new(move |phase| {
            if !fired
                && phase
                    == match mode {
                        "commit" => "before_commit",
                        "rollback" => "indexes",
                        _ => "after_commit",
                    }
            {
                fired = true;
                match mode {
                    "commit" => commit_fault(),
                    "rollback" => {
                        // This pointer is used only while the original owner connection is alive,
                        // after the SQL statement returns. Flush forces REAL restoration writes at
                        // default cache/EXTRA; the subsequent failure is in xWrite, not this hook.
                        assert_eq!(
                            unsafe { ffi::sqlite3_db_cacheflush(handle) },
                            ffi::SQLITE_OK
                        );
                        rollback_fault();
                        return Err(invalid("test requests rollback after real cache flush"));
                    }
                    _ => return Err(invalid("test withholds publication after durable COMMIT")),
                }
            }
            if phase == "recovery_barrier" && gate.load(Ordering::SeqCst) {
                barrier_fault();
            }
            Ok(())
        }));
        let mut w = build(store);
        for tx in inputs(2) {
            assert_eq!(w.test_command(tx)["ok"], true);
        }
        let original = prepare_proposal(&mut w);
        approve(&mut w, &d, &original);
        let (config, port) = config(d.path());
        let mut r = TestRuntime::new(w, &config).unwrap();
        let _peer = peer(&mut r, port);
        v.reset();
        let began = Instant::now();
        let failed = r.command(json!({"command":"commit_prepared","selection":1}));
        let fault_us = began.elapsed().as_micros();
        assert_eq!(
            failed["error"]["kind"], "recovery_required",
            "{mode}: {failed}"
        );
        assert!(failed.get("result").is_none());
        blocked(&mut r);
        let events = v.events();
        if mode == "commit" {
            assert!(events.iter().any(|e| e.kind == "xsync"));
        }
        if mode == "rollback" {
            assert!(
                events
                    .iter()
                    .filter(
                        |e| e.kind == "xwrite" && !e.path.to_string_lossy().ends_with("-journal")
                    )
                    .count()
                    >= 2
            );
        }
        // Clear the first fault so the next selected error is specifically the real recovery
        // barrier's xSync, after full reopen/audit/reconciliation; it must not publish Ready.
        v.reset();
        let began = Instant::now();
        let failed_recovery = command(&mut r, "recover");
        let failed_recovery_us = began.elapsed().as_micros();
        assert_eq!(failed_recovery["ok"], false, "{failed_recovery}");
        assert!(v.events().iter().any(|e| e.kind == "xsync"));
        blocked(&mut r);
        barrier.store(false, Ordering::SeqCst);
        v.reset();
        let began = Instant::now();
        let recovered = command(&mut r, "recover");
        let recovery_us = began.elapsed().as_micros();
        let present = mode == "durable_publication_gap";
        assert_eq!(
            recovered["result"]["attempted_present"], present,
            "{mode}: {recovered}"
        );
        assert_eq!(recovered["result"]["new_commit"], false);
        assert_eq!(
            command(&mut r, "propose")["ok"],
            false,
            "recovery invalidates old preparation"
        );
        assert_eq!(
            r.command(json!({"command":"pool","offset":0,"limit":16}))["result"]["count"],
            if present { 0 } else { 2 }
        );
        assert_eq!(
            command(&mut r, "status")["result"]["tip"]["revision"],
            u64::from(present)
        );
        let replay =
            r.command(json!({"command":"apply","selection":1,"envelope":original["envelope"]}));
        assert_eq!(replay["result"]["new_commit"], !present);
        assert_eq!(
            r.command(json!({"command":"export","revision":1}))["result"]["envelope"],
            original["envelope"]
        );
        emit(
            json!({"kind":"s4_owner_real_io","case":mode,"fault_action_us":fault_us,
            "failed_recovery_us":failed_recovery_us,"successful_recovery_us":recovery_us,"attempted_present":present,
            "fault_response":failed,"failed_barrier_response":failed_recovery,"blocked_queries_export_publication":true,
            "rollback_uses_test_forced_cache_flush":mode=="rollback","physical_power_loss":false}),
        );
        drop(r); // VFS registration is still alive for close/rollback callbacks.
    }
}

fn emit(value: Value) {
    // Unique development/verification artifacts preserve earlier timings and outliers too.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mode = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    std::fs::write(
        format!("target/s4-owner-{mode}-{stamp}.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
    println!("{value}");
}

#[test]
fn actual_catchup_owner_io_poison_halts_and_explicit_retry_authenticates_duplicates_once_only() {
    let d = TempDir::new_in("target").unwrap();
    let p = profile();
    let mut producer = build(
        AuthenticatedFixtureStore::create_authenticated_fixture(d.path().join("p.db"), &p.manifest)
            .unwrap(),
    );
    for tx in inputs(2) {
        assert_eq!(producer.test_command(tx)["ok"], true);
    }
    let original = prepare_proposal(&mut producer);
    approve(&mut producer, &d, &original);
    assert_eq!(
        producer.test_command(json!({"command":"commit_prepared","selection":1}))["ok"],
        true
    );
    let v = Harness::new();
    let mut store = AuthenticatedFixtureStore::create_inner(
        &d.path().join("r.db"),
        &p.manifest,
        Some(v.name()),
        |_| Ok(()),
    )
    .unwrap();
    let mut arm = v.arm_next_callback("xsync", ffi::SQLITE_IOERR_FSYNC, false);
    let mut fired = false;
    store.hook = Some(Box::new(move |phase| {
        if phase == "before_commit" && !fired {
            fired = true;
            arm();
        }
        Ok(())
    }));
    let approvals = worker::profile::Approvals::load(&d.path().join("approvals.json"), &p).unwrap();
    let w = worker::Worker::new(store, p, approvals, None).unwrap();
    let (config, port) = config(d.path());
    let mut r = TestRuntime::new(w, &config).unwrap();
    let mut source = peer(&mut r, port);
    let target = d.path().join("target.json");
    let p = profile();
    std::fs::write(&target,serde_json::to_vec(&json!({"format":"eternix-fixture-catchup-target-v1","run_id":p.run_id,
        "network_id":hex::encode(p.network),"anchor_hash":hex::encode(p.anchor_tip().hash),
        "target":{"hash":original["block_hash"],"slot":1,"revision":1},"envelope_id":original["envelope_id"]})).unwrap()).unwrap();
    let envelope = hex::decode(original["envelope"].as_str().unwrap()).unwrap();
    for attempt in 0..2 {
        assert_eq!(
            r.command(json!({"command":"catchup_start","node_id":2,"target_path":target}))["ok"],
            true
        );
        for _ in 0..4 {
            r.tick();
        }
        let body = read_frame(&mut source);
        let id = u64::from_be_bytes(body[..8].try_into().unwrap());
        reset_all();
        let response = codec::encode_extension(
            &codec::Context::new(2, &profile()),
            codec::Kind::Successor,
            &codec::successor(id, 1, &envelope),
        )
        .unwrap();
        source.write_all(&response).unwrap();
        if attempt == 0 {
            until(&mut r, |r| {
                command(r, "peer_status")["result"]["owner_available"] == false
            });
            assert_eq!(
                command(&mut r, "catchup_status")["result"]["phase"],
                "halted"
            );
            blocked(&mut r);
            v.reset();
            assert_eq!(
                command(&mut r, "recover")["result"]["attempted_present"],
                false
            );
            assert_eq!(
                command(&mut r, "catchup_status")["result"]["phase"],
                "halted"
            );
            assert_eq!(command(&mut r, "status")["result"]["tip"]["revision"], 0);
            source = peer(&mut r, port);
        } else {
            until(&mut r, |r| {
                command(r, "catchup_status")["result"]["phase"] == "complete"
            });
            assert_eq!(evidence(), (2, 1, 1, (2, 2)));
            source.write_all(&response).unwrap();
            until(&mut r, |r| {
                command(r, "peer_status")["result"]["duplicate_deliveries"] == 1
            });
            assert_eq!(
                evidence(),
                (2, 2, 1, (2, 2)),
                "duplicate cold producer auth, zero extra native staging/execution"
            );
            assert_eq!(auth::phase_evidence::signing_count(), 0);
            assert_eq!(
                command(&mut r, "peer_status")["result"]["relay_attempts"],
                0
            );
            assert_eq!(
                command(&mut r, "peer_status")["result"]["fresh_publications"],
                0
            );
        }
    }
    drop(r);
}

// SIGKILL children run the same production setup, operator I/O threads, lock and owner loop. The
// marker is external test coordination only; the peer/operator protocol cannot request a pause.
#[test]
#[ignore = "isolated S4 actual-runtime kill child, invoked only by the parent below"]
fn peer_kill_child() {
    let Some(root) = std::env::var_os("ETX_S4_KILL_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let point = std::env::var("ETX_S4_KILL_POINT").unwrap();
    let args = vec![
        "follower".into(),
        "open".into(),
        root.join("profile.json").into_os_string(),
        root.join("approvals.json").into_os_string(),
        root.join("node").into_os_string(),
        root.join("peers.json").into_os_string(),
    ];
    worker::transport::test_run(args, move |path, p, _| {
        let mut store =
            AuthenticatedFixtureStore::reopen(path, &p.manifest).map_err(|e| e.to_string())?;
        store.hook = Some(Box::new(move |phase| {
            if phase == point {
                std::fs::write(root.join("paused"), phase).unwrap();
                loop {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Ok(())
        }));
        Ok(store)
    })
    .unwrap();
}
struct ChildOwner {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl ChildOwner {
    fn start(root: &Path, point: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "authenticated_fixture::tests::worker_s4::peer_kill_child",
                "--ignored",
                "--nocapture",
            ])
            .env("ETX_S4_KILL_ROOT", root)
            .env("ETX_S4_KILL_POINT", point)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.contains("S4_OWNER_READY") {
                break;
            }
        }
        let mut result = Self {
            child,
            input,
            output,
        };
        assert_eq!(result.read()["ok"], true);
        result
    }
    fn send(&mut self, value: Value) {
        let b = serde_json::to_vec(&value).unwrap();
        self.input
            .write_all(&(b.len() as u32).to_be_bytes())
            .unwrap();
        self.input.write_all(&b).unwrap();
        self.input.flush().unwrap();
    }
    fn read(&mut self) -> Value {
        let mut n = [0; 4];
        self.output.read_exact(&mut n).unwrap();
        let n = u32::from_be_bytes(n) as usize;
        assert!(n <= 65536);
        let mut b = vec![0; n];
        self.output.read_exact(&mut b).unwrap();
        serde_json::from_slice(&b).unwrap()
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn actual_owner_sigkill_before_sql_and_at_durable_publication_gap_reopens_exact_prefix() {
    for point in ["before_begin", "before_commit", "after_commit"] {
        let d = TempDir::new_in("target").unwrap();
        let p = profile();
        let dir = d.path().join("node");
        std::fs::create_dir(&dir).unwrap();
        let mut w = build(
            AuthenticatedFixtureStore::create_authenticated_fixture(
                dir.join("archive.sqlite"),
                &p.manifest,
            )
            .unwrap(),
        );
        for tx in inputs(2) {
            assert_eq!(w.test_command(tx)["ok"], true);
        }
        let original = prepare_proposal(&mut w);
        approve(&mut w, &d, &original);
        drop(w);
        // The store fixture was constructed directly above; provide the same pre-existing lock
        // artifact that explicit process init creates. The child still exercises no-create open.
        std::fs::File::create_new(dir.join("worker.lock")).unwrap();
        std::fs::write(
            d.path().join("profile.json"),
            include_bytes!("../../../tests/fixtures/testnet_fixture_profile.json"),
        )
        .unwrap();
        config(d.path());
        let mut child = ChildOwner::start(d.path(), point);
        child.send(json!({"command":"apply","selection":1,"envelope":original["envelope"]}));
        let start = Instant::now();
        while !d.path().join("paused").exists() {
            assert!(start.elapsed() < Duration::from_secs(30));
            std::thread::sleep(Duration::from_millis(1));
        }
        child.child.kill().unwrap();
        assert!(!child.child.wait().unwrap().success());
        drop(child);
        let store =
            AuthenticatedFixtureStore::reopen(dir.join("archive.sqlite"), &p.manifest).unwrap();
        let present = point == "after_commit";
        assert_eq!(store.snapshot().unwrap().tip.revision, u64::from(present));
        if present {
            assert_eq!(
                hex::encode(store.export_signed_envelope(1).unwrap()),
                original["envelope"]
            );
        }
        let approvals =
            worker::profile::Approvals::load(&d.path().join("approvals.json"), &p).unwrap();
        let mut owner = worker::Worker::new(store, p, approvals, None).unwrap();
        assert_eq!(
            owner.test_command(json!({"command":"recover"}))["result"]["attempted_present"],
            Value::Null,
            "a fresh owner cannot fabricate the lost in-memory attempt's receipt"
        );
        let response = owner
            .test_command(json!({"command":"apply","selection":1,"envelope":original["envelope"]}));
        assert_eq!(response["result"]["new_commit"], !present);
        println!(
            "{}",
            json!({"kind":"s4_owner_sigkill","point":point,"retained_revision":u64::from(present),
            "lost_response_replay_new_commit":!present,"physical_power_loss":false})
        );
    }
}
