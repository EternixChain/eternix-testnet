//! New signing-journal I/O/model traces and real process kills. A semantic hook is never counted as
//! disk failure; VFS cases execute actual SQLite callbacks on the separately owned signing store.
use super::*;
use crate::durable_fixture::tests::vfs::Harness;
use rusqlite::ffi;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
fn vcreate(root: &Path, g: &Genesis, o: &PoashTrialStore, v: &Harness) -> SigningAuthority {
    SigningAuthority::open_inner(root, g, "trial-A", key(2), o, true, Some(v.name())).unwrap()
}
fn trace(recovery: bool) -> Vec<crate::durable_fixture::tests::vfs::Event> {
    let d = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = genesis();
    let o = owner(&d.path().join("o.db"), &g);
    let v = Harness::new();
    let mut a = vcreate(root.path(), &g, &o, &v);
    let prep = prepare(&o, &body(&g));
    if recovery {
        a.sign_prepared(&o, &prep).unwrap();
        v.reset();
        a.recover(&o).unwrap();
    } else {
        v.reset();
        a.sign_prepared(&o, &prep).unwrap();
    }
    v.events()
}
#[test]
fn real_signing_reservation_original_and_barrier_io_failures_never_expose_unsynchronized_signatures()
 {
    for recovery in [false, true] {
        let trace = trace(recovery);
        let mut cases = 0;
        for (kind, code) in [
            ("xwrite", ffi::SQLITE_FULL),
            ("xwrite", ffi::SQLITE_IOERR_WRITE),
            ("xsync", ffi::SQLITE_IOERR_FSYNC),
            ("xdelete", ffi::SQLITE_IOERR_DELETE),
        ] {
            for nth in 1..=trace.iter().filter(|e| e.kind == kind).count() {
                cases += 1;
                let d = TempDir::new().unwrap();
                let root = TempDir::new().unwrap();
                let g = genesis();
                let o = owner(&d.path().join("o.db"), &g);
                let v = Harness::new();
                let mut a = vcreate(root.path(), &g, &o, &v);
                let prep = prepare(&o, &body(&g));
                let expected = if recovery {
                    Some(a.sign_prepared(&o, &prep).unwrap().bytes().to_vec())
                } else {
                    None
                };
                phase_evidence::reset();
                v.reset();
                v.fault(kind, nth, code, false);
                if recovery {
                    assert!(a.recover(&o).is_err(), "{kind}:{nth}");
                } else {
                    assert!(a.sign_prepared(&o, &prep).is_err(), "{kind}:{nth}");
                }
                assert!(!a.is_ready());
                assert!(a.original(&o, 1).is_err());
                v.reset();
                let report = a.recover(&o).unwrap();
                assert_eq!(o.snapshot().unwrap().tip().slot, 0);
                assert!(report.committed.is_empty());
                if let Some(expected) = expected {
                    assert_eq!(a.original(&o, 1).unwrap().bytes(), expected);
                } else {
                    if !a.intents.contains_key(&1) {
                        assert_eq!(phase_evidence::count(), 0);
                    } else if !report.incomplete.is_empty() {
                        assert!(a.sign_prepared(&o, &prep).is_err());
                    } else {
                        let original = a.original(&o, 1).unwrap();
                        assert_eq!(original.bytes(), a.intents[&1].original.as_ref().unwrap());
                    }
                }
                assert!(phase_evidence::count() <= 1);
            }
        }
        println!(
            "C1_SIGN_IO recovery={recovery} newly_observed_events={} nth_real_error_cases={cases} no_unsigned_or_uncertain_signature_response=true",
            trace.len()
        );
    }
}
#[test]
fn persistent_journal_failure_and_canonical_commit_fsync_uncertainty_require_two_explicit_recoveries()
 {
    let d = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = genesis();
    let v = Harness::new();
    let mut o = PoashTrialStore::signing_test_create(&d.path().join("o.db"), &g, v.name()).unwrap();
    let mut a = vcreate(root.path(), &g, &o, &v);
    let prep = prepare(&o, &body(&g));
    let bytes = a.sign_prepared(&o, &prep).unwrap().bytes().to_vec();
    let stage = o.seal_prepared(prep, &bytes).unwrap();
    v.reset();
    v.fault("xsync", 1, ffi::SQLITE_IOERR_FSYNC, true);
    assert!(matches!(
        o.commit(stage),
        AppendOutcome::RecoveryRequired(_)
    ));
    assert!(a.original(&o, 1).is_err());
    v.reset();
    o.recover().unwrap();
    assert!(a.original(&o, 1).is_err());
    v.fault("xsync", 1, ffi::SQLITE_IOERR_FSYNC, true);
    assert!(a.recover(&o).is_err());
    assert!(!a.is_ready());
    assert!(a.original(&o, 1).is_err());
    v.reset();
    let report = a.recover(&o).unwrap();
    assert_eq!(report.pending, vec![1]);
    assert_eq!(a.original(&o, 1).unwrap().bytes(), bytes);
    phase_evidence::reset();
    let stage = o.stage_received(&bytes).unwrap();
    a.check_application(&o, 1, &stage).unwrap();
    assert!(matches!(o.commit(stage), AppendOutcome::Committed { .. }));
    assert_eq!(phase_evidence::count(), 0);
    println!(
        "C1_SIGN_IO canonical_fsync_uncertain=true signer_barrier_failed=true separate_explicit_recovery=true exact_original_applied_once=true"
    );
}
#[test]
fn signing_power_model_never_forgets_a_signature_whose_original_was_exposed() {
    for sector in [false, true] {
        let events = trace(false).len();
        let (mut absent, mut incomplete, mut complete) = (0, 0, 0);
        for cut in 1..=events {
            let d = TempDir::new().unwrap();
            let root = TempDir::new().unwrap();
            let g = genesis();
            let o = owner(&d.path().join("o.db"), &g);
            let v = Harness::new();
            let mut a = vcreate(root.path(), &g, &o, &v);
            let prep = prepare(&o, &body(&g));
            v.reset();
            v.power(cut, sector);
            assert!(a.sign_prepared(&o, &prep).is_err());
            drop(a);
            v.restore_power_image(root.path());
            v.reset();
            let mut a = SigningAuthority::open_inner(
                root.path(),
                &g,
                "trial-A",
                key(2),
                &o,
                false,
                Some(v.name()),
            )
            .unwrap();
            let report = a.status(&o).unwrap();
            if a.intents.is_empty() {
                absent += 1;
            } else if !report.incomplete.is_empty() {
                incomplete += 1;
                phase_evidence::reset();
                assert!(a.sign_prepared(&o, &prep).is_err());
                assert_eq!(phase_evidence::count(), 0);
            } else {
                complete += 1;
                assert!(a.original(&o, 1).is_ok());
            }
        }
        println!(
            "C1_SIGN_POWER_MODEL sector_prefix={sector} newly_observed_cuts={events} no_reservation={absent} fenced_incomplete={incomplete} complete_original={complete}"
        );
    }
    let d = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = genesis();
    let o = owner(&d.path().join("o.db"), &g);
    let v = Harness::new();
    let mut a = vcreate(root.path(), &g, &o, &v);
    let prep = prepare(&o, &[]);
    let original = a.sign_prepared(&o, &prep).unwrap().bytes().to_vec();
    v.capture_acknowledged();
    drop(a);
    v.restore_power_image(root.path());
    v.reset();
    let mut a = SigningAuthority::open_inner(
        root.path(),
        &g,
        "trial-A",
        key(2),
        &o,
        false,
        Some(v.name()),
    )
    .unwrap();
    phase_evidence::reset();
    assert_eq!(a.original(&o, 1).unwrap().bytes(), original);
    assert_eq!(phase_evidence::count(), 0);
    println!(
        "C1_SIGN_POWER_MODEL exposed_private_proposal_original_retained=true not_physical_power_certification=true"
    );
}
fn handshake(point: &str, target: &str) {
    if point == target {
        println!("C1_SIGN_READY:{point}");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        panic!("parent must terminate child");
    }
}
#[test]
#[ignore = "controlled protected-signing child, invoked only by parent"]
fn crash_child() {
    let Some(path) = std::env::var_os("ETX_C1_SIGN_DATABASE") else {
        return;
    };
    let root = std::env::var_os("ETX_C1_SIGN_ROOT").unwrap();
    let target = std::env::var("ETX_C1_SIGN_POINT").unwrap();
    let g = genesis();
    let mut o = owner(Path::new(&path), &g);
    if target == "competing" {
        assert!(matches!(
            SigningAuthority::reopen(Path::new(&root), &g, "trial-A", key(2), &o),
            Err(Error::Owned)
        ));
        println!("C1_SIGN_OWNED");
        return;
    }
    let mut a = authority(Path::new(&root), &g, &o);
    let prep = prepare(&o, &[]);
    let t = target.clone();
    a.hook = Some(Box::new(move |p| {
        handshake(p, &t);
        Ok(())
    }));
    let original = a.sign_prepared(&o, &prep).unwrap();
    let stage = o.seal_prepared(prep, original.bytes()).unwrap();
    a.check_application(&o, 1, &stage).unwrap();
    let t = target.clone();
    o.signing_test_hook(Some(Box::new(move |p| {
        handshake(&format!("canonical_{p}"), &t);
        Ok(())
    })));
    assert!(matches!(o.commit(stage), AppendOutcome::Committed { .. }));
    handshake("publication_gap", &target);
    handshake("lost_committed_reply", &target);
    panic!("requested signing boundary not reached");
}
#[test]
fn process_kills_cover_reservation_signature_original_sync_canonical_uncertainty_and_publication_gaps()
 {
    let points = [
        "before_reservation",
        "reservation_written",
        "before_reservation_commit",
        "after_reservation_commit",
        "after_reservation_sync",
        "before_signature",
        "after_signature",
        "original_written",
        "before_original_commit",
        "after_original_commit",
        "after_original_sync",
        "before_response",
        "canonical_before_begin",
        "canonical_after_commit",
        "canonical_after_install",
        "publication_gap",
        "lost_committed_reply",
    ];
    for target in points {
        let d = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        let path = d.path().join("o.db");
        let g = genesis();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_poash::signing::tests::faults::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("ETX_C1_SIGN_DATABASE", &path)
            .env("ETX_C1_SIGN_ROOT", root.path())
            .env("ETX_C1_SIGN_POINT", target)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut reached = false;
        for line in stdout.lines() {
            if line.unwrap() == format!("C1_SIGN_READY:{target}") {
                reached = true;
                break;
            }
        }
        if !reached {
            panic!(
                "signing boundary {target} missed: {:?}",
                child.wait().unwrap()
            );
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let mut o = PoashTrialStore::reopen(&path, &g).unwrap();
        let mut a = SigningAuthority::reopen(root.path(), &g, "trial-A", key(2), &o).unwrap();
        let report = a.status(&o).unwrap();
        phase_evidence::reset();
        if !report.incomplete.is_empty() {
            let prep = prepare(&o, &body(&g));
            assert!(a.sign_prepared(&o, &prep).is_err());
        } else if !report.pending.is_empty() {
            let bytes = a.original(&o, 1).unwrap().bytes().to_vec();
            let stage = o.stage_received(&bytes).unwrap();
            a.check_application(&o, 1, &stage).unwrap();
            assert!(matches!(o.commit(stage), AppendOutcome::Committed { .. }));
            assert!(matches!(
                o.stage_received(&bytes),
                Err(app::Error::AlreadyCommitted { .. })
            ));
        } else if !report.committed.is_empty() {
            let bytes = a.original(&o, 1).unwrap().bytes().to_vec();
            assert_eq!(o.export_envelope(1).unwrap(), bytes);
            assert_eq!(
                o.snapshot().unwrap().state.input().base_issuance,
                10_000_000
            );
        }
        assert_eq!(phase_evidence::count(), 0);
    }
    println!(
        "C1_SIGN_SIGKILL boundaries={} no_different_H_escaped=true originals_replayed_without_resigning_or_double_effects=true",
        points.len()
    );
}
#[test]
fn competing_process_cannot_own_same_network_key_from_another_archive() {
    let d = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = genesis();
    let o = owner(&d.path().join("a.db"), &g);
    let _a = authority(root.path(), &g, &o);
    let result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_poash::signing::tests::faults::crash_child",
            "--ignored",
            "--nocapture",
        ])
        .env("ETX_C1_SIGN_DATABASE", d.path().join("b.db"))
        .env("ETX_C1_SIGN_ROOT", root.path())
        .env("ETX_C1_SIGN_POINT", "competing")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("C1_SIGN_OWNED"));
}
