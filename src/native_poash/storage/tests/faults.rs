//! New schema4 actual-owner I/O traces, process termination and declared-model power-loss evidence.
//! The unchanged VFS machinery is shared; none of the schema3 results/counts is reused as C1 data.
use super::*;
use crate::durable_fixture::tests::vfs::Harness;
use rusqlite::ffi;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn vstore(p: &Path, g: &Genesis, v: &Harness) -> PoashTrialStore {
    PoashTrialStore::create_inner(p, g, Some(v.name()), |_| Ok(())).unwrap()
}
fn staged(s: &mut PoashTrialStore, g: &Genesis, populated: bool) -> StagedBlock {
    let body = if populated {
        vec![tx(g, 1, 3, 1, 0)]
    } else {
        vec![]
    };
    let wire = packet(preparation(s, &body).block(), g);
    s.stage_received(&wire).unwrap()
}
fn trace(phase: &str) -> Vec<crate::durable_fixture::tests::vfs::Event> {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let v = Harness::new();
    let mut s = vstore(&d.path().join("s.db"), &g, &v);
    if phase != "initialization" {
        append(&mut s, &g, &[]);
        v.reset();
        if phase == "recovery" {
            s.recover().unwrap();
        } else {
            let st = staged(&mut s, &g, phase == "populated");
            assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
        }
    }
    v.events()
}

#[test]
fn c1_new_nth_real_vfs_io_faults_cover_initialization_empty_populated_and_recovery() {
    for phase in ["initialization", "empty", "populated", "recovery"] {
        let trace = trace(phase);
        let mut cases = 0;
        let mut aborted = 0;
        let mut required = 0;
        for (kind, code) in [
            ("xwrite", ffi::SQLITE_FULL),
            ("xwrite", ffi::SQLITE_IOERR_WRITE),
            ("xsync", ffi::SQLITE_IOERR_FSYNC),
            ("xdelete", ffi::SQLITE_IOERR_DELETE),
        ] {
            for nth in 1..=trace.iter().filter(|e| e.kind == kind).count() {
                cases += 1;
                let d = TempDir::new().unwrap();
                let p = d.path().join("s.db");
                let g = genesis();
                let v = Harness::new();
                if phase == "initialization" {
                    v.fault(kind, nth, code, false);
                    let e = PoashTrialStore::create_inner(&p, &g, Some(v.name()), |_| Ok(()))
                        .err()
                        .expect("new trace fault reached");
                    if matches!(e, Error::Storage(StoreError::RecoveryRequired(_))) {
                        required += 1;
                    } else {
                        aborted += 1;
                    }
                    v.reset();
                    // Initialization faults can expose no usable dataset, or the entire durable
                    // initialized genesis (e.g. an uncertain directory deletion). Never repair it.
                    match PoashTrialStore::load(&p, &g, Some(v.name())) {
                        Ok(s) => assert_eq!(s.snapshot().unwrap(), &Snapshot::initial(&g)),
                        Err(Error::Storage(StoreError::Uninitialized)) => {}
                        Err(e) => panic!("init {kind}:{nth}: {e}"),
                    }
                } else {
                    let mut s = vstore(&p, &g, &v);
                    append(&mut s, &g, &[]);
                    let old = s.snapshot().unwrap().clone();
                    let st = staged(&mut s, &g, phase == "populated");
                    v.reset();
                    v.fault(kind, nth, code, false);
                    if phase == "recovery" {
                        assert!(s.recover().is_err(), "{phase} {kind}:{nth}");
                        required += 1;
                        assert!(!s.is_ready());
                    } else {
                        match s.commit(st) {
                            AppendOutcome::Aborted(_) => {
                                aborted += 1;
                                assert_eq!(s.snapshot().unwrap(), &old);
                            }
                            AppendOutcome::RecoveryRequired(_) => {
                                required += 1;
                                assert!(s.snapshot().is_err());
                                assert!(s.export_envelope(1).is_err());
                            }
                            _ => panic!("unreached {phase} {kind}:{nth}"),
                        }
                    }
                    v.reset();
                    s.recover().unwrap();
                    assert_eq!(s.snapshot().unwrap(), &old);
                }
            }
        }
        println!(
            "C1_IO phase={phase} new_trace_events={} cases={cases} confirmed_aborts={aborted} recovery_required={required} whole_state_original_evidence=true",
            trace.len()
        );
    }
}

#[test]
fn c1_real_failed_rollback_reopen_and_dirty_barrier_remain_poisoned_until_successful_sync() {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let v = Harness::new();
    let mut s = vstore(&d.path().join("s.db"), &g, &v);
    append(&mut s, &g, &[]);
    let old = s.snapshot().unwrap().clone();
    let st = staged(&mut s, &g, true);
    // Test-only pager flush forces real rollback playback even for tiny C1 data, without changing
    // default cache/spill or durability. A semantic hook requests rollback; the FAILURE is the VFS
    // database write during actual SQLite playback, not that hook.
    // SAFETY: this handle belongs to s's live connection, has no active SQLite call at the hook,
    // and the hook is removed before closing/recovering that connection. No callback unwinds in C.
    let handle = unsafe { s.conn().handle() };
    let mut arm = v.arm_next_callback("xwrite", ffi::SQLITE_IOERR_WRITE, true);
    s.hook = Some(Box::new(move |p| {
        if p == "before_commit" {
            assert_eq!(
                unsafe { ffi::sqlite3_db_cacheflush(handle) },
                ffi::SQLITE_OK
            );
            arm();
            return Err(invalid("request rollback"));
        }
        Ok(())
    }));
    let outcome = s.commit(st);
    assert!(
        matches!(outcome, AppendOutcome::RecoveryRequired(_)),
        "{outcome:?}; {:?}",
        v.events()
    );
    assert!(s.snapshot().is_err());
    s.hook = None;
    v.reset();
    v.fault("xopen", 1, ffi::SQLITE_CANTOPEN, true);
    assert!(s.recover().is_err());
    assert!(!s.is_ready());
    v.reset();
    let mut arm = v.arm_next_callback("xsync", ffi::SQLITE_IOERR_FSYNC, true);
    s.hook = Some(Box::new(move |p| {
        if p == "recovery_barrier" {
            arm();
        }
        Ok(())
    }));
    assert!(s.recover().is_err());
    assert!(s.snapshot().is_err());
    assert!(s.export_envelope(1).is_err());
    v.reset();
    s.hook = None;
    assert_eq!(s.recover().unwrap().attempted_present, Some(false));
    assert_eq!(s.snapshot().unwrap(), &old);
    println!(
        "C1_IO persistent_failed_rollback=true failed_reopen=true failed_real_dirty_barrier=true exact_absent_reconciled=true"
    );
}

#[test]
fn c1_new_power_loss_model_cuts_and_acknowledged_original_evidence() {
    for phase in ["initialization", "empty", "populated", "recovery"] {
        let events = trace(phase).len();
        for sector in [false, true] {
            let (mut old_count, mut new_count, mut unavailable) = (0, 0, 0);
            for cut in 1..=events {
                let d = TempDir::new().unwrap();
                let p = d.path().join("s.db");
                let g = genesis();
                let v = Harness::new();
                let expected = if phase == "initialization" {
                    v.power(cut, sector);
                    drop(PoashTrialStore::create_inner(
                        &p,
                        &g,
                        Some(v.name()),
                        |_| Ok(()),
                    ));
                    None
                } else {
                    let mut s = vstore(&p, &g, &v);
                    append(&mut s, &g, &[]);
                    let old = s.snapshot().unwrap().clone();
                    let st = staged(&mut s, &g, phase == "populated");
                    let mut next = old.clone();
                    next.insert(st.record.clone()).unwrap();
                    v.reset();
                    v.power(cut, sector);
                    if phase == "recovery" {
                        let _ = s.recover();
                    } else {
                        let _ = s.commit(st);
                    }
                    drop(s);
                    Some((old, next))
                };
                v.restore_power_image(d.path());
                v.reset();
                match PoashTrialStore::load(&p, &g, Some(v.name())) {
                    Err(Error::Storage(StoreError::Missing | StoreError::Uninitialized))
                        if expected.is_none() =>
                    {
                        unavailable += 1;
                    }
                    Ok(s) => {
                        if let Some((old, next)) = expected {
                            if s.snapshot().unwrap() == &old {
                                old_count += 1;
                            } else {
                                assert_eq!(s.snapshot().unwrap(), &next);
                                new_count += 1;
                            }
                        } else {
                            assert_eq!(s.snapshot().unwrap(), &Snapshot::initial(&g));
                            new_count += 1;
                        }
                    }
                    Err(e) => panic!("{phase} sector={sector} cut={cut}: {e}"),
                }
            }
            println!(
                "C1_POWER_MODEL phase={phase} sector_prefix={sector} new_cuts={events} exact_old={old_count} exact_new={new_count} uninitialized={unavailable}"
            );
        }
    }
    for acknowledged in [false, true] {
        let d = TempDir::new().unwrap();
        let p = d.path().join("s.db");
        let g = genesis();
        let v = Harness::new();
        let mut s = vstore(&p, &g, &v);
        append(&mut s, &g, &[]);
        let st = staged(&mut s, &g, true);
        let mut expected = s.snapshot().unwrap().clone();
        expected.insert(st.record.clone()).unwrap();
        if !acknowledged {
            s.hook = Some(hook("after_commit"));
        }
        let outcome = s.commit(st);
        assert!(if acknowledged {
            matches!(outcome, AppendOutcome::Committed { .. })
        } else {
            matches!(outcome, AppendOutcome::RecoveryRequired(_))
        });
        v.capture_acknowledged();
        drop(s);
        v.restore_power_image(d.path());
        v.reset();
        assert_eq!(
            PoashTrialStore::load(&p, &g, Some(v.name()))
                .unwrap()
                .snapshot()
                .unwrap(),
            &expected
        );
        println!(
            "C1_POWER_MODEL post_commit_acknowledged={acknowledged} complete_original_evidence=true"
        );
    }
}

fn handshake(point: &str, target: &str) {
    if point == target {
        println!("C1_READY:{point}");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        panic!("parent must terminate child");
    }
}
#[test]
#[ignore = "controlled C1 child invoked only by process-termination parent"]
fn crash_child() {
    let Some(path) = std::env::var_os("ETX_C1_CRASH_PATH") else {
        return;
    };
    let target = std::env::var("ETX_C1_CRASH_POINT").unwrap();
    let phase = std::env::var("ETX_C1_CRASH_PHASE").unwrap();
    let g = genesis();
    let v = Harness::new();
    let location = target
        .strip_prefix("init_")
        .or_else(|| target.strip_prefix("recovery_"))
        .unwrap_or(&target)
        .to_owned();
    let io = match location.as_str() {
        "journal_xwrite" => Some("journal_xwrite"),
        "database_xwrite" => Some("database_xwrite"),
        "journal_xsync" => Some("journal_xsync"),
        "database_xsync" => Some("database_xsync"),
        "xdelete" => Some("xdelete"),
        _ => None,
    };
    if phase == "initialization" {
        let t = target.clone();
        v.on_event(io, move |p| handshake(&format!("init_{p}"), &t));
        let _ = PoashTrialStore::create_inner(Path::new(&path), &g, Some(v.name()), |p| {
            handshake(p, &target);
            Ok(())
        });
    } else {
        let mut s = PoashTrialStore::load(Path::new(&path), &g, Some(v.name())).unwrap();
        let st = staged(&mut s, &g, phase == "populated");
        let t = target.clone();
        let recovering = phase == "recovery";
        v.on_event(io, move |p| {
            handshake(
                &if recovering {
                    format!("recovery_{p}")
                } else {
                    p.into()
                },
                &t,
            )
        });
        s.hook = Some(Box::new(move |p| {
            handshake(p, &target);
            Ok(())
        }));
        if recovering {
            let _ = s.recover();
        } else {
            let _ = s.commit(st);
        }
    }
    panic!("requested C1 kill boundary not reached");
}
#[test]
fn c1_process_termination_around_new_reward_state_evidence_and_io_boundaries() {
    let mut cases = 0;
    for phase in ["initialization", "empty", "populated", "recovery"] {
        let points: &[&str] = match phase {
            "initialization" => &[
                "init_schema",
                "init_year",
                "init_state",
                "init_marker",
                "init_before_commit",
                "init_after_commit",
                "init_journal_xsync",
                "init_database_xsync",
            ],
            "recovery" => &[
                "recovery_reopen",
                "recovery_validate",
                "recovery_barrier",
                "recovery_install",
                "recovery_journal_xsync",
                "recovery_database_xsync",
            ],
            _ => &[
                "accounts",
                "accounting",
                "block_evidence",
                "body",
                "indexes",
                "reward",
                "state",
                "revision",
                "tip",
                "before_commit",
                "after_commit",
                "after_install",
                "journal_xsync",
                "database_xsync",
            ],
        };
        for target in points {
            cases += 1;
            let d = TempDir::new().unwrap();
            let p = d.path().join("s.db");
            let g = genesis();
            let expected = if phase == "initialization" {
                None
            } else {
                let mut s = create(&p, &g);
                append(&mut s, &g, &[]);
                let old = s.snapshot().unwrap().clone();
                let st = staged(&mut s, &g, phase == "populated");
                let mut next = old.clone();
                next.insert(st.record.clone()).unwrap();
                drop(s);
                Some((old, next))
            };
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "native_poash::storage::tests::faults::crash_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("ETX_C1_CRASH_PATH", &p)
                .env("ETX_C1_CRASH_POINT", target)
                .env("ETX_C1_CRASH_PHASE", phase)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let stdout = BufReader::new(child.stdout.take().unwrap());
            let mut reached = false;
            for line in stdout.lines() {
                let line = line.unwrap();
                if line == format!("C1_READY:{target}") {
                    reached = true;
                    break;
                }
            }
            if !reached {
                let status = child.wait().unwrap();
                panic!("C1 boundary {phase}/{target} not reached: {status}");
            }
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            match PoashTrialStore::reopen(&p, &g) {
                Ok(s) => {
                    if let Some((old, next)) = expected {
                        if phase == "recovery" {
                            assert_eq!(s.snapshot().unwrap(), &old);
                        } else {
                            assert!(
                                s.snapshot().unwrap() == &old || s.snapshot().unwrap() == &next
                            );
                        }
                    } else {
                        assert_eq!(s.snapshot().unwrap(), &Snapshot::initial(&g));
                    }
                }
                Err(Error::Storage(StoreError::Uninitialized)) if phase == "initialization" => {}
                Err(e) => panic!("after SIGKILL {phase}/{target}: {e}"),
            }
        }
    }
    println!(
        "C1_SIGKILL newly_observed_boundaries={cases} complete_state_and_original_evidence=true not_power_loss=true"
    );
}
