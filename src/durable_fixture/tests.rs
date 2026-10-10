//! Each evidence class uses real files; application hooks and VFS faults are reported separately.

use super::*;
use crate::native_transaction::{
    ENCODING_VERSION, NATIVE_RULES_VERSION, TRANSFER_KIND, UnsignedTransaction,
    address_from_public_key, network_id_from_genesis_bytes, sign,
};
use k256::ecdsa::SigningKey;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use tempfile::TempDir;

pub(crate) mod vfs;

fn context() -> AuthenticationContext {
    AuthenticationContext::new(
        u64::MAX,
        network_id_from_genesis_bytes(b"ETERNIX_OFFLINE_DURABLE_FIXTURE_V1"),
        NATIVE_RULES_VERSION,
    )
    .unwrap()
}
fn key() -> SigningKey {
    // Published scalar one, solely to generate explicit offline signed fixtures.
    let mut bytes = [0; 32];
    bytes[31] = 1;
    SigningKey::from_slice(&bytes).unwrap()
}
fn sender() -> [u8; 20] {
    address_from_public_key(key().verifying_key())
}
fn initial(count: usize) -> TransferState {
    let mut accounts = BTreeMap::new();
    for n in 0..count {
        let mut address = [0x42; 20];
        address[12..].copy_from_slice(&(n as u64).to_be_bytes());
        accounts.insert(
            address,
            TransferAccount {
                balance_quarks: u128::MAX,
                nonce: u64::MAX,
            },
        );
    }
    accounts.insert(
        sender(),
        TransferAccount {
            balance_quarks: u128::MAX,
            nonce: u64::MAX - 1,
        },
    );
    TransferState::new(accounts, (i64::MAX as u64) + 1, (i64::MAX as u128) + 1)
}
fn body() -> Vec<Vec<u8>> {
    let c = context();
    vec![
        sign(
            UnsignedTransaction {
                encoding_version: ENCODING_VERSION,
                native_rules_version: NATIVE_RULES_VERSION,
                chain_id: c.chain_id(),
                network_id: c.network_id(),
                kind: TRANSFER_KIND,
                sender: sender(),
                nonce: u64::MAX - 1,
                recipient: [0x33; 20],
                token_id: 0,
                value: 17,
                gas_limit: 1000,
                valid_after_slot: u64::MAX,
            },
            &key(),
            &c,
        )
        .unwrap()
        .canonical_bytes()
        .unwrap()
        .to_vec(),
    ]
}
fn create(path: &Path, count: usize) -> FixtureStore {
    FixtureStore::create_fixture(
        path,
        context(),
        initial(count),
        "explicit offline fixture v1",
    )
    .unwrap()
}
fn commit(store: &mut FixtureStore, bytes: &[Vec<u8>]) {
    let overlay = store.stage(u64::MAX, bytes).unwrap();
    assert!(matches!(
        store.commit(overlay),
        CommitOutcome::Committed { .. }
    ));
}
fn hook_at(target: &'static str) -> TestHook {
    Box::new(move |point| {
        if point == target {
            Err(invalid(format!("application failpoint {point}")))
        } else {
            Ok(())
        }
    })
}

#[test]
fn normal_reopen_producer_replay_and_unsigned_boundaries() {
    let dir = TempDir::new().unwrap();
    let paths = [dir.path().join("producer.db"), dir.path().join("replay.db")];
    let mut producer = create(&paths[0], 4);
    let mut replay = create(&paths[1], 4);
    let bytes = body();
    commit(&mut producer, &bytes);
    commit(&mut replay, &bytes);
    let expected = producer.snapshot().unwrap().clone();
    assert_eq!(&expected, replay.snapshot().unwrap());
    assert_eq!(expected.state.account(&sender()).nonce, u64::MAX);
    assert_eq!(expected.canonical_tip, None);
    assert_eq!(expected.bodies[0].transactions[0].as_slice(), bytes[0]);
    assert_eq!(expected.state.account(&[0x33; 20]).balance_quarks, 17);
    assert!(producer.stage(u64::MAX, &bytes).is_err());
    drop(producer);
    drop(replay);
    for path in &paths {
        let mut loaded = FixtureStore::reopen(path, context()).unwrap();
        assert_eq!(loaded.snapshot().unwrap(), &expected);
        assert!(loaded.stage(u64::MAX, &bytes).is_err());
        commit(&mut loaded, &[]);
        assert_eq!(loaded.snapshot().unwrap().state, expected.state);
        assert_eq!(loaded.snapshot().unwrap().revision, 2);
    }
}

#[test]
fn create_and_reopen_never_seed_or_replace_existing_paths() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("store.db");
    assert!(matches!(
        FixtureStore::reopen(&path, context()),
        Err(StoreError::Missing)
    ));
    assert!(!path.exists());
    File::create(&path).unwrap();
    assert!(matches!(
        FixtureStore::create_fixture(&path, context(), initial(0), "fixture"),
        Err(StoreError::AlreadyExists)
    ));
    assert!(matches!(
        FixtureStore::reopen(&path, context()),
        Err(StoreError::Uninitialized)
    ));
    assert!(matches!(
        FixtureStore::recover_existing(&path, context()),
        Err(StoreError::Uninitialized)
    ));
    assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
    let initialized = dir.path().join("initialized.db");
    drop(create(&initialized, 0));
    for existing in [initialized.as_path(), dir.path()] {
        assert!(matches!(
            FixtureStore::create_fixture(existing, context(), initial(0), "fixture"),
            Err(StoreError::AlreadyExists)
        ));
    }
    #[cfg(unix)]
    {
        let link = dir.path().join("existing-link.db");
        std::os::unix::fs::symlink(&initialized, &link).unwrap();
        assert!(matches!(
            FixtureStore::create_fixture(&link, context(), initial(0), "fixture"),
            Err(StoreError::AlreadyExists)
        ));
    }
}

#[test]
fn atomic_initialization_application_failpoints_and_unacknowledged_commit() {
    for point in [
        "schema",
        "context",
        "fixture_account",
        "fixture_accounts",
        "initial_accounting",
        "provenance",
        "marker",
        "init_before_commit",
        "init_after_commit",
        "init_directory_sync",
    ] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("init.db");
        let result =
            FixtureStore::create_inner(&path, context(), initial(3), "fixture", None, |p| {
                if p == point {
                    Err(invalid(point))
                } else {
                    Ok(())
                }
            });
        assert!(result.is_err(), "{point}");
        if ["init_after_commit", "init_directory_sync"].contains(&point) {
            assert!(matches!(result, Err(StoreError::RecoveryRequired(_))));
            let recovered = FixtureStore::recover_existing(&path, context()).unwrap();
            assert_eq!(recovered.snapshot().unwrap().state, initial(3));
            assert_eq!(recovered.snapshot().unwrap().revision, 0);
        } else {
            assert!(matches!(result, Err(StoreError::Aborted(_))));
            assert!(matches!(
                FixtureStore::reopen(&path, context()),
                Err(StoreError::Uninitialized)
            ));
        }
        assert!(matches!(
            FixtureStore::create_fixture(&path, context(), initial(3), "fixture"),
            Err(StoreError::AlreadyExists)
        ));
    }
}

#[test]
fn stale_revisions_generations_and_duplicate_constraints() {
    let dir = TempDir::new().unwrap();
    let mut store = create(&dir.path().join("store.db"), 0);
    let stale = store.stage(0, &[]).unwrap();
    commit(&mut store, &[]);
    assert!(matches!(
        store.commit(stale),
        CommitOutcome::Aborted(StoreError::Stale)
    ));
    let old = store.stage(0, &[]).unwrap();
    store.recover().unwrap();
    assert!(matches!(
        store.commit(old),
        CommitOutcome::Aborted(StoreError::Stale)
    ));
    let mut wrong_revision = store.stage(0, &[]).unwrap();
    wrong_revision.revision = 0;
    assert!(matches!(
        store.commit(wrong_revision),
        CommitOutcome::Aborted(StoreError::Stale)
    ));
    commit(&mut store, &body());
    let tx = &store.snapshot.bodies[1].transactions[0];
    let id = store.snapshot.bodies[1].outcome.transaction_ids[0];
    // Direct constraint probes establish both index invariants independently of nonce execution.
    let revision = 2u64.to_be_bytes();
    let position = 1u64.to_be_bytes();
    let nonce = (u64::MAX - 1).to_be_bytes();
    let error = store
        .conn()
        .execute(
            "INSERT INTO transactions VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                id.as_slice(),
                revision.as_slice(),
                position.as_slice(),
                sender().as_slice(),
                1u64.to_be_bytes().as_slice(),
                tx.as_slice()
            ],
        )
        .unwrap_err();
    assert_eq!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::ConstraintViolation)
    );
    let error = store
        .conn()
        .execute(
            "INSERT INTO transactions VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                [0xeeu8; 32].as_slice(),
                revision.as_slice(),
                position.as_slice(),
                sender().as_slice(),
                nonce.as_slice(),
                tx.as_slice()
            ],
        )
        .unwrap_err();
    assert_eq!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::ConstraintViolation)
    );
}

#[test]
fn durable_revision_detects_another_empty_commit_and_full_base_mismatch() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("store.db");
    let mut store = create(&path, 0);
    let stale = store.stage(0, &[]).unwrap();
    let mut second = FixtureStore::reopen(&path, context()).unwrap();
    commit(&mut second, &[]);
    drop(second);
    assert!(matches!(store.commit(stale), CommitOutcome::Aborted(_)));
    store.recover().unwrap();
    let mut mismatch = store.stage(0, &[]).unwrap();
    mismatch.base = TransferState::default();
    assert!(matches!(
        store.commit(mismatch),
        CommitOutcome::Aborted(StoreError::Stale)
    ));
    let stale = store.stage(0, &[]).unwrap();
    store
        .conn()
        .execute(
            "UPDATE accounts SET balance=?1 WHERE address=?2",
            params![1u128.to_be_bytes().as_slice(), sender().as_slice()],
        )
        .unwrap();
    assert!(matches!(store.commit(stale), CommitOutcome::Aborted(_)));
    assert!(store.conn().is_autocommit());
}

#[test]
fn every_sql_phase_rolls_back_all_tables() {
    for point in [
        "accounts",
        "accounting",
        "body",
        "indexes",
        "revision",
        "before_commit",
        "sql_index_constraint",
    ] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("store.db");
        let mut store = create(&path, 2);
        commit(&mut store, &[]);
        let old = store.snapshot().unwrap().clone();
        if point == "sql_index_constraint" {
            // A real SQLite constraint error after account/accounting/body writes verifies the
            // index failure boundary independently of application-level phase hooks.
            store.conn().execute_batch("CREATE TRIGGER reject_fixture_index BEFORE INSERT ON transactions BEGIN SELECT RAISE(ABORT,'fixture index constraint'); END").unwrap();
        } else {
            store.hook = Some(hook_at(point));
        }
        let staged = store.stage(u64::MAX, &body()).unwrap();
        assert!(
            matches!(store.commit(staged), CommitOutcome::Aborted(_)),
            "{point}"
        );
        assert_eq!(store.snapshot().unwrap(), &old);
        store.hook = None;
        if point == "sql_index_constraint" {
            store
                .conn()
                .execute_batch("DROP TRIGGER reject_fixture_index")
                .unwrap();
        }
        drop(store);
        assert_eq!(
            FixtureStore::reopen(path, context())
                .unwrap()
                .snapshot()
                .unwrap(),
            &old
        );
    }
}

#[test]
fn poison_blocks_publication_and_recovery_refreshes_old_and_new_outcomes() {
    for after_commit in [false, true] {
        let dir = TempDir::new().unwrap();
        let mut store = create(&dir.path().join("store.db"), 1);
        let old = store.stage(0, &[]).unwrap();
        let attempted = store.stage(u64::MAX, &body()).unwrap();
        store.hook = Some(Box::new(move |p| {
            if p == if after_commit {
                "after_commit"
            } else {
                "accounts"
            } || (!after_commit && p == "rollback")
            {
                Err(invalid(p))
            } else {
                Ok(())
            }
        }));
        assert!(matches!(
            store.commit(attempted),
            CommitOutcome::RecoveryRequired(_)
        ));
        assert!(!store.is_ready());
        assert_eq!(store.snapshot(), Err(StoreError::Blocked));
        assert!(matches!(store.stage(0, &[]), Err(StoreError::Blocked)));
        let pending = Overlay {
            generation: store.generation,
            revision: 0,
            base: initial(1),
            candidate: initial(1),
            record: AppliedBody {
                context: context(),
                slot: 0,
                transactions: vec![],
                outcome: BodyOutcome::default(),
            },
        };
        assert!(matches!(
            store.commit(pending),
            CommitOutcome::Aborted(StoreError::Blocked)
        ));
        // Every explicit recovery phase can fail and must leave publication/staging unavailable.
        for point in [
            "recovery_reopen",
            "recovery_validate",
            "recovery_barrier",
            "recovery_install",
        ] {
            store.hook = Some(hook_at(point));
            assert!(store.recover().is_err());
            assert!(!store.is_ready());
            assert!(store.snapshot().is_err());
        }
        store.hook = None;
        let report = store.recover().unwrap();
        assert_eq!(report.revision, u64::from(after_commit));
        assert_eq!(report.attempted_revision_present, Some(after_commit));
        assert_eq!(store.snapshot().unwrap().revision, report.revision);
        assert!(matches!(
            store.commit(old),
            CommitOutcome::Aborted(StoreError::Stale)
        ));
        commit(&mut store, &[]);
    }
}

#[test]
fn incompatible_corrupt_or_incomplete_stores_are_not_repaired() {
    for fault in [
        "context",
        "schema",
        "marker",
        "accounting",
        "width",
        "state",
        "index",
        "damage",
    ] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("store.db");
        let mut store = create(&path, 2);
        commit(&mut store, &body());
        drop(store);
        if fault == "damage" {
            std::fs::write(&path, b"not a SQLite file").unwrap();
        } else {
            let c = Connection::open(&path).unwrap();
            match fault {
                "context" => {
                    c.execute(
                        "UPDATE metadata SET chain=?1",
                        params![1u64.to_be_bytes().as_slice()],
                    )
                    .unwrap();
                }
                "schema" => {
                    c.execute(
                        "UPDATE metadata SET schema_version=?1",
                        params![2u32.to_be_bytes().as_slice()],
                    )
                    .unwrap();
                }
                "marker" => {
                    c.execute_batch("UPDATE metadata SET initialized=0")
                        .unwrap();
                }
                "accounting" => {
                    c.execute_batch("DELETE FROM accounting").unwrap();
                }
                "width" => {
                    c.execute_batch(
                        "PRAGMA ignore_check_constraints=ON; UPDATE accounts SET nonce=x'00'",
                    )
                    .unwrap();
                }
                "state" => {
                    c.execute_batch("DELETE FROM accounts").unwrap();
                }
                "index" => {
                    c.execute_batch("DELETE FROM transactions").unwrap();
                }
                _ => unreachable!(),
            }
        }
        let before = std::fs::read(&path).unwrap();
        assert!(FixtureStore::reopen(&path, context()).is_err(), "{fault}");
        assert!(
            FixtureStore::recover_existing(&path, context()).is_err(),
            "{fault}"
        );
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
}

// Parent/child handshake occurs at an exact application or VFS callback, never at a guessed sleep.
fn handshake(point: &str, wanted: &str) {
    if point == wanted {
        println!("FIXTURE_READY:{point}");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        panic!("parent must terminate the child");
    }
}

#[test]
#[ignore = "controlled subprocess entry, invoked by process_termination test"]
fn crash_child() {
    let Some(path) = std::env::var_os("ETX_FIXTURE_CRASH_PATH") else {
        return;
    };
    let point = std::env::var("ETX_FIXTURE_CRASH_POINT").unwrap();
    let path = PathBuf::from(path);
    let vfs = vfs::Harness::new();
    if point.starts_with("init_")
        || [
            "schema",
            "context",
            "fixture_account",
            "fixture_accounts",
            "initial_accounting",
            "provenance",
            "marker",
        ]
        .contains(&point.as_str())
    {
        let event_point = point
            .strip_prefix("init_")
            .filter(|p| p.contains("xwrite") || p.contains("xsync") || *p == "xdelete");
        let event_point = event_point.map(|p| match p {
            "journal_xwrite" => "journal_xwrite",
            "database_xwrite" => "database_xwrite",
            "journal_xsync" => "journal_xsync",
            "database_xsync" => "database_xsync",
            "xdelete" => "xdelete",
            _ => unreachable!(),
        });
        vfs.on_event(event_point, {
            let point = point.clone();
            move |p| handshake(&format!("init_{p}"), &point)
        });
        let _ = FixtureStore::create_inner(
            &path,
            context(),
            initial(50_000),
            "explicit offline fixture v1",
            Some(vfs.name()),
            |p| {
                handshake(p, &point);
                Ok(())
            },
        );
    } else {
        let mut store = FixtureStore::load(&path, context(), Some(vfs.name()), false).unwrap();
        store.conn().execute_batch("PRAGMA cache_size=8").unwrap();
        vfs.on_event(
            match point.as_str() {
                "journal_xwrite" => Some("journal_xwrite"),
                "database_xwrite" => Some("database_xwrite"),
                "journal_xsync" => Some("journal_xsync"),
                "database_xsync" => Some("database_xsync"),
                "xdelete" => Some("xdelete"),
                _ => None,
            },
            {
                let point = point.clone();
                move |p| handshake(p, &point)
            },
        );
        store.hook = Some(Box::new(move |p| {
            handshake(p, &point);
            Ok(())
        }));
        commit(&mut store, &body());
    }
    panic!("failpoint was not reached");
}

fn terminate_child(path: &Path, point: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "durable_fixture::tests::crash_child",
            "--ignored",
            "--nocapture",
        ])
        .env("ETX_FIXTURE_CRASH_PATH", path)
        .env("ETX_FIXTURE_CRASH_POINT", point)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            lines.read_line(&mut line).unwrap(),
            0,
            "child exited before {point}"
        );
        if line.starts_with("FIXTURE_READY:") {
            break;
        }
    }
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    if point.contains("database_xsync") {
        // A synchronized rollback journal survives with real modified database pages, so this
        // location exercises hot-journal recovery rather than only an untouched transaction.
        let journal = PathBuf::from(format!("{}-journal", path.display()));
        assert!(std::fs::metadata(journal).unwrap().len() >= 512);
    }
}

#[test]
fn process_termination_at_initialization_and_commit_boundaries() {
    for point in [
        "schema",
        "context",
        "fixture_account",
        "fixture_accounts",
        "initial_accounting",
        "provenance",
        "marker",
        "init_before_commit",
        "init_journal_xwrite",
        "init_database_xwrite",
        "init_journal_xsync",
        "init_database_xsync",
        "init_xdelete",
        "init_after_commit",
        "init_directory_sync",
    ] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("store.db");
        terminate_child(&path, point);
        let result = FixtureStore::recover_existing(&path, context());
        if ["init_after_commit", "init_directory_sync"].contains(&point) {
            assert_eq!(result.unwrap().snapshot().unwrap().state, initial(50_000));
        } else {
            assert!(matches!(result, Err(StoreError::Uninitialized)), "{point}");
        }
    }
    for point in [
        "before_begin",
        "accounts",
        "accounting",
        "body",
        "indexes",
        "revision",
        "before_commit",
        "journal_xwrite",
        "database_xwrite",
        "journal_xsync",
        "database_xsync",
        "xdelete",
        "after_commit",
        "after_install",
    ] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("store.db");
        drop(create(&path, 50_000));
        terminate_child(&path, point);
        let loaded = FixtureStore::recover_existing(path, context()).unwrap();
        let revision = u64::from(["after_commit", "after_install"].contains(&point));
        assert_eq!(loaded.snapshot().unwrap().revision, revision, "{point}");
        assert_eq!(loaded.snapshot().unwrap().bodies.len(), revision as usize);
        assert_eq!(loaded.snapshot().unwrap().canonical_tip, None);
    }
}
