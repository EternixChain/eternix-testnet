//! Test-only wrapper around SQLite's real platform VFS, with operation faults and stable images.
//!
//! Safety: SQLite allocates Wrapper with szOsFile and calls it serially per connection. The real
//! file is separately SQLite-allocated/aligned. Boxes/Arc state outlive registration and every
//! connection; Harness must be dropped last. No callback unwinds for a deliberately injected error.
//! The model is sector-prefix destaging plus loss of other unsynced writes, not physical certification.

use super::*;
use rusqlite::ffi as f;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Passive test-only delegate observations, not a lost-write model or injected error.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub(crate) struct IoMetric {
    pub calls: u64,
    pub bytes: u64,
    pub elapsed_ns: u128,
    pub maximum_ns: u128,
    pub errors: u64,
    /// Non-OK delegate statuses can include expected SQLite journal-sentinel short reads.
    pub non_ok_statuses: BTreeMap<c_int, u64>,
}
type IoProfile = BTreeMap<String, BTreeMap<String, IoMetric>>;

#[derive(Clone, Debug)]
pub struct Event {
    pub kind: &'static str,
    pub path: PathBuf,
    pub ordinal: usize,
}
type Image = BTreeMap<PathBuf, Vec<u8>>;
type Callback = Box<dyn FnMut(&str) + Send>;
#[derive(Default)]
struct State {
    events: Vec<Event>,
    fault: Option<(&'static str, usize, c_int, bool)>,
    power: Option<(usize, bool)>,
    stable: Image,
    cut: Option<Image>,
    callback: Option<(&'static str, Callback)>,
    // Reopen faults are counted separately so existing write/sync/delete power traces are unchanged.
    open_calls: usize,
    // Passive profiling never snapshots files or simulates capabilities; it forwards the platform
    // sector/device methods and only observes real operations. Existing fault/model mode is intact.
    passive: bool,
    profile_phase: &'static str,
    io: IoProfile,
}
struct VfsData {
    parent: *mut f::sqlite3_vfs,
    state: Arc<Mutex<State>>,
}
struct FileData {
    real: *mut f::sqlite3_file,
    methods: f::sqlite3_io_methods,
    state: Arc<Mutex<State>>,
    path: PathBuf,
}
#[repr(C)]
struct Wrapper {
    base: f::sqlite3_file,
    data: *mut FileData,
}

pub struct Harness {
    name: CString,
    vfs: Box<f::sqlite3_vfs>,
    data: Box<VfsData>,
}
impl Harness {
    pub fn new() -> Self {
        // Never replace the default VFS: parallel tests each use their own uniquely named wrapper.
        unsafe {
            assert_eq!(f::sqlite3_initialize(), f::SQLITE_OK);
            let parent = f::sqlite3_vfs_find(std::ptr::null());
            assert!(!parent.is_null());
            let name =
                CString::new(format!("etx-fixture-test-{}", next_generation().unwrap())).unwrap();
            let mut data = Box::new(VfsData {
                parent,
                state: Arc::new(Mutex::new(State::default())),
            });
            let mut vfs = Box::new(*parent);
            vfs.zName = name.as_ptr();
            vfs.pNext = std::ptr::null_mut();
            vfs.pAppData = (&mut *data as *mut VfsData).cast();
            vfs.szOsFile = std::mem::size_of::<Wrapper>() as c_int;
            vfs.xOpen = Some(xopen);
            vfs.xDelete = Some(xdelete);
            // Other VFS methods are platform callbacks that do not access pAppData on bundled unix.
            assert_eq!(f::sqlite3_vfs_register(&mut *vfs, 0), f::SQLITE_OK);
            Self { name, vfs, data }
        }
    }
    pub fn name(&self) -> &str {
        self.name.to_str().unwrap()
    }
    pub fn reset(&self) {
        let mut s = self.data.state.lock().unwrap();
        s.events.clear();
        s.fault = None;
        s.power = None;
        s.cut = None;
        s.open_calls = 0;
        s.io.clear();
    }
    /// Selects passive delegate observation, with no failure injection/stable-image reads.
    pub(crate) fn passive_profile(&self) {
        let mut s = self.data.state.lock().unwrap();
        s.passive = true;
        s.fault = None;
        s.power = None;
        s.callback = None;
        s.events.clear();
        s.stable.clear();
        s.cut = None;
        s.io.clear();
    }
    /// Labels subsequent observations; owned control closure can be installed in a store test hook.
    pub(crate) fn phase_controller(&self) -> impl FnMut(&'static str) + 'static {
        let state = self.data.state.clone();
        move |phase| {
            state.lock().unwrap().profile_phase = phase;
        }
    }
    pub(crate) fn io_profile(&self) -> IoProfile {
        self.data.state.lock().unwrap().io.clone()
    }
    pub fn fault(&self, kind: &'static str, nth: usize, code: c_int, persistent: bool) {
        self.data.state.lock().unwrap().fault = Some((kind, nth, code, persistent));
    }
    pub fn power(&self, event: usize, torn_sector: bool) {
        self.data.state.lock().unwrap().power = Some((event, torn_sector));
    }
    pub fn events(&self) -> Vec<Event> {
        self.data.state.lock().unwrap().events.clone()
    }
    /// Shared fault control for another fixture owner's SQL hook; errors still occur in real VFS.
    pub(crate) fn arm_next_callback(
        &self,
        kind: &'static str,
        code: c_int,
        persistent: bool,
    ) -> impl FnMut() + 'static {
        let state = self.data.state.clone();
        move || {
            let mut s = state.lock().unwrap();
            let next = s.events.iter().filter(|e| e.kind == kind).count() + 1;
            s.fault = Some((kind, next, code, persistent));
        }
    }
    /// Captures only synchronized model images after acknowledgement, without freshening from disk.
    pub(crate) fn capture_acknowledged(&self) {
        let mut s = self.data.state.lock().unwrap();
        s.cut = Some(s.stable.clone());
    }
    pub fn on_event(
        &self,
        kind: Option<&'static str>,
        callback: impl FnMut(&str) + Send + 'static,
    ) {
        self.data.state.lock().unwrap().callback =
            kind.map(|kind| (kind, Box::new(callback) as Callback));
    }
    pub fn restore_power_image(&self, directory: &Path) {
        // Called only after every connection has closed. Discard volatile real files and install
        // precisely the captured stable model, independent of SQLite's post-cut error cleanup.
        let image = self
            .data
            .state
            .lock()
            .unwrap()
            .cut
            .clone()
            .expect("cut reached");
        for entry in std::fs::read_dir(directory).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        for (path, bytes) in image {
            std::fs::write(path, bytes).unwrap();
        }
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        unsafe {
            assert_eq!(f::sqlite3_vfs_unregister(&mut *self.vfs), f::SQLITE_OK);
        }
    }
}

fn event(
    state: &Arc<Mutex<State>>,
    kind: &'static str,
    path: &Path,
    write: Option<(i64, &[u8])>,
) -> c_int {
    let mut s = state.lock().unwrap();
    if s.passive {
        return f::SQLITE_OK;
    }
    let ordinal = s.events.iter().filter(|e| e.kind == kind).count() + 1;
    s.events.push(Event {
        kind,
        path: path.to_owned(),
        ordinal,
    });
    let location = match (kind, path.to_string_lossy().ends_with("-journal")) {
        ("xwrite", true) => "journal_xwrite",
        ("xwrite", false) => "database_xwrite",
        ("xsync", true) => "journal_xsync",
        ("xsync", false) => "database_xsync",
        _ => kind,
    };
    if let Some((wanted, callback)) = &mut s.callback
        && (*wanted == kind || *wanted == location)
    {
        callback(location);
    }
    if s.power.is_some_and(|(n, _)| n == s.events.len()) && s.cut.is_none() {
        let mut image = s.stable.clone();
        // Optional early persistence of the first 512-byte sector of one unsynced database write.
        // All other unsynced writes are discarded; synchronized journal pages remain intact.
        if s.power.unwrap().1
            && !path.to_string_lossy().ends_with("-journal")
            && let Some((offset, data)) = write
        {
            let bytes = image.entry(path.to_owned()).or_default();
            let end = offset as usize + data.len().min(512);
            bytes.resize(bytes.len().max(end), 0);
            bytes[offset as usize..end].copy_from_slice(&data[..end - offset as usize]);
        }
        s.cut = Some(image);
        return match kind {
            "xsync" => f::SQLITE_IOERR_FSYNC,
            "xdelete" => f::SQLITE_IOERR_DELETE,
            _ => f::SQLITE_IOERR_WRITE,
        };
    }
    if let Some((wanted, nth, code, persistent)) = s.fault
        && wanted == kind
        && (ordinal == nth || (persistent && ordinal >= nth))
    {
        return code;
    }
    f::SQLITE_OK
}

fn profile_start(state: &Arc<Mutex<State>>) -> Option<Instant> {
    state.lock().unwrap().passive.then(Instant::now)
}
fn observe_io(
    state: &Arc<Mutex<State>>,
    start: Option<Instant>,
    kind: &'static str,
    bytes: u64,
    code: c_int,
) {
    if let Some(start) = start {
        let ns = start.elapsed().as_nanos();
        let mut s = state.lock().unwrap();
        let phase = s.profile_phase.to_owned();
        let metric =
            s.io.entry(phase)
                .or_default()
                .entry(kind.into())
                .or_default();
        metric.calls += 1;
        metric.bytes += bytes;
        metric.elapsed_ns += ns;
        metric.maximum_ns = metric.maximum_ns.max(ns);
        metric.errors += u64::from(code != f::SQLITE_OK);
        if code != f::SQLITE_OK {
            *metric.non_ok_statuses.entry(code).or_default() += 1;
        }
    }
}

// All raw-pointer operations below are confined to SQLite's callback contract. Delegated calls
// use the real file and its original methods, never accidentally the wrapper's synthetic layout.
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn data<'a>(file: *mut f::sqlite3_file) -> &'a mut FileData {
    &mut *(*(file.cast::<Wrapper>())).data
}
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn xopen(
    vfs: *mut f::sqlite3_vfs,
    name: *const c_char,
    file: *mut f::sqlite3_file,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    let v = &*((*vfs).pAppData.cast::<VfsData>());
    {
        let mut s = v.state.lock().unwrap();
        s.open_calls += 1;
        if let Some((kind, nth, code, persistent)) = s.fault
            && kind == "xopen"
            && (s.open_calls == nth || (persistent && s.open_calls >= nth))
        {
            return code;
        }
    }
    let real = f::sqlite3_malloc((*v.parent).szOsFile).cast::<f::sqlite3_file>();
    if real.is_null() {
        return f::SQLITE_NOMEM;
    }
    std::ptr::write_bytes(real.cast::<u8>(), 0, (*v.parent).szOsFile as usize);
    let code = (*v.parent).xOpen.unwrap()(v.parent, name, real, flags, out);
    if code != f::SQLITE_OK {
        f::sqlite3_free(real.cast());
        return code;
    }
    let path = if name.is_null() {
        PathBuf::from("anonymous-test-temp")
    } else {
        PathBuf::from(CStr::from_ptr(name).to_str().unwrap())
    };
    if flags & f::SQLITE_OPEN_MAIN_DB != 0 && !v.state.lock().unwrap().passive {
        // Model reservation as a surviving empty directory entry. Initialization may still be
        // unusable; this never upgrades an unsynchronized application schema to initialized.
        v.state
            .lock()
            .unwrap()
            .stable
            .entry(path.clone())
            .or_insert_with(|| std::fs::read(&path).unwrap_or_default());
    }
    let d = Box::new(FileData {
        real,
        methods: *(*real).pMethods,
        state: v.state.clone(),
        path,
    });
    std::ptr::write(
        file.cast::<Wrapper>(),
        Wrapper {
            base: f::sqlite3_file { pMethods: &METHODS },
            data: Box::into_raw(d),
        },
    );
    f::SQLITE_OK
}
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn xdelete(
    vfs: *mut f::sqlite3_vfs,
    name: *const c_char,
    sync_dir: c_int,
) -> c_int {
    let v = &*((*vfs).pAppData.cast::<VfsData>());
    let path = PathBuf::from(CStr::from_ptr(name).to_str().unwrap());
    let error = event(&v.state, "xdelete", &path, None);
    if error != f::SQLITE_OK {
        return error;
    }
    let start = profile_start(&v.state);
    let code = (*v.parent).xDelete.unwrap()(v.parent, name, sync_dir);
    observe_io(&v.state, start, "delete_including_directory_sync", 0, code);
    if code == f::SQLITE_OK && sync_dir != 0 && !v.state.lock().unwrap().passive {
        v.state.lock().unwrap().stable.remove(&path);
    }
    code
}
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn xclose(file: *mut f::sqlite3_file) -> c_int {
    let d = Box::from_raw((*(file.cast::<Wrapper>())).data);
    let code = d.methods.xClose.unwrap()(d.real);
    f::sqlite3_free(d.real.cast());
    code
}
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn xwrite(
    file: *mut f::sqlite3_file,
    bytes: *const c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    let d = data(file);
    let input = std::slice::from_raw_parts(bytes.cast::<u8>(), amount as usize);
    let code = event(&d.state, "xwrite", &d.path, Some((offset, input)));
    if code != f::SQLITE_OK {
        return code;
    }
    let start = profile_start(&d.state);
    let code = d.methods.xWrite.unwrap()(d.real, bytes, amount, offset);
    observe_io(
        &d.state,
        start,
        if d.path.to_string_lossy().ends_with("-journal") {
            "journal_write"
        } else {
            "database_write"
        },
        amount as u64,
        code,
    );
    code
}
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn xsync(file: *mut f::sqlite3_file, flags: c_int) -> c_int {
    let d = data(file);
    let error = event(&d.state, "xsync", &d.path, None);
    if error != f::SQLITE_OK {
        return error;
    }
    let start = profile_start(&d.state);
    let code = d.methods.xSync.unwrap()(d.real, flags);
    observe_io(
        &d.state,
        start,
        if d.path.to_string_lossy().ends_with("-journal") {
            "journal_sync"
        } else {
            "database_sync"
        },
        0,
        code,
    );
    if code == f::SQLITE_OK && !d.state.lock().unwrap().passive {
        d.state
            .lock()
            .unwrap()
            .stable
            .insert(d.path.clone(), std::fs::read(&d.path).unwrap());
    }
    code
}
macro_rules! delegate {
    ($name:ident, $method:ident, ($($arg:ident : $ty:ty),*)) => {
        #[allow(unsafe_op_in_unsafe_fn)]
        unsafe extern "C" fn $name(file: *mut f::sqlite3_file, $($arg: $ty),*) -> c_int {
            let d = data(file); d.methods.$method.unwrap()(d.real, $($arg),*)
        }
    };
}
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn xread(
    file: *mut f::sqlite3_file,
    bytes: *mut c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    let d = data(file);
    let start = profile_start(&d.state);
    let code = d.methods.xRead.unwrap()(d.real, bytes, amount, offset);
    observe_io(
        &d.state,
        start,
        if d.path.to_string_lossy().ends_with("-journal") {
            "journal_read"
        } else {
            "database_read"
        },
        amount as u64,
        code,
    );
    code
}
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn xtruncate(file: *mut f::sqlite3_file, size: i64) -> c_int {
    let d = data(file);
    let code = event(&d.state, "xtruncate", &d.path, None);
    if code != f::SQLITE_OK {
        return code;
    }
    let start = profile_start(&d.state);
    let code = d.methods.xTruncate.unwrap()(d.real, size);
    observe_io(&d.state, start, "truncate", 0, code);
    code
}
delegate!(xsize, xFileSize, (size: *mut i64));
delegate!(xlock, xLock, (lock: c_int));
delegate!(xunlock, xUnlock, (lock: c_int));
delegate!(xreserved, xCheckReservedLock, (reserved: *mut c_int));
delegate!(xcontrol, xFileControl, (op: c_int, arg: *mut c_void));
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn xsector(file: *mut f::sqlite3_file) -> c_int {
    let d = data(file);
    if d.state.lock().unwrap().passive {
        d.methods.xSectorSize.unwrap()(d.real)
    } else {
        512
    }
}
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn xdevice(file: *mut f::sqlite3_file) -> c_int {
    let d = data(file);
    if d.state.lock().unwrap().passive {
        d.methods.xDeviceCharacteristics.unwrap()(d.real)
    } else {
        0
    }
}
static METHODS: f::sqlite3_io_methods = f::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(xclose),
    xRead: Some(xread),
    xWrite: Some(xwrite),
    xTruncate: Some(xtruncate),
    xSync: Some(xsync),
    xFileSize: Some(xsize),
    xLock: Some(xlock),
    xUnlock: Some(xunlock),
    xCheckReservedLock: Some(xreserved),
    xFileControl: Some(xcontrol),
    xSectorSize: Some(xsector),
    xDeviceCharacteristics: Some(xdevice),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

#[test]
fn io_failures_in_real_sqlite_initialization_and_commits() {
    for initializing in [true, false] {
        let trace = {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("store.db");
            let vfs = Harness::new();
            let mut store = FixtureStore::create_inner(
                &path,
                context(),
                initial(100),
                "fixture",
                Some(vfs.name()),
                |_| Ok(()),
            )
            .unwrap();
            if !initializing {
                vfs.reset();
                commit(&mut store, &body());
            }
            vfs.events()
        };
        for (kind, code) in [
            ("xwrite", f::SQLITE_FULL),
            ("xwrite", f::SQLITE_IOERR_WRITE),
            ("xsync", f::SQLITE_IOERR_FSYNC),
            ("xdelete", f::SQLITE_IOERR_DELETE),
        ] {
            for nth in 1..=trace.iter().filter(|e| e.kind == kind).count() {
                let dir = TempDir::new().unwrap();
                let path = dir.path().join("store.db");
                let vfs = Harness::new();
                let mut store = if initializing {
                    None
                } else {
                    Some(
                        FixtureStore::create_inner(
                            &path,
                            context(),
                            initial(100),
                            "fixture",
                            Some(vfs.name()),
                            |_| Ok(()),
                        )
                        .unwrap(),
                    )
                };
                vfs.reset();
                vfs.fault(kind, nth, code, false);
                if initializing {
                    let result = FixtureStore::create_inner(
                        &path,
                        context(),
                        initial(100),
                        "fixture",
                        Some(vfs.name()),
                        |_| Ok(()),
                    );
                    assert!(result.is_err(), "{kind}:{code}");
                    println!(
                        "io initialization {kind} nth={nth} code={code} outcome={:?}",
                        result.err()
                    );
                    vfs.reset();
                    match FixtureStore::load(&path, context(), Some(vfs.name()), true) {
                        Ok(loaded) => assert_eq!(loaded.snapshot().unwrap().state, initial(100)),
                        Err(StoreError::Uninitialized) => (),
                        Err(e) => panic!("unexpected recovered initialization: {e}"),
                    }
                } else {
                    let store = store.as_mut().unwrap();
                    let old = store.snapshot().unwrap().clone();
                    let overlay = store.stage(u64::MAX, &body()).unwrap();
                    let outcome = store.commit(overlay);
                    println!("io commitment {kind} nth={nth} code={code} outcome={outcome:?}");
                    match outcome {
                        CommitOutcome::Aborted(_) => assert_eq!(store.snapshot().unwrap(), &old),
                        CommitOutcome::RecoveryRequired(_) => {
                            assert!(store.snapshot().is_err());
                            assert!(store.stage(0, &[]).is_err());
                        }
                        _ => panic!("fault did not fail"),
                    }
                    assert!(!vfs.events().is_empty());
                    vfs.reset();
                    store.recover().unwrap();
                    assert!(store.snapshot().unwrap().revision <= 1);
                }
            }
        }
    }
}

#[test]
fn initialization_rollback_io_failure_is_not_a_confirmed_abort() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("store.db");
    let vfs = Harness::new();
    let state = vfs.data.state.clone();
    let result =
        FixtureStore::create_inner(
            &path,
            context(),
            initial(50_000),
            "fixture",
            Some(vfs.name()),
            move |p| {
                if p == "initial_accounting" {
                    let mut s = state.lock().unwrap();
                    assert!(
                        s.events.iter().any(|e| e.kind == "xwrite"
                            && !e.path.to_string_lossy().ends_with("-journal"))
                    );
                    let next = s.events.iter().filter(|e| e.kind == "xtruncate").count() + 1;
                    s.fault = Some(("xtruncate", next, f::SQLITE_IOERR_TRUNCATE, true));
                    Err(invalid("force initialization rollback"))
                } else {
                    Ok(())
                }
            },
        );
    assert!(matches!(result, Err(StoreError::RecoveryRequired(_))));
    println!("initialization rollback I/O outcome={:?}", result.err());
    vfs.reset();
    assert!(matches!(
        FixtureStore::load(&path, context(), Some(vfs.name()), true),
        Err(StoreError::Uninitialized)
    ));
}

#[test]
fn sync_failure_during_recovery_stays_poisoned() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("store.db");
    let vfs = Harness::new();
    let mut store = FixtureStore::create_inner(
        &path,
        context(),
        initial(1),
        "fixture",
        Some(vfs.name()),
        |_| Ok(()),
    )
    .unwrap();
    let old = store.stage(0, &[]).unwrap();
    store.hook = Some(hook_at("after_commit"));
    let overlay = store.stage(u64::MAX, &body()).unwrap();
    assert!(matches!(
        store.commit(overlay),
        CommitOutcome::RecoveryRequired(_)
    ));
    store.hook = None;
    vfs.reset();
    vfs.fault("xsync", 1, f::SQLITE_IOERR_FSYNC, false);
    assert!(store.recover().is_err());
    assert!(!store.is_ready());
    assert!(store.snapshot().is_err());
    vfs.reset();
    assert_eq!(store.recover().unwrap().revision, 1);
    assert!(matches!(
        store.commit(old),
        CommitOutcome::Aborted(StoreError::Stale)
    ));
}

#[test]
fn real_rollback_write_failure_requires_recovery() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("store.db");
    let vfs = Harness::new();
    let seed = TransferState::new(
        BTreeMap::from([(
            sender(),
            TransferAccount {
                balance_quarks: 100_000_000,
                nonce: 0,
            },
        )]),
        0,
        0,
    );
    let mut store = FixtureStore::create_inner(
        &path,
        context(),
        seed.clone(),
        "rollback fixture",
        Some(vfs.name()),
        |_| Ok(()),
    )
    .unwrap();
    store.conn().execute_batch("PRAGMA cache_size=1").unwrap();
    let mut bytes = Vec::new();
    for nonce in 0..2_048u64 {
        let mut recipient = [0x55; 20];
        recipient[12..].copy_from_slice(&nonce.to_be_bytes());
        bytes.push(
            sign(
                UnsignedTransaction {
                    encoding_version: 2,
                    native_rules_version: 1,
                    chain_id: context().chain_id(),
                    network_id: context().network_id(),
                    kind: 0,
                    sender: sender(),
                    nonce,
                    recipient,
                    token_id: 0,
                    value: 1,
                    gas_limit: 1000,
                    valid_after_slot: 0,
                },
                &key(),
                &context(),
            )
            .unwrap()
            .canonical_bytes()
            .unwrap()
            .to_vec(),
        );
    }
    let overlay = store.stage(0, &bytes).unwrap();
    vfs.reset();
    let state = vfs.data.state.clone();
    store.hook = Some(Box::new(move |point| {
        if point == "accounting" {
            // Force enough dirty pages to spill, then fail actual database rollback restoration,
            // rather than returning an application-level "rollback failed" flag.
            let mut s = state.lock().unwrap();
            assert!(
                s.events
                    .iter()
                    .any(|e| e.kind == "xwrite" && !e.path.to_string_lossy().ends_with("-journal")),
                "real database page spill required"
            );
            let next = s.events.iter().filter(|e| e.kind == "xwrite").count() + 1;
            s.fault = Some(("xwrite", next, f::SQLITE_IOERR_WRITE, true));
            Err(invalid("force SQL-phase rollback"))
        } else {
            Ok(())
        }
    }));
    let outcome = store.commit(overlay);
    println!("real rollback outcome={outcome:?}");
    assert!(matches!(outcome, CommitOutcome::RecoveryRequired(_)));
    assert!(!store.is_ready());
    assert!(store.stage(0, &[]).is_err());
    store.hook = None;
    vfs.reset();
    store.recover().unwrap();
    assert_eq!(store.snapshot().unwrap().state, seed);
    assert_eq!(store.snapshot().unwrap().revision, 0);
}

#[test]
fn acknowledged_commit_survives_declared_volatile_loss() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("store.db");
    let vfs = Harness::new();
    let mut store = FixtureStore::create_inner(
        &path,
        context(),
        initial(10),
        "fixture",
        Some(vfs.name()),
        |_| Ok(()),
    )
    .unwrap();
    commit(&mut store, &body());
    let acknowledged = store.snapshot().unwrap().clone();
    // Crash after the success return: keep only xSync images and EXTRA's synced journal deletion.
    {
        let mut s = vfs.data.state.lock().unwrap();
        s.cut = Some(s.stable.clone());
    }
    drop(store);
    vfs.restore_power_image(dir.path());
    vfs.reset();
    let loaded = FixtureStore::load(&path, context(), Some(vfs.name()), true).unwrap();
    assert_eq!(loaded.snapshot().unwrap(), &acknowledged);
}

#[test]
fn declared_power_model_valid_prefix_and_acknowledged_retention() {
    // Enumerate every actual write/sync/delete event in both initialization and a subsequent commit.
    // Repeat each cut with volatile-loss only and optional sector-prefix early persistence.
    for initializing in [true, false] {
        let event_count = {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("store.db");
            let vfs = Harness::new();
            let mut store = FixtureStore::create_inner(
                &path,
                context(),
                initial(10),
                "fixture",
                Some(vfs.name()),
                |_| Ok(()),
            )
            .unwrap();
            if !initializing {
                commit(&mut store, &[]);
                vfs.reset();
                commit(&mut store, &body());
            }
            vfs.events().len()
        };
        for torn in [false, true] {
            for cut in 1..=event_count {
                let dir = TempDir::new().unwrap();
                let path = dir.path().join("store.db");
                let vfs = Harness::new();
                if initializing {
                    vfs.power(cut, torn);
                    let result = FixtureStore::create_inner(
                        &path,
                        context(),
                        initial(10),
                        "fixture",
                        Some(vfs.name()),
                        |_| Ok(()),
                    );
                    drop(result);
                } else {
                    let mut store = FixtureStore::create_inner(
                        &path,
                        context(),
                        initial(10),
                        "fixture",
                        Some(vfs.name()),
                        |_| Ok(()),
                    )
                    .unwrap();
                    commit(&mut store, &[]); // acknowledged prefix must survive every later cut
                    vfs.reset();
                    vfs.power(cut, torn);
                    let overlay = store.stage(u64::MAX, &body()).unwrap();
                    let _ = store.commit(overlay);
                    drop(store);
                }
                let events = vfs.events();
                let event = &events[cut - 1];
                assert!(event.ordinal > 0 && event.path.is_absolute());
                vfs.restore_power_image(dir.path());
                vfs.reset();
                let result = FixtureStore::load(&path, context(), Some(vfs.name()), true);
                if initializing {
                    match result {
                        Ok(loaded) => {
                            assert_eq!(loaded.snapshot().unwrap().state, initial(10));
                            assert_eq!(loaded.snapshot().unwrap().revision, 0);
                        }
                        Err(StoreError::Missing | StoreError::Uninitialized) => (),
                        Err(e) => panic!("init power {cut} {event:?} torn={torn}: {e}"),
                    }
                } else {
                    let loaded =
                        result.unwrap_or_else(|e| panic!("power {cut} {event:?} torn={torn}: {e}"));
                    assert!((1..=2).contains(&loaded.snapshot().unwrap().revision));
                    assert_eq!(loaded.snapshot().unwrap().bodies[0].transactions.len(), 0);
                }
            }
            println!(
                "power_model initialization={initializing} sector_prefix={torn} cuts={event_count}"
            );
        }
    }
}
