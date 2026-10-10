//! Shared *offline* signed receiver entry, compiled by examples and composition tests only.
//! Its store is private so unsigned fixture staging is not an admission fallback. SQL still stores
//! only inner content; signed bytes are separate test artifacts, not atomically retained evidence.
use super::chain;
use chain::block_authentication::{self as auth, BlockAuthenticationContext, ProducerBinding};
use chain::canonical_fixture::{
    AppendOutcome, CanonicalFixtureStore, FixtureAdmissionGrant, FixtureManifest, LoadTimings,
    RecoveryReport, Snapshot, StagedNativeBlock,
};
use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

/// Distinct attribution/configuration/fixture failures; none turns a grant into leader proof.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Explicit auth context must be the same context used to open/create the store.
    Context,
    /// Producer envelope attribution failed before native staging.
    Authentication(auth::Error),
    /// Existing ownership/grant/native application/recovery failure.
    Fixture(chain::canonical_fixture::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signed offline fixture: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<chain::canonical_fixture::Error> for Error {
    fn from(e: chain::canonical_fixture::Error) -> Self {
        Self::Fixture(e)
    }
}

/// Non-forgeable, consumed once by this receiver; immutable proof checks preceded native staging.
#[derive(Debug)]
pub struct SignedFixtureStage {
    staged: StagedNativeBlock,
    authentication: Duration,
}
impl SignedFixtureStage {
    /// Whole cold attribution call, including decode/preflight/hash/recovery/key matching.
    pub fn authentication_time(&self) -> Duration {
        self.authentication
    }
}

/// Offline harness owner; original fixture APIs elsewhere remain explicitly unsigned fixture APIs.
pub struct SignedFixtureReceiver {
    store: CanonicalFixtureStore,
    context: BlockAuthenticationContext,
    binding: ProducerBinding,
}
impl SignedFixtureReceiver {
    /// Exclusive fixture creation with independent trusted manifest/context and one static binding.
    pub fn create(
        path: &Path,
        manifest: &FixtureManifest,
        context: BlockAuthenticationContext,
        binding: ProducerBinding,
    ) -> Result<Self, Error> {
        if context.native_context() != manifest.context() {
            return Err(Error::Context);
        }
        let store = CanonicalFixtureStore::create_anchored_fixture(path, manifest)?;
        Ok(Self {
            store,
            context,
            binding,
        })
    }
    /// Ready-gated mandatory signed admission. Caller supplies grant independently of packet claims.
    pub fn stage(
        &self,
        bytes: &[u8],
        grant: FixtureAdmissionGrant,
    ) -> Result<SignedFixtureStage, Error> {
        self.store.snapshot()?; // blocked wins over even malformed envelope errors
        let begin = Instant::now();
        let proof = auth::authenticate_block(bytes, &self.context, &self.binding, None)
            .map_err(Error::Authentication)?;
        let authentication = begin.elapsed();
        let staged = self
            .store
            .stage_received(&proof.envelope().block().wire_bytes(), grant)?;
        Ok(SignedFixtureStage {
            staged,
            authentication,
        })
    }
    /// Existing atomic commit/install; neither producer verification nor native staging repeats here.
    pub fn commit(&mut self, stage: SignedFixtureStage) -> AppendOutcome {
        self.store.commit(stage.staged)
    }
    /// Same sealed route with opt-in disjoint SQL clocks, never another authentication pass.
    pub fn commit_profiled(&mut self, stage: SignedFixtureStage) -> AppendOutcome {
        self.store.commit_profiled(stage.staged)
    }
    /// Strict ordinary fixture-store reopen/full audit; historical signatures are not inferred.
    pub fn reopen(
        path: &Path,
        manifest: &FixtureManifest,
        context: BlockAuthenticationContext,
        binding: ProducerBinding,
    ) -> Result<Self, Error> {
        if context.native_context() != manifest.context() {
            return Err(Error::Context);
        }
        let store = CanonicalFixtureStore::reopen(path, manifest)?;
        Ok(Self {
            store,
            context,
            binding,
        })
    }
    /// Read-only reconciled projection; contains no producer signature evidence.
    pub fn snapshot(&self) -> Result<&Snapshot, Error> {
        Ok(self.store.snapshot()?)
    }
    /// Queried fixture resource/durability settings, not producer authorization metadata.
    pub fn settings(&self) -> Result<chain::durable_fixture::StorageSettings, Error> {
        Ok(self.store.settings()?)
    }
    /// Explicit fixture-store recovery only; SQL cannot authenticate producer history.
    pub fn recover(&mut self) -> Result<RecoveryReport, Error> {
        Ok(self.store.recover()?)
    }
    /// Full fixture audit/barrier timings, distinct from test-envelope re-authentication.
    pub fn load_timings(&self) -> Result<LoadTimings, Error> {
        Ok(self.store.load_timings()?)
    }
    /// Consumes the wrapper for an explicitly labeled ordinary fixture-store close/reopen check.
    pub fn into_store(self) -> CanonicalFixtureStore {
        self.store
    }
    /// Fault instrumentation only; never compiled into the ordinary example admission entry.
    #[cfg(test)]
    pub(crate) fn store_mut_for_test(&mut self) -> &mut CanonicalFixtureStore {
        &mut self.store
    }
}

/// Public scalar 2 is a deterministic toy producer key; it is distinct from the sender's scalar 1.
pub fn toy_producer_key() -> k256::ecdsa::SigningKey {
    let mut bytes = [0; 32];
    bytes[31] = 2;
    k256::ecdsa::SigningKey::from_slice(&bytes).expect("published toy scalar")
}

/// Explicit static fixture key, not inferred from the authenticated packet or validator economics.
pub fn toy_binding(producer: &str) -> ProducerBinding {
    ProducerBinding::new(
        producer,
        toy_producer_key()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    )
    .expect("explicit toy producer")
}
