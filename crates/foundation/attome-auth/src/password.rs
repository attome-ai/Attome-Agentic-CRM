use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier},
};
use attome_types::AppError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The single Argon2 instance every hash and verification in this crate goes
/// through.
///
/// Production is `Argon2::default()` — the argon2 0.6 defaults, which are
/// still the OWASP-aligned Argon2id m=19456 KiB, t=2, p=1 this module has
/// always used (the crate moved 0.5 → 0.6.0 without changing them).
///
/// **This function's cost only ever governs *hashing*.** Verification derives
/// its parameters from the stored PHC string, not from this instance:
/// `PasswordVerifier::verify_password` rebuilds an `Argon2` from the hash's own
/// `Params::try_from(hash)` before recomputing (password-hash 0.6.1 over
/// argon2 0.6.0). So a real
/// production hash still verifies at its own full cost even when the
/// test-profile instance below is what performs the call — reducing the cost
/// here cannot weaken verification of anything already stored.
#[cfg(not(test))]
fn hasher() -> Argon2<'static> {
    use argon2::{Algorithm, Params, Version};
    // BAU-15a: `auth.kdf.argon2_m_cost`/`t_cost` (validated at boot, floors
    // m = 19456, t = 2). An invalid pair cannot get past `AppConfig::validate`;
    // falling back to the defaults keeps hashing at the OWASP floor regardless.
    let kdf = settings();
    Params::new(kdf.m_cost, kdf.t_cost, Params::DEFAULT_P_COST, None)
        .map(|params| Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
        .unwrap_or_default()
}

/// Test-profile cost parameters — argon2's own documented minimums (m=8 KiB,
/// t=1, p=1) instead of the ~19 MiB / 2-pass production defaults.
///
/// M-15 (TODO-017): `attome-auth`'s unit tests alone were 109 s of wall clock,
/// essentially all of it KDF — roughly 2,000 Argon2 operations at the ~40-60 ms
/// each the workspace's `[profile.dev.package.argon2] opt-level = 3` already
/// buys. The tests that pay it (MFA recovery-code generation hashes ten codes
/// per call, api-key legacy-hash fallbacks, registration/reset flows) assert on
/// *behavior* — that a hash round-trips, that a wrong secret fails, that a
/// legacy PHC row is detected and rehashed — none of which depends on the work
/// factor. Paying the production factor to prove them made the suite too slow
/// to run before pushing, which is a real security cost of its own.
///
/// This is `cfg(test)`, so it applies **only when compiling this crate's own
/// test harness**. A release build, a debug binary, and every other crate's
/// tests (which link the normally-compiled `attome-auth`) all keep the
/// production factor — there is no feature, env var, or config key that can
/// turn it on, so it cannot leak into a shipped artifact.
#[cfg(test)]
fn hasher() -> Argon2<'static> {
    use argon2::{Algorithm, Params, Version};
    let params = Params::new(
        Params::MIN_M_COST,
        Params::MIN_T_COST,
        Params::MIN_P_COST,
        None,
    )
    .expect("argon2's own minimum parameters are valid by construction");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Synchronous KDF hash. Crate-private (security contract I3): callers outside
/// this crate go through [`hash_password_async`], which bounds concurrency.
pub(crate) fn hash_password(password: &str) -> Result<String, AppError> {
    hasher()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(AppError::internal)
}

/// Synchronous KDF verify. Crate-private (security contract I3): callers
/// outside this crate go through [`verify_password_async`].
pub(crate) fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    Ok(hasher().verify_password(password.as_bytes(), hash).is_ok())
}

/// Minimum password length, in characters (security contract I2).
pub const PASSWORD_MIN_CHARS: usize = 12;

/// Maximum password length, in bytes. Bounds the input the KDF hashes, which
/// is why it counts bytes rather than characters.
pub const PASSWORD_MAX_BYTES: usize = 128;

/// The platform password policy (security contract I2): at least
/// [`PASSWORD_MIN_CHARS`] characters, at most [`PASSWORD_MAX_BYTES`] bytes, no
/// NUL character. There are deliberately no composition rules
/// (uppercase/digit/symbol): they push people toward predictable patterns
/// without adding real strength.
///
/// [`NewPassword::validate`] runs it, and [`hash_password_async`] takes only a
/// [`NewPassword`], so no password-writing path can skip it (BAU-16). The error
/// message is returned to the client as a 422.
pub fn validate_policy(password: &str) -> Result<(), AppError> {
    // Byte length first: O(1), so an oversized input is rejected before the
    // O(n) checks below walk it.
    if password.len() > PASSWORD_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "password must be at most {PASSWORD_MAX_BYTES} bytes"
        )));
    }
    if password.contains('\0') {
        return Err(AppError::Validation(
            "password must not contain a NUL character".to_string(),
        ));
    }
    let min_chars = settings().password_min_chars;
    if password.chars().count() < min_chars {
        return Err(AppError::Validation(format!(
            "password must be at least {min_chars} characters"
        )));
    }
    Ok(())
}

/// A password that may be hashed and stored (BAU-16, finding BAU-F9): the
/// only input [`hash_password_async`] accepts, so no password-writing path
/// can skip the policy by forgetting to call [`validate_policy`].
///
/// Built by [`NewPassword::validate`] for anything a person typed, or by
/// [`NewPassword::platform_generated`] for a secret the platform generated
/// itself (a bootstrap or dev-seed password, a legacy token secret).
pub struct NewPassword(String);

impl NewPassword {
    /// Security contract I2: runs [`validate_policy`]; its error is the 422 a
    /// client sees.
    pub fn validate(password: &str) -> Result<Self, AppError> {
        validate_policy(password)?;
        Ok(Self(password.to_owned()))
    }

    /// A server-generated secret. Never pass user input here: it skips the
    /// policy on the grounds that the platform chose the value.
    pub fn platform_generated(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }
}

impl std::fmt::Debug for NewPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewPassword(<redacted>)")
    }
}

/// BAU-15b: whether a stored hash was written with weaker KDF parameters than
/// this process now writes (or is not Argon2id at all). An unparseable hash is
/// `false`: it cannot have verified, so there is nothing to upgrade.
pub(crate) fn needs_rehash(stored: &str) -> bool {
    use argon2::password_hash::phc::PasswordHash;
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    if parsed.algorithm != argon2::Algorithm::Argon2id.ident() {
        return true;
    }
    let Ok(params) = argon2::Params::try_from(&parsed) else {
        return false;
    };
    let current = hasher();
    let current = current.params();
    params.m_cost() < current.m_cost() || params.t_cost() < current.t_cost()
}

/// BAU-15b: a fresh hash of an already-verified password at the current
/// parameters, taking a KDF permit only if one is free right now. `Ok(None)`
/// means the executor was saturated and the upgrade is simply skipped (the
/// next login retries it); it never waits, so it cannot fail or slow a login
/// behind other KDF work.
pub(crate) async fn rehash_if_capacity(password: &str) -> Result<Option<String>, AppError> {
    let password = password.to_owned();
    executor().try_run(move || hash_password(&password)).await
}

// ── Bounded KDF executor (security contract I3, I12) ────────────────────────
//
// Every Argon2 hash or verify runs through one process-wide executor: a
// semaphore sized by `kdf_permits`, a bounded wait for a permit, then the work
// on the blocking pool. Without it, each request spawned its own blocking task,
// so a login or reset flood could run hundreds of 19 MiB hashes at once.
//
// The hard cap, per-operation overhead and acquire timeout below come from the
// release-build benchmark in `examples/kdf_bench.rs`, run with the production
// `Params`
// (m=19456 KiB, t=2, p=1) on the 16-thread reference box and recorded in
// `document/base/auth/kdf-benchmark-2026-09-14.md`. They are the defaults:
// BAU-15a (hardening 2.7) makes them validated config, `auth.kdf` (see
// [`KdfSettings`] and [`configure`]).

/// Upper bound on concurrent KDF operations, whatever the host. On the
/// reference box raw Argon2 throughput rose until 5–6 concurrent operations,
/// then fell from 8 on while per-operation latency kept climbing (Argon2 is
/// memory-bandwidth-bound), so more concurrency only adds latency and memory.
const KDF_HARD_CAP: usize = 6;

/// Memory all concurrent KDF operations may use together. A policy ceiling,
/// not a measurement; with the measured footprint it allows 12 operations, so
/// the hard cap is what binds.
const KDF_MEMORY_BUDGET_BYTES: usize = 256 * 1024 * 1024;

/// Per-operation resident memory beyond `m_cost`. Measured: the peak working
/// set grew 17.8–19.6 MiB per additional concurrent operation against a
/// 19.0 MiB `m_cost`, so under 1 MiB of overhead, rounded up here. `m_cost`
/// alone is never treated as the real footprint.
const KDF_PER_OP_OVERHEAD_BYTES: usize = 1024 * 1024;

/// How long a request waits for a KDF permit before it is rejected with
/// `AppError::Overloaded` (a 503). Measured with the hard cap above: a burst of
/// 128 simultaneous verifications drained in under a second with none
/// rejected, and sustained load past capacity (200 and 300 requests/s against
/// roughly 130/s served) was shed after exactly this wait, keeping served
/// requests' p99 at 2.1 s. A shorter wait would reject bursts the executor
/// clears in time; a longer one would only raise worst-case latency.
const KDF_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);

/// BAU-15a — the KDF knobs `auth.kdf` configures. The constants above are
/// the defaults (and what a process that never calls [`configure`] uses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfSettings {
    pub hard_cap: usize,
    pub memory_budget_bytes: usize,
    pub acquire_timeout: Duration,
    pub m_cost: u32,
    pub t_cost: u32,
    pub password_min_chars: usize,
}

impl Default for KdfSettings {
    fn default() -> Self {
        Self {
            hard_cap: KDF_HARD_CAP,
            memory_budget_bytes: KDF_MEMORY_BUDGET_BYTES,
            acquire_timeout: KDF_ACQUIRE_TIMEOUT,
            m_cost: argon2::Params::DEFAULT_M_COST,
            t_cost: argon2::Params::DEFAULT_T_COST,
            password_min_chars: PASSWORD_MIN_CHARS,
        }
    }
}

impl From<&attome_config::KdfSection> for KdfSettings {
    fn from(kdf: &attome_config::KdfSection) -> Self {
        Self {
            hard_cap: kdf.hard_cap,
            memory_budget_bytes: usize::try_from(kdf.memory_budget_bytes).unwrap_or(usize::MAX),
            acquire_timeout: Duration::from_millis(kdf.acquire_timeout_ms),
            m_cost: kdf.argon2_m_cost,
            t_cost: kdf.argon2_t_cost,
            // Never below the contract floor, whatever reached this far.
            password_min_chars: kdf.password_min_length.max(PASSWORD_MIN_CHARS),
        }
    }
}

static SETTINGS: OnceLock<KdfSettings> = OnceLock::new();

/// Installs the process's KDF settings. Set-once, and only effective before
/// the first hash, verify or policy check (those read the settings and size
/// the executor on first use), so the binary calls it at boot right after the
/// config validates. Returns `false` if settings were already fixed.
pub fn configure(settings: KdfSettings) -> bool {
    SETTINGS.set(settings).is_ok()
}

fn settings() -> KdfSettings {
    *SETTINGS.get_or_init(KdfSettings::default)
}

/// Effective KDF concurrency: `max(1, min(cpus, hard cap, memory budget ÷
/// per-operation footprint))`. Pure, so the formula is unit-tested directly.
fn kdf_permits(available_parallelism: usize, m_cost_kib: u32) -> usize {
    kdf_permits_with(available_parallelism, m_cost_kib, &settings())
}

fn kdf_permits_with(available_parallelism: usize, m_cost_kib: u32, kdf: &KdfSettings) -> usize {
    let footprint = (m_cost_kib as usize) * 1024 + KDF_PER_OP_OVERHEAD_BYTES;
    let memory_limit = kdf.memory_budget_bytes / footprint;
    available_parallelism
        .min(kdf.hard_cap)
        .min(memory_limit)
        .max(1)
}

/// Runs KDF work with bounded concurrency and a bounded wait for capacity.
struct KdfExecutor {
    permits: Arc<Semaphore>,
    acquire_timeout: Duration,
    in_flight: Arc<AtomicUsize>,
    peak_in_flight: Arc<AtomicUsize>,
}

/// Held by the blocking task for the whole KDF operation. The permit and the
/// in-flight count are released only when the work finishes, so a request
/// cancelled mid-hash cannot let a new operation start while the old one is
/// still running (I12 holds under cancellation too).
struct InFlight {
    counter: Arc<AtomicUsize>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
        metrics::gauge!("auth_kdf_inflight").decrement(1.0);
    }
}

impl KdfExecutor {
    fn new(permits: usize, acquire_timeout: Duration) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(permits)),
            acquire_timeout,
            in_flight: Arc::new(AtomicUsize::new(0)),
            peak_in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn run<R, F>(&self, work: F) -> Result<R, AppError>
    where
        F: FnOnce() -> Result<R, AppError> + Send + 'static,
        R: Send + 'static,
    {
        let waiting_since = Instant::now();
        let permit = match tokio::time::timeout(
            self.acquire_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_closed)) => return Err(AppError::internal("KDF executor semaphore closed")),
            Err(_elapsed) => {
                metrics::counter!("auth_kdf_rejected_total").increment(1);
                tracing::warn!(
                    timeout_ms = self.acquire_timeout.as_millis() as u64,
                    "KDF capacity exhausted; rejecting the request"
                );
                return Err(AppError::Overloaded("authentication capacity"));
            }
        };
        metrics::histogram!("auth_kdf_wait_seconds").record(waiting_since.elapsed().as_secs_f64());
        self.spawn(permit, work).await
    }

    /// [`Self::run`] without waiting: `Ok(None)` when no permit is free now.
    async fn try_run<R, F>(&self, work: F) -> Result<Option<R>, AppError>
    where
        F: FnOnce() -> Result<R, AppError> + Send + 'static,
        R: Send + 'static,
    {
        let permit = match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(tokio::sync::TryAcquireError::NoPermits) => return Ok(None),
            Err(tokio::sync::TryAcquireError::Closed) => {
                return Err(AppError::internal("KDF executor semaphore closed"));
            }
        };
        self.spawn(permit, work).await.map(Some)
    }

    async fn spawn<R, F>(&self, permit: OwnedSemaphorePermit, work: F) -> Result<R, AppError>
    where
        F: FnOnce() -> Result<R, AppError> + Send + 'static,
        R: Send + 'static,
    {
        KDF_OPERATIONS.fetch_add(1, Ordering::SeqCst);
        let now_in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_in_flight
            .fetch_max(now_in_flight, Ordering::SeqCst);
        metrics::gauge!("auth_kdf_inflight").increment(1.0);
        let guard = InFlight {
            counter: Arc::clone(&self.in_flight),
            _permit: permit,
        };

        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            work()
        })
        .await
        .map_err(AppError::internal)?
    }
}

static KDF_OPERATIONS: AtomicUsize = AtomicUsize::new(0);

/// How many KDF operations this process has started. Test evidence only (a
/// path claimed to take no KDF permit must leave it unchanged); not a metric.
#[doc(hidden)]
pub fn kdf_operations_started() -> usize {
    KDF_OPERATIONS.load(Ordering::SeqCst)
}

/// The process-wide executor, sized once from the host and the Argon2
/// parameters actually in use.
fn executor() -> &'static KdfExecutor {
    static EXECUTOR: OnceLock<KdfExecutor> = OnceLock::new();
    EXECUTOR.get_or_init(|| {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        KdfExecutor::new(
            kdf_permits(cpus, hasher().params().m_cost()),
            settings().acquire_timeout,
        )
    })
}

/// Hashes a password through the bounded KDF executor. Returns
/// `AppError::Overloaded` if no capacity frees up within the acquire timeout.
pub async fn hash_password_async(password: NewPassword) -> Result<String, AppError> {
    executor().run(move || hash_password(&password.0)).await
}

/// Verifies a password against a stored PHC hash through the bounded KDF
/// executor. A malformed hash is `Ok(false)`, never an error.
pub async fn verify_password_async(password: &str, hash: &str) -> Result<bool, AppError> {
    let (password, hash) = (password.to_owned(), hash.to_owned());
    executor()
        .run(move || verify_password(&password, &hash))
        .await
}

/// The miss path's stand-in verify: runs the same KDF work as a real verify
/// against [`dummy_hash`], so "no such account or token" costs the same as a
/// wrong secret (security contract I17). The dummy hash is resolved inside the
/// executor, because its first use performs a full hash.
pub async fn verify_against_dummy_async(password: &str) -> Result<bool, AppError> {
    let password = password.to_owned();
    executor()
        .run(move || verify_password(&password, dummy_hash()))
        .await
}

static DUMMY_HASH: OnceLock<String> = OnceLock::new();

/// A fixed argon2 hash, computed once, with no matching password. Callers run
/// `verify_password` against this on the "not found" branch of a login/API-key
/// lookup so the miss path costs the same as the hit path — otherwise the
/// argon2 latency gap is an account enumeration oracle.
///
/// It is produced by [`hash_password`], so it always carries whatever cost
/// parameters real hashes in the same build carry — that equality, not any
/// particular work factor, is what makes the timing symmetric. Under the test
/// profile both sides drop together (see [`hasher`]), so the property still
/// holds there.
#[expect(
    clippy::expect_used,
    reason = "hashing a fixed constant with the build's own parameters cannot fail"
)]
pub(crate) fn dummy_hash() -> &'static str {
    DUMMY_HASH.get_or_init(|| {
        hash_password("attome-dummy-verify-constant-do-not-use")
            .expect("hashing a fixed constant string cannot fail")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::phc::PasswordHash;

    /// The `m` cost embedded in a PHC string, which is what verification
    /// actually re-derives its work factor from.
    fn m_cost(phc: &str) -> u32 {
        let parsed = PasswordHash::new(phc).expect("a PHC string this crate wrote must parse");
        argon2::Params::try_from(&parsed)
            .expect("argon2 parameters must be recoverable from the hash")
            .m_cost()
    }

    /// A hash written at the full production work factor must still verify
    /// under the reduced test profile, because verification derives its
    /// parameters from the stored PHC string rather than from [`hasher`].
    ///
    /// That is the claim [`hasher`]'s doc comment rests on, and the one that
    /// makes lowering the test cost safe at all: if it were ever false, every
    /// password already stored by a production deployment would stop verifying.
    /// The production-cost hash is generated here rather than pinned as a
    /// literal so the test proves the property against the argon2 version
    /// actually compiled in.
    #[test]
    fn a_production_cost_hash_still_verifies_under_the_test_profile() {
        const PASSWORD: &str = "correct-horse-battery-staple";

        let production = Argon2::default()
            .hash_password(PASSWORD.as_bytes())
            .expect("hashing at the production work factor")
            .to_string();

        // Precondition: this build really does hash more cheaply than
        // production. Without it the assertions below would still pass in a
        // build where `hasher()` had quietly reverted, proving nothing.
        let under_test = hash_password(PASSWORD).expect("hash under the test profile");
        assert!(
            m_cost(&production) > m_cost(&under_test),
            "the test profile must be cheaper than production (m={} vs m={})",
            m_cost(&production),
            m_cost(&under_test),
        );

        assert!(
            verify_password(PASSWORD, &production).expect("a well-formed PHC string must parse"),
            "a production-cost hash must verify under the reduced test profile"
        );
        assert!(
            !verify_password("wrong-password", &production)
                .expect("a well-formed PHC string must parse"),
            "a wrong password must still fail against a production-cost hash"
        );
    }

    /// Round-trip through whatever profile is compiled: hashing then verifying
    /// succeeds, and a near-miss password fails.
    #[test]
    fn hash_and_verify_round_trip() {
        let hash = hash_password("s3cr3t-value").expect("hash");
        assert!(
            hash.starts_with("$argon2id$"),
            "unexpected PHC format: {hash}"
        );
        assert!(verify_password("s3cr3t-value", &hash).expect("verify"));
        assert!(!verify_password("s3cr3t-valuf", &hash).expect("verify"));
    }

    /// `dummy_hash` is the constant the enumeration-symmetry branches verify
    /// against, so it must be stable across calls (it is computed once) and it
    /// must carry the same work factor real hashes in this build carry —
    /// that equality is the whole point, not the absolute cost.
    #[test]
    fn dummy_hash_is_stable_and_costs_what_a_real_hash_costs() {
        assert_eq!(
            dummy_hash(),
            dummy_hash(),
            "dummy_hash must be computed once"
        );
        assert_eq!(
            m_cost(dummy_hash()),
            m_cost(&hash_password("any-other-value").expect("hash")),
            "the miss path must pay exactly what the hit path pays"
        );
        assert!(
            !verify_password("a-user-supplied-password", dummy_hash())
                .expect("dummy_hash must be a parseable PHC string"),
            "no ordinary password may verify against dummy_hash"
        );
    }

    // ── validate_policy (security contract I2) ──────────────────────────────

    fn rejected(password: &str) -> bool {
        matches!(validate_policy(password), Err(AppError::Validation(_)))
    }

    #[test]
    fn policy_rejects_an_empty_password() {
        assert!(rejected(""));
    }

    #[test]
    fn policy_enforces_the_character_minimum_at_its_boundary() {
        assert!(rejected(&"a".repeat(PASSWORD_MIN_CHARS - 1)));
        assert!(validate_policy(&"a".repeat(PASSWORD_MIN_CHARS)).is_ok());
    }

    #[test]
    fn policy_counts_the_minimum_in_characters_not_bytes() {
        // 12 two-byte characters are 24 bytes: long enough by characters.
        assert!(validate_policy(&"é".repeat(PASSWORD_MIN_CHARS)).is_ok());
        // 11 of them are 22 bytes, but still one character short.
        assert!(rejected(&"é".repeat(PASSWORD_MIN_CHARS - 1)));
    }

    #[test]
    fn policy_enforces_the_byte_maximum_at_its_boundary() {
        assert!(validate_policy(&"a".repeat(PASSWORD_MAX_BYTES)).is_ok());
        assert!(rejected(&"a".repeat(PASSWORD_MAX_BYTES + 1)));
    }

    #[test]
    fn policy_counts_the_maximum_in_bytes_not_characters() {
        // 50 three-byte characters: well under 128 characters, but 150 bytes.
        assert!(rejected(&"€".repeat(50)));
    }

    #[test]
    fn policy_rejects_a_very_large_input() {
        assert!(rejected(&"a".repeat(1024 * 1024)));
    }

    #[test]
    fn policy_rejects_a_nul_character() {
        assert!(rejected("correct-horse\0battery"));
    }

    #[test]
    fn policy_has_no_composition_rules() {
        // All lowercase, no digits or symbols: allowed on length alone.
        assert!(validate_policy("correcthorsebatterystaple").is_ok());
    }

    // ── KDF executor (security contract I3, I12) ────────────────────────────

    #[test]
    fn configured_kdf_settings_bound_the_executor() {
        let kdf = KdfSettings::from(&attome_config::KdfSection {
            hard_cap: 2,
            memory_budget_bytes: 1024 * 1024 * 1024,
            acquire_timeout_ms: 500,
            argon2_m_cost: 19_456,
            argon2_t_cost: 3,
            password_min_length: 16,
        });
        assert_eq!(kdf.acquire_timeout, Duration::from_millis(500));
        assert_eq!(kdf.t_cost, 3);
        assert_eq!(kdf.password_min_chars, 16);
        assert_eq!(
            kdf_permits_with(64, 19_456, &kdf),
            2,
            "the configured hard cap binds"
        );
        assert_eq!(
            KdfSettings::default().m_cost,
            19_456,
            "the default is argon2's own, OWASP-aligned"
        );
    }

    #[test]
    fn kdf_permits_takes_the_smallest_limit_and_is_never_zero() {
        let production_m_cost = argon2::Params::DEFAULT_M_COST;
        assert_eq!(kdf_permits(1, production_m_cost), 1, "CPU limit");
        assert_eq!(kdf_permits(64, production_m_cost), KDF_HARD_CAP, "hard cap");
        // A 1 GiB m_cost fits zero times in the budget; still one permit.
        assert_eq!(kdf_permits(64, 1024 * 1024), 1, "memory limit, floored");
        // The memory term uses m_cost plus overhead, not m_cost alone.
        let footprint = (production_m_cost as usize) * 1024 + KDF_PER_OP_OVERHEAD_BYTES;
        assert!(
            KDF_MEMORY_BUDGET_BYTES / footprint
                < KDF_MEMORY_BUDGET_BYTES / ((production_m_cost as usize) * 1024)
        );
    }

    #[tokio::test]
    async fn kdf_executor_rejects_when_capacity_is_exhausted_without_running_the_work() {
        let executor = Arc::new(KdfExecutor::new(1, Duration::from_millis(50)));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();

        // Occupy the only permit until told to finish.
        let holder = {
            let executor = Arc::clone(&executor);
            tokio::spawn(async move {
                executor
                    .run(move || {
                        let _ = started_tx.send(());
                        let _ = release_rx.recv();
                        Ok(())
                    })
                    .await
            })
        };
        started_rx.await.expect("holder started");

        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_in_work = Arc::clone(&ran);
        let result = executor
            .run(move || {
                ran_in_work.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert!(
            matches!(result, Err(AppError::Overloaded(_))),
            "a request that cannot get a permit in time must be Overloaded, got {result:?}"
        );
        assert!(!ran.load(Ordering::SeqCst), "rejected work must never run");

        release_tx.send(()).expect("release holder");
        holder
            .await
            .expect("holder task")
            .expect("holder work succeeds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn kdf_executor_never_exceeds_its_permits_under_contention() {
        const PERMITS: usize = 2;
        let executor = Arc::new(KdfExecutor::new(PERMITS, Duration::from_secs(30)));
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let executor = Arc::clone(&executor);
                tokio::spawn(async move {
                    executor
                        .run(|| {
                            std::thread::sleep(Duration::from_millis(20));
                            Ok(())
                        })
                        .await
                })
            })
            .collect();
        for task in tasks {
            task.await.expect("task").expect("work succeeds");
        }
        let peak = executor.peak_in_flight.load(Ordering::SeqCst);
        assert!(peak >= 1, "work must actually have run");
        assert!(
            peak <= PERMITS,
            "peak in-flight {peak} exceeded the {PERMITS} permits"
        );
        assert_eq!(executor.in_flight.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn async_wrappers_round_trip_through_the_executor() {
        let hash = hash_password_async(NewPassword::validate("s3cr3t-value-123").expect("policy"))
            .await
            .expect("hash");
        assert!(
            verify_password_async("s3cr3t-value-123", &hash)
                .await
                .expect("verify")
        );
        assert!(
            !verify_password_async("s3cr3t-value-124", &hash)
                .await
                .expect("verify")
        );
        assert!(
            !verify_against_dummy_async("anything-at-all")
                .await
                .expect("dummy verify")
        );
    }

    // ── NewPassword (BAU-16) and rehash-on-login (BAU-15b) ──────────────────

    #[test]
    fn new_password_validate_runs_the_policy_and_redacts_its_debug() {
        assert!(matches!(
            NewPassword::validate("short"),
            Err(AppError::Validation(_))
        ));
        let accepted = NewPassword::validate("correcthorsebatterystaple").expect("policy");
        assert_eq!(format!("{accepted:?}"), "NewPassword(<redacted>)");
    }

    #[test]
    fn a_hash_weaker_than_the_current_parameters_needs_a_rehash() {
        use argon2::{Algorithm, Version};
        let current = hash_password("correcthorsebatterystaple").expect("hash");
        assert!(
            !needs_rehash(&current),
            "a current-parameter hash is left alone"
        );

        // The test profile already hashes at argon2's minimum, so weaken the
        // algorithm instead: Argon2i is below the Argon2id this crate writes.
        let argon2i = Argon2::new(
            Algorithm::Argon2i,
            Version::V0x13,
            hasher().params().clone(),
        )
        .hash_password(b"correcthorsebatterystaple")
        .expect("hash")
        .to_string();
        assert!(needs_rehash(&argon2i), "a non-Argon2id hash is upgraded");

        let production = Argon2::default()
            .hash_password(b"correcthorsebatterystaple")
            .expect("hash")
            .to_string();
        assert!(
            !needs_rehash(&production),
            "a hash stronger than the current parameters is never downgraded"
        );
        assert!(!needs_rehash("not-a-phc-string"));
    }

    #[tokio::test]
    async fn a_saturated_executor_never_fails_a_correct_login_that_needs_a_rehash() {
        let executor = Arc::new(KdfExecutor::new(1, Duration::from_secs(30)));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let holder = {
            let executor = Arc::clone(&executor);
            tokio::spawn(async move {
                executor
                    .run(move || {
                        let _ = started_tx.send(());
                        let _ = release_rx.recv();
                        Ok(())
                    })
                    .await
            })
        };
        started_rx.await.expect("holder started");

        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_in_work = Arc::clone(&ran);
        let started = Instant::now();
        let outcome = executor
            .try_run(move || {
                ran_in_work.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert!(
            matches!(outcome, Ok(None)),
            "a saturated executor skips the rehash (Ok(None)), never errors: {outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the rehash never waits for a permit"
        );
        assert!(!ran.load(Ordering::SeqCst), "skipped work never runs");

        release_tx.send(()).expect("release holder");
        holder.await.expect("holder task").expect("holder work");
        let rehashed = executor.try_run(|| Ok(7)).await.expect("free executor");
        assert_eq!(rehashed, Some(7), "with a free permit the rehash runs");
    }
}
