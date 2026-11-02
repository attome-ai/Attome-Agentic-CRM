//! Y10-T1: one Wasmtime engine per process, and every call held to three
//! limits:
//!
//! - **Fuel.** Each instruction costs fuel; a call that spends its budget
//!   stops with [`ExtensionError::OutOfFuel`].
//! - **Memory.** A store may hold at most [`Limits::memory_bytes`] of linear
//!   memory (64 MiB by default); a module that asks for more, at start or by
//!   growing, stops with [`ExtensionError::Memory`].
//! - **Time.** A ticker thread advances the engine's epoch every
//!   [`TICK`]; a call past [`Limits::timeout`] (500 ms by default) is
//!   interrupted with [`ExtensionError::Timeout`], whatever it is doing.
//!
//! Every call gets a fresh store, so nothing one call does is seen by the
//! next. The limits come from the deployment's configuration through the
//! caller (Y10-T2 wires them where hooks run).

use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wasmtime::{Config, Engine, Instance, Module, ResourceLimiter, Store, Trap};

/// The largest answer a JSON call may return, in bytes.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// How often the epoch advances.
pub const TICK: Duration = Duration::from_millis(10);

/// The limits of one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Fuel one call may spend (about one unit per instruction).
    pub fuel: u64,
    /// The most linear memory one call's store may hold, in bytes.
    pub memory_bytes: usize,
    /// The longest one call may run.
    #[serde(with = "millis")]
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            fuel: 100_000_000,
            memory_bytes: 64 * 1024 * 1024,
            timeout: Duration::from_millis(500),
        }
    }
}

impl From<&attome_config::ExtensionsSection> for Limits {
    /// The deployment's `extensions` section.
    fn from(section: &attome_config::ExtensionsSection) -> Self {
        Self {
            fuel: section.fuel,
            memory_bytes: usize::try_from(section.memory_mib)
                .unwrap_or(usize::MAX)
                .saturating_mul(1024 * 1024),
            timeout: Duration::from_millis(u64::from(section.timeout_ms)),
        }
    }
}

mod millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        u64::deserialize(d).map(Duration::from_millis)
    }
}

/// Y10-T6: what one call cost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CallCost {
    pub fuel_used: u64,
    pub elapsed: Duration,
}

/// Y10-T6: `line` with every non-empty secret value replaced by `***`, for
/// a run log. Pure.
pub fn mask_secrets(line: &str, secrets: &[&str]) -> String {
    let mut out = line.to_owned();
    let mut values: Vec<&str> = secrets.iter().copied().filter(|s| s.len() >= 3).collect();
    // Longest first, so a secret holding another is masked whole.
    values.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for value in values {
        out = out.replace(value, "***");
    }
    out
}

/// Why a call did not finish.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtensionError {
    #[error("the extension could not be loaded: {0}")]
    Load(String),
    #[error("the extension has no export `{0}` of the expected type")]
    MissingExport(String),
    #[error("the extension ran out of fuel")]
    OutOfFuel,
    #[error("the extension ran longer than {0:?}")]
    Timeout(Duration),
    #[error("the extension asked for more than {0} bytes of memory")]
    Memory(usize),
    #[error("the extension stopped: {0}")]
    Trap(String),
}

/// The store's data: the memory limit and whether it refused a request.
struct Guard {
    memory_bytes: usize,
    refused: bool,
}

impl ResourceLimiter for Guard {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.memory_bytes {
            self.refused = true;
            return Err(wasmtime::Error::msg("memory limit reached"));
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 100_000)
    }
}

/// The extension runtime: one engine, its epoch ticker, and calls.
#[derive(Clone)]
pub struct Runtime {
    engine: Engine,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime").finish_non_exhaustive()
    }
}

impl Runtime {
    /// The process's runtime, built once, with its epoch ticker.
    pub fn shared() -> Result<&'static Runtime, ExtensionError> {
        static RUNTIME: OnceLock<Result<Runtime, ExtensionError>> = OnceLock::new();
        RUNTIME
            .get_or_init(Runtime::new)
            .as_ref()
            .map_err(Clone::clone)
    }

    /// A runtime with its own engine and ticker thread (the thread lives as
    /// long as the process; [`Runtime::shared`] keeps it to one).
    pub fn new() -> Result<Self, ExtensionError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        config.wasm_component_model(true);
        let engine = Engine::new(&config).map_err(|e| ExtensionError::Load(e.to_string()))?;
        let ticker = engine.clone();
        std::thread::Builder::new()
            .name("attome-extension-epoch".into())
            .spawn(move || {
                loop {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "the epoch ticker is its own OS thread, not an async worker"
                    )]
                    std::thread::sleep(TICK);
                    ticker.increment_epoch();
                }
            })
            .map_err(|e| ExtensionError::Load(format!("the epoch ticker: {e}")))?;
        Ok(Self { engine })
    }

    /// Compiles a module (WebAssembly binary or text).
    pub fn compile(&self, bytes: impl AsRef<[u8]>) -> Result<Module, ExtensionError> {
        Module::new(&self.engine, bytes).map_err(|e| ExtensionError::Load(e.to_string()))
    }

    /// Calls the module's export `name`, `(i32) -> i32`, with `arg`, inside
    /// `limits`, in a fresh store.
    pub fn call_i32(
        &self,
        module: &Module,
        name: &str,
        arg: i32,
        limits: &Limits,
    ) -> Result<i32, ExtensionError> {
        self.call_i32_measured(module, name, arg, limits).0
    }

    /// Y10-T6: [`Self::call_i32`] with what the call cost, for its run log.
    pub fn call_i32_measured(
        &self,
        module: &Module,
        name: &str,
        arg: i32,
        limits: &Limits,
    ) -> (Result<i32, ExtensionError>, CallCost) {
        self.in_store(module, limits, |store, instance| {
            let run = instance
                .get_typed_func::<i32, i32>(&mut *store, name)
                .map_err(|_| ExtensionError::MissingExport(name.to_owned()))?;
            run.call(&mut *store, arg)
                .map_err(|e| classify(e, store.data(), limits))
        })
    }

    /// Y10-T2: calls the module's export `name` with `input` (JSON bytes)
    /// and answers its output bytes, with the call's cost. The calling
    /// convention, for modules without the component model: the module
    /// exports `memory`, `alloc(len: i32) -> i32` (where the host writes the
    /// input) and `name(ptr: i32, len: i32) -> i64`, whose answer is the
    /// output's pointer in the high 32 bits and its length in the low 32.
    pub fn call_json_measured(
        &self,
        module: &Module,
        name: &str,
        input: &[u8],
        limits: &Limits,
    ) -> (Result<Vec<u8>, ExtensionError>, CallCost) {
        self.in_store(module, limits, |store, instance| {
            let memory = instance
                .get_memory(&mut *store, "memory")
                .ok_or_else(|| ExtensionError::MissingExport("memory".into()))?;
            let alloc = instance
                .get_typed_func::<i32, i32>(&mut *store, "alloc")
                .map_err(|_| ExtensionError::MissingExport("alloc".into()))?;
            let run = instance
                .get_typed_func::<(i32, i32), i64>(&mut *store, name)
                .map_err(|_| ExtensionError::MissingExport(name.to_owned()))?;
            let len = i32::try_from(input.len())
                .map_err(|_| ExtensionError::Trap("the input is too large".into()))?;
            let ptr = alloc
                .call(&mut *store, len)
                .map_err(|e| classify(e, store.data(), limits))?;
            memory
                .write(
                    &mut *store,
                    usize::try_from(ptr).unwrap_or(usize::MAX),
                    input,
                )
                .map_err(|_| ExtensionError::Trap("alloc answered memory out of bounds".into()))?;
            let packed = run
                .call(&mut *store, (ptr, len))
                .map_err(|e| classify(e, store.data(), limits))?;
            let (out_ptr, out_len) = unpack(packed);
            if out_len > MAX_OUTPUT_BYTES {
                return Err(ExtensionError::Trap(format!(
                    "the answer is larger than {MAX_OUTPUT_BYTES} bytes"
                )));
            }
            let mut out = vec![0; out_len];
            memory
                .read(&*store, out_ptr, &mut out)
                .map_err(|_| ExtensionError::Trap("the answer is out of bounds".into()))?;
            Ok(out)
        })
    }

    /// Runs `body` against a fresh instance of `module` in a fresh store
    /// held to `limits`, and measures it.
    fn in_store<T>(
        &self,
        module: &Module,
        limits: &Limits,
        body: impl FnOnce(&mut Store<Guard>, Instance) -> Result<T, ExtensionError>,
    ) -> (Result<T, ExtensionError>, CallCost) {
        let started = std::time::Instant::now();
        let mut store = Store::new(
            &self.engine,
            Guard {
                memory_bytes: limits.memory_bytes,
                refused: false,
            },
        );
        store.limiter(|guard| guard as &mut dyn ResourceLimiter);
        let result = (|| {
            store
                .set_fuel(limits.fuel)
                .map_err(|e| ExtensionError::Load(e.to_string()))?;
            let ticks = u64::try_from(limits.timeout.as_millis() / TICK.as_millis())
                .unwrap_or(u64::MAX)
                .max(1);
            store.set_epoch_deadline(ticks);
            let instance = match Instance::new(&mut store, module, &[]) {
                Ok(instance) => instance,
                Err(e) => return Err(classify(e, store.data(), limits)),
            };
            body(&mut store, instance)
        })();
        let left = store.get_fuel().unwrap_or(0);
        let cost = CallCost {
            fuel_used: limits.fuel.saturating_sub(left),
            elapsed: started.elapsed(),
        };
        (result, cost)
    }
}

/// A JSON call's answer: pointer in the high 32 bits, length in the low.
/// Pure.
fn unpack(packed: i64) -> (usize, usize) {
    let bits = packed.cast_unsigned();
    let ptr = usize::try_from(bits >> 32).unwrap_or(usize::MAX);
    let len = usize::try_from(bits & 0xffff_ffff).unwrap_or(usize::MAX);
    (ptr, len)
}

/// The typed reason a call failed. Pure.
fn classify(error: wasmtime::Error, guard: &Guard, limits: &Limits) -> ExtensionError {
    if guard.refused {
        return ExtensionError::Memory(limits.memory_bytes);
    }
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => ExtensionError::OutOfFuel,
        Some(Trap::Interrupt) => ExtensionError::Timeout(limits.timeout),
        Some(other) => ExtensionError::Trap(other.to_string()),
        None => ExtensionError::Trap(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loops forever.
    const SPIN: &str = r#"(module (func (export "run") (param i32) (result i32) (loop $l (br $l)) (i32.const 0)))"#;

    #[test]
    fn a_module_runs_inside_its_limits() {
        let rt = Runtime::shared().unwrap();
        let module = rt
            .compile(r#"(module (func (export "run") (param i32) (result i32) (i32.add (local.get 0) (i32.const 1))))"#)
            .unwrap();
        assert_eq!(rt.call_i32(&module, "run", 41, &Limits::default()), Ok(42));
        assert_eq!(
            rt.call_i32(&module, "missing", 1, &Limits::default()),
            Err(ExtensionError::MissingExport("missing".into()))
        );
    }

    #[test]
    fn a_module_exceeding_fuel_is_stopped_with_a_typed_error() {
        let rt = Runtime::shared().unwrap();
        let module = rt.compile(SPIN).unwrap();
        let limits = Limits {
            fuel: 10_000,
            ..Limits::default()
        };
        assert_eq!(
            rt.call_i32(&module, "run", 0, &limits),
            Err(ExtensionError::OutOfFuel)
        );
    }

    #[test]
    fn a_module_running_too_long_is_interrupted() {
        let rt = Runtime::shared().unwrap();
        let module = rt.compile(SPIN).unwrap();
        let limits = Limits {
            fuel: u64::MAX,
            timeout: Duration::from_millis(50),
            ..Limits::default()
        };
        let started = std::time::Instant::now();
        assert_eq!(
            rt.call_i32(&module, "run", 0, &limits),
            Err(ExtensionError::Timeout(Duration::from_millis(50)))
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_module_asking_for_too_much_memory_is_stopped() {
        let rt = Runtime::shared().unwrap();
        // One page, then 2,000 more (125 MiB) against a 64 MiB limit.
        let module = rt
            .compile(r#"(module (memory 1) (func (export "run") (param i32) (result i32) (memory.grow (i32.const 2000))))"#)
            .unwrap();
        assert_eq!(
            rt.call_i32(&module, "run", 0, &Limits::default()),
            Err(ExtensionError::Memory(64 * 1024 * 1024))
        );
    }

    #[test]
    fn a_call_reports_its_cost_and_logs_hide_secrets() {
        let rt = Runtime::shared().unwrap();
        let module = rt.compile(SPIN).unwrap();
        let limits = Limits {
            fuel: 5_000,
            ..Limits::default()
        };
        let (result, cost) = rt.call_i32_measured(&module, "run", 0, &limits);
        assert_eq!(result, Err(ExtensionError::OutOfFuel));
        assert_eq!(cost.fuel_used, 5_000, "a spent budget is all used");
        assert_eq!(
            mask_secrets(
                "token=abc123 user=svc pass=abc12345",
                &["abc123", "abc12345", ""]
            ),
            "token=*** user=svc pass=***"
        );
    }

    /// Echoes its input: `alloc` places it at 1024 and `on_record` answers
    /// the same bytes.
    const ECHO: &str = r#"(module
        (memory (export "memory") 1)
        (func (export "alloc") (param i32) (result i32) (i32.const 1024))
        (func (export "on_record") (param i32 i32) (result i64)
            (i64.or
                (i64.shl (i64.extend_i32_u (local.get 0)) (i64.const 32))
                (i64.extend_i32_u (local.get 1)))))"#;

    #[test]
    fn a_json_call_passes_bytes_in_and_out() {
        let rt = Runtime::shared().unwrap();
        let module = rt.compile(ECHO).unwrap();
        let input = br#"{"stage":"before_save","values":{"name":"x"}}"#;
        let (out, cost) = rt.call_json_measured(&module, "on_record", input, &Limits::default());
        assert_eq!(out.unwrap(), input.to_vec());
        assert!(cost.fuel_used > 0);
        let (missing, _) = rt.call_json_measured(
            &rt.compile(SPIN).unwrap(),
            "on_record",
            input,
            &Limits::default(),
        );
        assert_eq!(missing, Err(ExtensionError::MissingExport("memory".into())));
        assert_eq!(unpack((7_i64 << 32) | 9), (7, 9));
    }

    #[test]
    fn limits_follow_the_deployment_config() {
        let limits = Limits::from(&attome_config::ExtensionsSection::default());
        assert_eq!(limits, Limits::default());
    }

    #[test]
    fn limits_read_from_configuration() {
        let limits: Limits =
            serde_json::from_str(r#"{"memory_bytes": 1048576, "timeout": 250}"#).unwrap();
        assert_eq!(limits.memory_bytes, 1_048_576);
        assert_eq!(limits.timeout, Duration::from_millis(250));
        assert_eq!(limits.fuel, Limits::default().fuel);
    }
}
