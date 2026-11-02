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
        let mut store = Store::new(
            &self.engine,
            Guard {
                memory_bytes: limits.memory_bytes,
                refused: false,
            },
        );
        store.limiter(|guard| guard as &mut dyn ResourceLimiter);
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
        let run = instance
            .get_typed_func::<i32, i32>(&mut store, name)
            .map_err(|_| ExtensionError::MissingExport(name.to_owned()))?;
        run.call(&mut store, arg)
            .map_err(|e| classify(e, store.data(), limits))
    }
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
    fn limits_read_from_configuration() {
        let limits: Limits =
            serde_json::from_str(r#"{"memory_bytes": 1048576, "timeout": 250}"#).unwrap();
        assert_eq!(limits.memory_bytes, 1_048_576);
        assert_eq!(limits.timeout, Duration::from_millis(250));
        assert_eq!(limits.fuel, Limits::default().fuel);
    }
}
