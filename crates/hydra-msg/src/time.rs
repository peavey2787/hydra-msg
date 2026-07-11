use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
type PlatformInstant = std::time::Instant;

/// Panic-free internal monotonic-ish timestamp used by hydra-msg on both native
/// and wasm32. `std::time::Instant::now()` can panic on wasm32-unknown-unknown,
/// so browser-facing state machines must use this wrapper instead.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HydraInstant {
    inner: PlatformInstant,
}

impl HydraInstant {
    #[must_use]
    pub(crate) fn now() -> Self {
        Self {
            inner: platform_now(),
        }
    }

    #[must_use]
    pub(crate) fn elapsed(self) -> Duration {
        platform_elapsed(self.inner)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn now_minus(duration: Duration) -> Self {
        Self {
            inner: platform_now_minus(duration),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn platform_now() -> PlatformInstant {
    std::time::Instant::now()
}

#[cfg(not(target_arch = "wasm32"))]
fn platform_elapsed(start: PlatformInstant) -> Duration {
    start.elapsed()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn platform_now_minus(duration: Duration) -> PlatformInstant {
    std::time::Instant::now() - duration
}

#[cfg(target_arch = "wasm32")]
type PlatformInstant = f64;

#[cfg(target_arch = "wasm32")]
fn platform_now() -> PlatformInstant {
    js_sys::Date::now()
}

#[cfg(target_arch = "wasm32")]
fn platform_elapsed(start: PlatformInstant) -> Duration {
    let elapsed_ms = js_sys::Date::now() - start;
    if elapsed_ms.is_finite() && elapsed_ms > 0.0 {
        Duration::from_secs_f64(elapsed_ms / 1_000.0)
    } else {
        Duration::ZERO
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
fn platform_now_minus(duration: Duration) -> PlatformInstant {
    js_sys::Date::now() - duration.as_secs_f64() * 1_000.0
}
