#![cfg(feature = "redis")]

//! Integration test for the Redis `SET NX PX` state-coordination lock backend.
//! Exercises the public `StateWriteCoordinator` directly, verifying per-scope
//! mutual exclusion across holders (the same primitive `run_package_exclusive`
//! uses to serialize sidecar writes between instances).

use rustaccio::{error::RegistryError, state_coordination::StateWriteCoordinator};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::oneshot;
use uuid::Uuid;

static ENV_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn env_lock() -> &'static tokio::sync::Mutex<()> {
    ENV_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn redis_it_url() -> String {
    std::env::var("RUSTACCIO_REDIS_IT_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:56379/".to_string())
}

async fn coordinator() -> StateWriteCoordinator {
    coordinator_with(&redis_it_url(), false).await
}

async fn coordinator_with(url: &str, fail_open: bool) -> StateWriteCoordinator {
    unsafe {
        std::env::set_var("RUSTACCIO_STATE_COORDINATION_BACKEND", "redis");
        std::env::set_var("RUSTACCIO_STATE_COORDINATION_REDIS_URL", url);
        std::env::set_var(
            "RUSTACCIO_STATE_COORDINATION_LOCK_KEY",
            "rustaccio:test:lock",
        );
        // Keep the contention check fast (clamped minimum is 1000ms).
        std::env::set_var("RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS", "1000");
        std::env::set_var("RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS", "50");
        std::env::set_var(
            "RUSTACCIO_STATE_COORDINATION_FAIL_OPEN",
            if fail_open { "true" } else { "false" },
        );
    }
    StateWriteCoordinator::from_env()
        .await
        .expect("build redis coordinator")
}

#[tokio::test]
#[ignore = "requires local Redis (`just governance-up`)"]
async fn redis_lock_serializes_same_scope() {
    let _guard = env_lock().lock().await;
    let coordinator = Arc::new(coordinator().await);
    let scope = format!("redis-lock-it:{}", Uuid::new_v4().as_simple());

    // Holder acquires the lock and keeps it until told to release.
    let (acquired_tx, acquired_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let holder_coordinator = coordinator.clone();
    let holder_scope = scope.clone();
    let holder = tokio::spawn(async move {
        holder_coordinator
            .run_exclusive_scoped(&holder_scope, "hold", || async move {
                acquired_tx.send(()).expect("signal acquired");
                release_rx.await.expect("await release");
                Ok::<(), RegistryError>(())
            })
            .await
    });

    acquired_rx.await.expect("holder acquired lock");

    // A second attempt on the SAME scope must fail to acquire within the timeout.
    let contended = coordinator
        .run_exclusive_scoped(&scope, "contend", || async { Ok::<(), RegistryError>(()) })
        .await;
    assert!(
        contended.is_err(),
        "same-scope acquire should time out while the lock is held"
    );

    // A DIFFERENT scope is unaffected and proceeds immediately.
    let other_scope = format!("{scope}:other");
    coordinator
        .run_exclusive_scoped(&other_scope, "independent", || async {
            Ok::<(), RegistryError>(())
        })
        .await
        .expect("different scope should not be blocked");

    // Release the holder, then the same scope becomes acquirable again.
    release_tx.send(()).expect("send release");
    holder
        .await
        .expect("holder task joined")
        .expect("holder operation ok");

    tokio::time::sleep(Duration::from_millis(50)).await;
    coordinator
        .run_exclusive_scoped(&scope, "after-release", || async {
            Ok::<(), RegistryError>(())
        })
        .await
        .expect("same scope acquirable after release");
}

#[tokio::test]
async fn redis_unavailable_fail_open_runs_the_operation() {
    let _guard = env_lock().lock().await;
    let coordinator = coordinator_with("redis://127.0.0.1:1/", true).await;
    let result = coordinator
        .run_exclusive_scoped("unavailable", "publish", || async {
            Ok::<_, RegistryError>(42)
        })
        .await;
    assert_eq!(result.expect("fail-open operation"), 42);
}

#[tokio::test]
async fn redis_unavailable_fail_closed_never_runs_the_operation() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let _guard = env_lock().lock().await;
    let coordinator = coordinator_with("redis://127.0.0.1:1/", false).await;
    let called = AtomicBool::new(false);
    let result = coordinator
        .run_exclusive_scoped("unavailable", "publish", || async {
            called.store(true, Ordering::SeqCst);
            Ok::<_, RegistryError>(())
        })
        .await;
    assert!(result.is_err(), "backend outage must reject the write");
    assert!(!called.load(Ordering::SeqCst));
}
