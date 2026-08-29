# NetGauze Service Core

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Apache licensed][apache-badge]][apache-url]


[crates-badge]: https://img.shields.io/crates/v/netgauze-service-core.svg

[crates-url]: https://crates.io/crates/netgauze-service-core

[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg

[apache-url]: https://github.com/NetGauze/NetGauze/blob/main/LICENSE

[docs-badge]: https://docs.rs/netgauze-service-core/badge.svg

[docs-url]: https://docs.rs/netgauze-service-core


Shared-nothing, thread-per-core service scaffolding for NetGauze
collectors: the `Worker` trait, a supervising `CollectionSupervisor`
(pinned spawn, in-thread panic capture, budgeted respawn, graceful
shutdown, concurrent admin plane), CPU affinity strategies with
environment auto-detection, NUMA-aware core assignment, and shared
drain-loop batch knobs (`BatchConfig`).

## Modules

- `worker` — the `Worker` trait a protocol service implements
  (`build_stats` once per slot, `build`/`run` per incarnation on the
  pinned thread) and the `WorkerContext` it receives.
- `supervisor` — `CollectionSupervisor::start/supervise/shutdown`,
  `RestartPolicy` (respawn budget + the `min_live_workers` valve),
  `SuperviseExit`, and the cloneable `AdminHandle`
  (`route`/`try_route`/`broadcast`, failed/done slot mirrors).
- `affinity` — `AffinityStrategy` (`PinnedAffinity`/`NoAffinity`,
  extensible via `PinOutcome`) and `AffinityConfig::Auto` environment
  detection (container/quota/exclusive-cpuset heuristics).
- `assignment` — `CoreAssignment::explicit` and NUMA-ordered
  physical-core discovery (`numa_ordered`, behind the default-on `numa`
  feature; disable default features to skip the vendored hwloc build).
- `batch` — validated drain-loop knobs for UDP-shaped workers.

## Shape

```rust,ignore
let mut sup = CollectionSupervisor::<MyWorker>::start(
    config,
    SupervisorOptions::new(CoreAssignment::numa_ordered(8)?)
        .with_affinity(AffinityConfig::Auto.resolve())
        .with_policy(RestartPolicy::default().with_min_live_workers(6)),
    meter,
)?;
let admin = sup.admin_handle(); // serve queries while supervising
match sup.supervise(&mut shutdown_rx).await {
    SuperviseExit::ShutdownRequested => { /* orderly teardown */ }
    SuperviseExit::BelowMinimumWorkers { .. } => { /* fail the site */ }
    _ => {}
}
sup.shutdown(Duration::from_secs(5)).await; // ALWAYS end via shutdown()
```

Workers are detached threads; every exit (clean, error, or panic —
caught in-thread) reaches the supervisor over an exit channel, and
`shutdown()` is the only correct teardown once `AdminHandle` clones
exist. Construct at most one supervisor per worker type per process:
metric callbacks are registered permanently.
