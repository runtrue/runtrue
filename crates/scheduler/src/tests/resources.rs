use super::fixtures::{job, runner};
use crate::resources;
use runtrue_workflow_ir::Isolation;

#[test]
fn reservation_and_release_update_every_counter_together() {
    let mut runner = runner("runner");
    let requirements = job("job", "tenant").requirements;

    resources::reserve(&mut runner, &requirements);
    assert_eq!(runner.active_jobs, 1);
    assert_eq!(runner.used_cpus, requirements.cpu);
    assert_eq!(runner.used_memory_bytes, requirements.memory_bytes);
    assert_eq!(runner.used_storage_bytes, requirements.storage_bytes);

    resources::release(&mut runner, Some(&requirements));
    assert_eq!(runner.active_jobs, 0);
    assert_eq!(runner.used_cpus, 0);
    assert_eq!(runner.used_memory_bytes, 0);
    assert_eq!(runner.used_storage_bytes, 0);
}

#[test]
fn wasm_slots_pack_only_wasm_jobs_up_to_the_explicit_ceiling() {
    let mut runner = runner("runner");
    runner.isolation_backends = [Isolation::Wasm, Isolation::Microvm].into_iter().collect();
    runner.max_concurrent_wasm_jobs = 3;
    let mut wasm = job("wasm", "tenant").requirements;
    wasm.isolation = Isolation::Wasm;
    assert!(resources::available(&runner, &wasm));
    resources::reserve(&mut runner, &wasm);
    assert!(resources::available(&runner, &wasm));
    assert!(!resources::available(
        &runner,
        &job("microvm", "tenant").requirements
    ));
    resources::reserve(&mut runner, &wasm);
    resources::reserve(&mut runner, &wasm);
    assert_eq!(runner.active_jobs, 3);
    assert_eq!(runner.active_wasm_jobs, 3);
    assert!(!resources::available(&runner, &wasm));
    resources::release(&mut runner, Some(&wasm));
    assert!(resources::available(&runner, &wasm));
}
