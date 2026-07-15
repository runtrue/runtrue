use super::fixtures::{job, runner};
use crate::resources;

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
