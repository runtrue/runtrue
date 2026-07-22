#[tokio::main]
async fn main() {
    let result = runtrue_autoscaler::AutoscalerConfig::from_env()
        .and_then(runtrue_autoscaler::AutoscalerRuntime::new)
        .map(|runtime| runtime.run_until_signal());
    let result = match result {
        Ok(future) => future.await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("runtrue-autoscaler: {error}");
        std::process::exit(1);
    }
}
