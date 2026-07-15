mod startup;

#[tokio::main]
async fn main() {
    if let Err(error) = startup::run().await {
        eprintln!("runtrue-runner: {error}");
        std::process::exit(1);
    }
}
