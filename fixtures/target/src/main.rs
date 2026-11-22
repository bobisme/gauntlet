use std::{net::SocketAddr, process::ExitCode};

use clap::Parser;

#[derive(Parser)]
#[command(
    version,
    about = "Run Scourge's development fixture target",
    after_help = "Examples:\n  scourge-fixture --listen 127.0.0.1:3000 --admin-secret local-reset-secret\n  SCOURGE_FIXTURE_ADMIN_SECRET=local-reset-secret scourge-fixture --listen 127.0.0.1:0\n\nAgent workflow: start the fixture, POST JSON credentials to /app/login, retain the cookie,\nthen GET /app/api/me. See fixtures/target/README.md for seeded credentials and reset.\n\nExit codes: 0 = stopped normally; 1 = invalid arguments; 2 = runtime failure."
)]
struct Args {
    /// Address to listen on; port 0 asks the OS for an available port.
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: SocketAddr,
    /// Secret required in X-Fixture-Admin-Secret for POST /app/_reset.
    #[arg(long, env = "SCOURGE_FIXTURE_ADMIN_SECRET", hide_env_values = true)]
    admin_secret: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => {
            let code = if error.use_stderr() { 1 } else { 0 };
            let _ = error.print();
            return ExitCode::from(code);
        }
    };
    if args.admin_secret.is_empty() {
        eprintln!(
            "error: administration secret is empty; set --admin-secret or SCOURGE_FIXTURE_ADMIN_SECRET"
        );
        return ExitCode::from(1);
    }
    match serve(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: fixture server failed: {error}");
            ExitCode::from(2)
        }
    }
}

async fn serve(args: Args) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!("fixture  listening  http://{}", listener.local_addr()?);
    axum::serve(listener, scourge_fixture::app(args.admin_secret))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}
