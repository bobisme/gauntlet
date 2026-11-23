use std::{fs, net::SocketAddr, path::PathBuf, process::ExitCode};

use clap::Parser;

#[derive(Parser)]
#[command(
    version,
    about = "Run Scourge's development fixture target",
    after_help = "Examples:\n  scourge-fixture --listen 127.0.0.1:3000 --admin-secret-file ./admin-secret\n  SCOURGE_FIXTURE_ADMIN_SECRET=local-reset-secret scourge-fixture --listen 127.0.0.1:0\n\nAgent workflow: start the fixture, POST JSON credentials to /app/login, retain the cookie,\nthen GET /app/api/me. See fixtures/target/README.md for seeded credentials and reset.\n\nExit codes: 0 = stopped normally; 1 = invalid arguments; 2 = runtime failure."
)]
struct Args {
    /// Address to listen on; port 0 asks the OS for an available port.
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: SocketAddr,
    /// Secret required in X-Fixture-Admin-Secret for administration requests.
    #[arg(
        long,
        env = "SCOURGE_FIXTURE_ADMIN_SECRET",
        hide_env_values = true,
        required_unless_present = "admin_secret_file"
    )]
    admin_secret: Option<String>,
    /// Read the administration secret from a UTF-8 file, ignoring trailing line endings.
    #[arg(long, conflicts_with = "admin_secret")]
    admin_secret_file: Option<PathBuf>,
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
    let secret = match args.admin_secret_file {
        Some(path) => match fs::read_to_string(path) {
            Ok(contents) => contents.trim_end_matches(['\r', '\n']).to_owned(),
            Err(error) => {
                eprintln!("error: could not read administration secret file: {error}");
                return ExitCode::from(1);
            }
        },
        None => args.admin_secret.expect("clap requires a secret source"),
    };
    if secret.is_empty() {
        eprintln!("error: administration secret is empty");
        return ExitCode::from(1);
    }
    match serve(args.listen, secret).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: fixture server failed: {error}");
            ExitCode::from(2)
        }
    }
}

async fn serve(listen: SocketAddr, admin_secret: String) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("fixture  listening  http://{}", listener.local_addr()?);
    axum::serve(listener, scourge_fixture::app(admin_secret))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}
