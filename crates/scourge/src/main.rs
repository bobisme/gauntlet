use std::{
    env,
    io::{self, IsTerminal},
    process::ExitCode,
};

use scourge_core::wire::ErrorCode;

fn main() -> ExitCode {
    let stdout = io::stdout();
    let code = scourge::run(
        env::args_os(),
        env::var_os("FORMAT").as_deref(),
        stdout.is_terminal(),
        scourge::unbound_status,
        &mut stdout.lock(),
        &mut io::stderr().lock(),
    );
    ExitCode::from(code.unwrap_or_else(|_| ErrorCode::DependencyUnavailable.exit_code()))
}
