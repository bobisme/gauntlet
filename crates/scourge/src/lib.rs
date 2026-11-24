//! Shared CLI parsing, dispatch and output.

use std::{
    ffi::{OsStr, OsString},
    fmt::Write as _,
    io::{self, Write},
    path::PathBuf,
};

use clap::{
    ColorChoice, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum, error::ErrorKind,
};
use scourge_core::{
    ids::EngagementId,
    response::{Context, exit_table},
    wire::{self, ActionEffect, CommitStatus, Effect, ErrorCode, ResponseV1},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Format {
    Text,
    Pretty,
    Json,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Subcommand)]
pub enum Command {
    /// Read the workspace status.
    #[default]
    #[command(after_help = "Examples:\n  scourge status\n  scourge status --format json")]
    Status,
    /// Print the Scourge version.
    #[command(after_help = "Examples:\n  scourge version\n  scourge version --format json")]
    Version,
}

impl Command {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Version => "version",
        }
    }
}

/// Parsed selectors. A handler must resolve and authorize them before using
/// them as response identities or opening any dependency.
pub struct Invocation {
    pub command: Command,
    pub workspace: Option<PathBuf>,
    pub engagement: Option<EngagementId>,
    pub format: Format,
}

#[derive(Parser)]
#[command(name = "scourge", bin_name = "scourge", version, about = "Read Scourge workspace status", after_long_help = help_footer(), disable_help_flag = true, disable_help_subcommand = true)]
struct Args {
    /// Print help.
    #[arg(short, long, global = true)]
    help: bool,
    /// Output format. Defaults to FORMAT, then pretty on a terminal and text on a pipe.
    #[arg(long = "format", global = true, value_name = "FORMAT")]
    _formats: Vec<Format>,
    #[arg(long = "json", global = true, hide = true, action = clap::ArgAction::Count)]
    _json: u8,
    /// Select a workspace directory.
    #[arg(long, global = true, value_name = "PATH")]
    workspace: Option<PathBuf>,
    /// Select an engagement within the workspace.
    #[arg(long, global = true, value_name = "ID")]
    engagement: Option<EngagementId>,
    #[command(subcommand)]
    command: Option<ParsedCommand>,
}

#[derive(Subcommand)]
enum ParsedCommand {
    #[command(flatten)]
    Dispatch(Command),
    /// Print help for Scourge or a subcommand.
    Help { path: Vec<String> },
}

fn help_footer() -> String {
    let mut help = String::from(
        "Examples:\n  scourge status\n  scourge --format json status\n  scourge version\n\n\
         Agent workflow: read status in JSON and follow the argv in next.\n\nExit codes:\n",
    );
    for (exit, code) in exit_table() {
        let label = code.map_or(
            "Completed, including reads with blockers",
            ErrorCode::as_str,
        );
        writeln!(help, "  {exit}  {label}").expect("write help to string");
    }
    help
}

fn format_selection(args: &[OsString], env: Option<&OsStr>, terminal: bool) -> (Format, bool) {
    // Find presentation flags before parsing so an earlier invalid argument
    // cannot force a JSON caller to interpret a plaintext error.
    let mut explicit = None;
    let mut conflicting = false;
    let mut args = args.iter().skip(1).peekable();
    while let Some(argument) = args.next() {
        let value = match argument.to_str() {
            Some("--") => break,
            Some("--json") => Some("json"),
            Some("--format") => args
                .next_if(|value| !value.as_encoded_bytes().starts_with(b"-"))
                .and_then(|value| value.to_str()),
            Some(value) => value.strip_prefix("--format="),
            None => None,
        };
        if let Some(format) = value.and_then(|value| Format::from_str(value, false).ok()) {
            conflicting |= explicit.is_some_and(|selected| selected != format);
            if explicit != Some(Format::Json) {
                explicit = Some(format);
            }
        }
    }

    let env = env
        .and_then(OsStr::to_str)
        .and_then(|value| Format::from_str(value, false).ok());
    let default = if terminal {
        Format::Pretty
    } else {
        Format::Text
    };
    (explicit.or(env).unwrap_or(default), conflicting)
}

/// Parse, dispatch a command and publish one response. The handler runs only
/// after parsing. It returns an envelope without writing to the output streams.
pub fn run(
    argv: impl IntoIterator<Item = OsString>,
    format_env: Option<&OsStr>,
    stdout_is_terminal: bool,
    dispatch: impl FnOnce(Invocation) -> ResponseV1,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    let argv: Vec<_> = argv.into_iter().collect();
    let (format, conflicting) = format_selection(&argv, format_env, stdout_is_terminal);
    let response = if conflicting {
        usage_error("Select one output format.")
    } else {
        parse_and_dispatch(argv, format, dispatch)
    };

    emit_response(response, format, stdout, stderr)
}

fn parse_and_dispatch(
    argv: Vec<OsString>,
    format: Format,
    dispatch: impl FnOnce(Invocation) -> ResponseV1,
) -> ResponseV1 {
    let mut parser = Args::command().color(ColorChoice::Never);
    let args = match parser
        .try_get_matches_from_mut(argv)
        .and_then(|mut matches| Args::from_arg_matches_mut(&mut matches))
    {
        Ok(args) => args,
        Err(error) => {
            return match error.kind() {
                ErrorKind::DisplayVersion => version_response(),
                ErrorKind::UnknownArgument => usage_error("Unknown option."),
                ErrorKind::InvalidSubcommand => usage_error("Unknown command."),
                ErrorKind::InvalidValue | ErrorKind::ValueValidation | ErrorKind::InvalidUtf8 => {
                    usage_error("An argument has an invalid value.")
                }
                ErrorKind::MissingRequiredArgument => {
                    usage_error("A required argument is missing.")
                }
                _ => usage_error("Invalid arguments."),
            };
        }
    };
    let command = match args.command {
        Some(ParsedCommand::Help { path }) => return help_response(parser, path),
        Some(ParsedCommand::Dispatch(command)) => Some(command),
        None => None,
    };
    if args.help {
        return help_response(parser, command.iter().map(|command| command.as_str()));
    }
    let command = command.unwrap_or_default();
    if command == Command::Version {
        version_response()
    } else {
        dispatch(Invocation {
            command,
            workspace: args.workspace,
            engagement: args.engagement,
            format,
        })
    }
}

fn help_response(
    mut parser: clap::Command,
    path: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> ResponseV1 {
    parser.build();
    let mut target = &mut parser;
    let mut resolved = Vec::new();
    for name in path {
        let Some(command) = target.find_subcommand_mut(name) else {
            return usage_error("Unknown command.");
        };
        resolved.push(command.get_name().to_owned());
        target = command;
    }
    let context = Context {
        command: resolved.join(" ").parse().ok(),
        ..Context::default()
    };
    let mut response = context.success("help");
    response
        .extensions
        .insert("help".into(), target.render_long_help().to_string().into());
    response
}

fn version_response() -> ResponseV1 {
    let mut response = Context::for_command("version").success("version");
    response
        .extensions
        .insert("version".into(), env!("CARGO_PKG_VERSION").into());
    response
}

fn usage_error(message: &'static str) -> ResponseV1 {
    let context = Context::default();
    let mut response = context.failure(
        ErrorCode::UsageError,
        message,
        CommitStatus::NotCommitted,
        Effect::None,
    );
    response
        .next
        .push(context.action(ActionEffect::None, ["--help".parse().unwrap()]));
    response
}

/// The initial status handler has no operator binding resolver. Keep selectors
/// untrusted and unbound until the workspace service is wired in.
pub fn unbound_status(invocation: Invocation) -> ResponseV1 {
    let context = Context::for_command(invocation.command.as_str());
    if invocation.workspace.is_none() && invocation.engagement.is_none() {
        return context.blocked(vec![ErrorCode::WorkspaceUnbound]);
    }
    let mut response = context.failure(
        ErrorCode::WorkspaceUnbound,
        "No bound workspace was found.",
        CommitStatus::NotCommitted,
        Effect::None,
    );
    response
        .next
        .push(context.action(ActionEffect::None, ["status".parse().unwrap()]));
    response
}

fn emit_response(
    mut response: ResponseV1,
    format: Format,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    response.redact_diagnostics();
    let output = if format == Format::Json {
        let encoded = match wire::to_vec(&response) {
            Ok(encoded) => Ok(encoded),
            Err(_) => {
                let context = Context {
                    command: response.command,
                    workspace: response.workspace,
                    engagement: response.engagement,
                    request_key: response.request_key,
                };
                let mut fallback = context.failure(
                    ErrorCode::IntegrityFailure,
                    "The response could not be encoded.",
                    response
                        .error
                        .map_or(CommitStatus::Unknown, |error| error.commit_status),
                    response.effects,
                );
                fallback.run = response.run;
                fallback.diagnostics = response.diagnostics;
                response = fallback;
                wire::to_vec(&response)
            }
        };
        encoded
            .map_err(io::Error::other)
            .and_then(|line| write_line(stdout, line))
    } else {
        write_human(&response, format, stdout, stderr)
    };
    for diagnostic in &response.diagnostics {
        let event = response.diagnostic_event(diagnostic.clone());
        let encoded = wire::to_vec(&event).map_err(io::Error::other)?;
        // A closed stderr must not change the command outcome.
        let _ = write_line(stderr, encoded);
    }
    output.map(|()| response.exit_code())
}

fn write_line(stream: &mut impl Write, mut encoded: Vec<u8>) -> io::Result<()> {
    encoded.push(b'\n');
    stream.write_all(&encoded)
}

fn write_human(
    response: &ResponseV1,
    format: Format,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<()> {
    if let Some(help) = response
        .extensions
        .get("help")
        .and_then(serde_json::Value::as_str)
    {
        stdout.write_all(help.as_bytes())?;
    } else if let Some(version) = response
        .extensions
        .get("version")
        .and_then(serde_json::Value::as_str)
    {
        writeln!(stdout, "scourge {version}")?;
    } else if let Some(error) = &response.error {
        if format == Format::Pretty {
            writeln!(stderr, "[ERROR] {}", error.code.as_str())?;
            writeln!(stderr, "        {}", error.message.as_str())?;
        } else {
            writeln!(
                stderr,
                "{}  {}",
                error.code.as_str(),
                error.message.as_str()
            )?;
        }
        write_next(response, stderr)?;
    } else if let (Some(command), Some(result)) = (&response.command, &response.result) {
        if format == Format::Pretty {
            writeln!(stdout, "{}: {}", command.as_str(), result.as_str())?;
        } else {
            writeln!(stdout, "{}  {}", command.as_str(), result.as_str())?;
        }
        for blocker in &response.blockers {
            if format == Format::Pretty {
                writeln!(stdout, "  [BLOCKED] {}", blocker.as_str())?;
            } else {
                writeln!(stdout, "{}  blocker", blocker.as_str())?;
            }
        }
        write_next(response, stdout)?;
    }
    Ok(())
}

fn write_next(response: &ResponseV1, stream: &mut impl Write) -> io::Result<()> {
    for action in &response.next {
        let argv: Vec<_> = action
            .argv
            .iter()
            .map(|arg| shell_quote(arg.as_str()))
            .collect();
        writeln!(stream, "next  {}", argv.join(" "))?;
    }
    Ok(())
}

fn shell_quote(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-./_".contains(&byte))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
