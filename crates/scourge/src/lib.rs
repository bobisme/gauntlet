//! Shared CLI parsing, dispatch and output.

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fmt::Write as _,
    io::{self, Write},
    path::{Path, PathBuf},
};

use clap::{
    ColorChoice, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum, error::ErrorKind,
};
use scourge_core::{
    ids::{EngagementId, LeadId},
    response::{Context, exit_table},
    wire::{self, ActionEffect, CommitStatus, Effect, ErrorCode, ResponseV1},
    workspace::{self, Authority, WorkspaceError},
};

mod entry;
pub use entry::EntryArgs;
use entry::ORIENTATION;

mod doctor;
mod lead;
mod read;
pub use read::{BoundReads, Depth, ListArgs, ObjectId, dispatch_read, dispatch_read_at};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Format {
    Text,
    Pretty,
    Json,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum Command {
    /// Read the workspace status.
    #[command(visible_aliases = ["tldr", "brief", "onboard"], after_help = "Examples:\n  scourge status\n  scourge status --format json\n  scourge status --details setup")]
    Status(EntryArgs),
    /// Inspect an explicit ID in the selected engagement.
    #[command(
        after_help = "Examples:\n  scourge show L-1 --depth summary\n  scourge show R-4 --format json\n\nAgent workflow: use an ID from list. Raw evidence is withheld."
    )]
    Show {
        /// A lead (L-...), finding (finding:L-...), run (R-...), record
        /// (V-...), or locally recorded Teapot flow (teapot:flow:N).
        #[arg(value_name = "ID")]
        id: Option<ObjectId>,
        /// Detail level for local metadata.
        #[arg(long, value_enum, default_value_t = Depth::Summary)]
        depth: Depth,
        /// Request a fresh derivation from retained originals.
        #[arg(long)]
        rederive: bool,
    },
    /// List a bounded page of IDs in the selected engagement.
    #[command(
        after_help = "Examples:\n  scourge list leads --limit 10\n  scourge list runs --status finalized --format json\n\nAgent workflow: follow next to advance a page, or pass a listed ID to show."
    )]
    List(ListArgs),
    /// Read the latest recorded checks for an engagement.
    #[command(
        after_help = "Examples:\n  scourge doctor\n  scourge doctor --engagement orders-api --format json\n\nAgent workflow: inspect the age, missing checks and recorded failures. Doctor runs no checks."
    )]
    Doctor,
    /// Print the Scourge version.
    #[command(after_help = "Examples:\n  scourge version\n  scourge version --format json")]
    Version,
    /// Create a workspace bound to an engagement declaration.
    Init { path: Option<PathBuf> },
    /// Manage engagement declarations.
    Engagement {
        #[command(subcommand)]
        action: Option<EngagementCommand>,
    },
    /// Record or revise unverified leads.
    Lead {
        #[command(subcommand)]
        action: Option<LeadCommand>,
    },
    /// Inspect the experiment that would verify a lead.
    Verify {
        #[arg(value_name = "LEAD")]
        lead: LeadId,
        /// Plan only. Sends no target traffic.
        #[arg(long)]
        plan: bool,
    },
}

impl Default for Command {
    fn default() -> Self {
        Self::Status(EntryArgs::default())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum EngagementCommand {
    /// Select one engagement and show its binding status.
    Show,
    /// Add an explicitly named engagement to a bound workspace.
    Add {
        file: Option<PathBuf>,
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum LeadCommand {
    /// Create one unverified lead in one call.
    Add(lead::LeadAddArgs),
    /// Append a lead revision.
    Set(lead::LeadSetArgs),
    /// Mark a lead withdrawn without deleting history.
    Withdraw(lead::LeadDispositionArgs),
    /// Defer a lead without deleting history.
    Defer(lead::LeadDispositionArgs),
    /// Mark a lead as a duplicate of another lead.
    Duplicate(lead::LeadDuplicateArgs),
}

impl Command {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Status(_) => "status",
            Self::Show { .. } => "show",
            Self::List(_) => "list",
            Self::Doctor => "doctor",
            Self::Version => "version",
            Self::Init { .. } => "init",
            Self::Engagement {
                action: Some(EngagementCommand::Add { .. }),
            } => "engagement add",
            Self::Engagement {
                action: Some(EngagementCommand::Show),
            } => "engagement show",
            Self::Engagement { action: None } => "engagement",
            Self::Lead {
                action: Some(LeadCommand::Add(_)),
            } => "lead add",
            Self::Lead {
                action: Some(LeadCommand::Set(_)),
            } => "lead set",
            Self::Lead {
                action: Some(LeadCommand::Withdraw(_)),
            } => "lead withdraw",
            Self::Lead {
                action: Some(LeadCommand::Defer(_)),
            } => "lead defer",
            Self::Lead {
                action: Some(LeadCommand::Duplicate(_)),
            } => "lead duplicate",
            Self::Lead { action: None } => "lead",
            Self::Verify { .. } => "verify",
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

/// Derive process-test seeds from the same Clap tree that parses the shipped
/// CLI. Braced values name fixture inputs that the process harness must
/// provide. A new command, visible alias, option or value-enum member therefore
/// enters the action-discovery test without a second command allowlist.
#[doc(hidden)]
pub fn cli_action_discovery_seeds() -> Vec<Vec<String>> {
    let command = Args::command();
    let mut seeds = BTreeSet::from([
        Vec::new(),
        vec!["--help".to_owned()],
        vec!["--version".to_owned()],
        vec!["--scourge-action-catalog-invalid".to_owned()],
    ]);
    catalog_subcommands(&command, &[], &mut seeds);
    seeds.into_iter().collect()
}

fn catalog_subcommands(
    command: &clap::Command,
    prefix: &[String],
    seeds: &mut BTreeSet<Vec<String>>,
) {
    for subcommand in command.get_subcommands() {
        for name in std::iter::once(subcommand.get_name()).chain(subcommand.get_visible_aliases()) {
            let mut path = prefix.to_vec();
            path.push(name.to_owned());
            catalog_variants(subcommand, &path, seeds);
            catalog_subcommands(subcommand, &path, seeds);
        }
    }
}

fn catalog_variants(command: &clap::Command, path: &[String], seeds: &mut BTreeSet<Vec<String>>) {
    seeds.insert(path.to_vec());
    for suffix in [["--help"], ["--scourge-action-catalog-invalid"]] {
        let mut seed = path.to_vec();
        seed.extend(suffix.map(str::to_owned));
        seeds.insert(seed);
    }
    for argument in command
        .get_arguments()
        .filter(|argument| !argument.is_global_set())
    {
        let prefix = if argument.is_positional() {
            Vec::new()
        } else if let Some(long) = argument.get_long() {
            vec![format!("--{long}")]
        } else if let Some(short) = argument.get_short() {
            vec![format!("-{short}")]
        } else {
            continue;
        };
        if argument.get_action().takes_values() || argument.is_positional() {
            let possible = argument.get_possible_values();
            let values = if possible.is_empty() {
                vec![format!(
                    "{{{}}}",
                    argument
                        .get_value_names()
                        .and_then(|names| names.first())
                        .map_or_else(|| argument.get_id().as_str(), |name| name.as_str())
                )]
            } else {
                possible
                    .into_iter()
                    .filter(|value| !value.is_hide_set())
                    .map(|value| value.get_name().to_owned())
                    .collect()
            };
            for value in values {
                let mut seed = path.to_vec();
                seed.extend(prefix.iter().cloned());
                seed.push(value);
                seeds.insert(seed);
            }
        } else {
            let mut seed = path.to_vec();
            seed.extend(prefix);
            seeds.insert(seed);
        }
    }
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
        return help_response(
            parser,
            command
                .iter()
                .flat_map(|command| command.as_str().split_whitespace()),
        );
    }
    let command = command.unwrap_or_default();
    match &command {
        Command::Version => version_response(),
        Command::Engagement { action: None } => usage_error("Choose an engagement command."),
        Command::Lead { action: None } => usage_error("Choose a lead command."),
        Command::Show { id: None, .. } => usage_error("Show requires an explicit ID."),
        Command::List(args) if !args.valid_status() => {
            usage_error("The status filter is invalid for this noun.")
        }
        _ => dispatch(Invocation {
            command,
            workspace: args.workspace,
            engagement: args.engagement,
            format,
        }),
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

fn state_root(create: bool) -> io::Result<PathBuf> {
    let path = std::env::var_os("XDG_STATE_HOME")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/state")))
        .ok_or_else(|| io::Error::other("state directory unavailable"))?;
    if !path.is_absolute() {
        return Err(io::Error::other("state directory must be absolute"));
    }
    if create {
        std::fs::create_dir_all(&path)?;
    }
    Ok(path)
}
fn declaration(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1_048_577)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err(io::Error::other("declaration too large"));
    }
    Ok(bytes)
}
fn failure(context: &Context, code: ErrorCode, message: &'static str) -> ResponseV1 {
    let mut response = context.failure(code, message, CommitStatus::NotCommitted, Effect::None);
    response
        .next
        .push(context.action(ActionEffect::None, ["status".parse().unwrap()]));
    response
}
fn workspace_failure(context: &Context, error: WorkspaceError) -> ResponseV1 {
    let code = error.code();
    let mut response = failure(
        context,
        code,
        match code {
            ErrorCode::EngagementRequired => "Select an engagement with --engagement.",
            ErrorCode::ObjectNotFound => "The engagement was not found.",
            ErrorCode::SchemaInvalid => "The engagement declaration is invalid.",
            ErrorCode::WorkspaceUnbound => "No valid operator binding was found.",
            ErrorCode::ConflictingRun => "The local coordination store is busy. Retry this read.",
            ErrorCode::IntegrityFailure => {
                "The bound coordination state failed an integrity check."
            }
            _ => "Workspace setup failed.",
        },
    );
    if matches!(error, WorkspaceError::Io(_))
        && let Some(error) = response.error.as_mut()
    {
        error.commit_status = CommitStatus::Unknown;
    }
    if code == ErrorCode::WorkspaceUnbound {
        response
            .extensions
            .insert("orientation".into(), ORIENTATION.into());
    }
    response
}

/// Dispatch using only an operator binding for workspace authority.
pub fn dispatch(invocation: Invocation) -> ResponseV1 {
    let context = Context::for_command(invocation.command.as_str());
    let state = match state_root(matches!(invocation.command, Command::Init { .. })) {
        Ok(path) => path,
        Err(_) => {
            if matches!(invocation.command, Command::Status(_))
                && invocation.workspace.is_none()
                && invocation.engagement.is_none()
            {
                return entry::unbound(&context);
            }
            return workspace_failure(&context, WorkspaceError::Unbound);
        }
    };
    let cwd = match std::env::current_dir() {
        Ok(path) => path,
        Err(_) => {
            return failure(
                &context,
                ErrorCode::DependencyUnavailable,
                "Current directory unavailable.",
            );
        }
    };
    let selected = match &invocation.command {
        Command::Init { path } => {
            let Some(path) = path else {
                return failure(&context, ErrorCode::UsageError, "Provide a workspace path.");
            };
            let Some(file) = invocation.engagement.as_ref() else {
                return failure(
                    &context,
                    ErrorCode::InputRequired,
                    "Provide --engagement FILE.",
                );
            };
            let path_in = Path::new(file.as_str());
            let Some(name) = path_in
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|s| !s.is_empty())
            else {
                return failure(
                    &context,
                    ErrorCode::UsageError,
                    "Engagement file needs a name.",
                );
            };
            let bytes = match declaration(path_in) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return failure(
                        &context,
                        ErrorCode::DependencyUnavailable,
                        "Cannot read engagement file.",
                    );
                }
            };
            workspace::init(path, &state, name, &bytes, Authority::default())
        }
        Command::Engagement {
            action: Some(EngagementCommand::Add { file, name }),
        } => {
            let (Some(file), Some(name)) = (file, name) else {
                return failure(
                    &context,
                    ErrorCode::UsageError,
                    "Provide a file and --name.",
                );
            };
            if let Err(error) = workspace::select(&cwd, invocation.workspace.as_deref(), &state) {
                return workspace_failure(&context, error);
            }
            let bytes = match declaration(file) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return failure(
                        &context,
                        ErrorCode::DependencyUnavailable,
                        "Cannot read engagement file.",
                    );
                }
            };
            workspace::add_engagement(&cwd, invocation.workspace.as_deref(), &state, name, &bytes)
        }
        _ => workspace::select(&cwd, invocation.workspace.as_deref(), &state),
    };
    let selected = match selected {
        Ok(value) => value,
        Err(WorkspaceError::Unbound)
            if matches!(invocation.command, Command::Status(_))
                && invocation.workspace.is_none()
                && invocation.engagement.is_none() =>
        {
            return entry::unbound(&context);
        }
        Err(error) => return workspace_failure(&context, error),
    };
    let mut context = context;
    context.workspace = selected.root.to_str().and_then(|s| s.parse().ok());
    if let Command::Status(args) = &invocation.command {
        return entry::bound(context, &selected, invocation.engagement.as_ref(), args);
    }
    if matches!(
        invocation.command,
        Command::Show { .. } | Command::List(_) | Command::Doctor
    ) {
        return read::dispatch_workspace(invocation, context, &selected);
    }
    let mut response = context.success("bound");
    response.extensions.insert(
        "engagements".into(),
        selected.engagements().collect::<Vec<_>>().into(),
    );
    if matches!(
        invocation.command,
        Command::Engagement {
            action: Some(EngagementCommand::Show)
        }
    ) {
        match selected.select_engagement(invocation.engagement.as_ref().map(EngagementId::as_str)) {
            Ok((id, _)) => context.engagement = id.parse().ok(),
            Err(error) => return workspace_failure(&context, error),
        }
    }
    if let Command::Lead {
        action: Some(action),
    } = &invocation.command
    {
        let (name, declaration) = match selected
            .select_engagement(invocation.engagement.as_ref().map(EngagementId::as_str))
        {
            Ok(value) => value,
            Err(error) => return workspace_failure(&context, error),
        };
        let engagement = match name.parse() {
            Ok(value) => value,
            Err(_) => return workspace_failure(&context, WorkspaceError::InvalidEngagement),
        };
        return match action {
            LeadCommand::Add(args) => lead::add(context, &selected, engagement, declaration, args),
            LeadCommand::Set(args) => lead::set(context, &selected, engagement, declaration, args),
            LeadCommand::Withdraw(args) => lead::disposition(
                context,
                &selected,
                engagement,
                args,
                scourge_core::domain::LeadEventKind::Withdrawn,
                "lead-withdrawn",
            ),
            LeadCommand::Defer(args) => lead::disposition(
                context,
                &selected,
                engagement,
                args,
                scourge_core::domain::LeadEventKind::Deferred,
                "lead-deferred",
            ),
            LeadCommand::Duplicate(args) => lead::duplicate(context, &selected, engagement, args),
        };
    }
    if let Command::Verify { lead: id, plan } = &invocation.command {
        let (name, declaration) = match selected
            .select_engagement(invocation.engagement.as_ref().map(EngagementId::as_str))
        {
            Ok(value) => value,
            Err(error) => return workspace_failure(&context, error),
        };
        let engagement = match name.parse() {
            Ok(value) => value,
            Err(_) => return workspace_failure(&context, WorkspaceError::InvalidEngagement),
        };
        if !plan {
            return failure(
                &context,
                ErrorCode::CapabilityUnavailable,
                "Effectful verification is not implemented.",
            );
        }
        return lead::plan(context, &selected, engagement, declaration, id);
    }
    response.engagement = context.engagement;
    response
}

pub fn unbound_status(invocation: Invocation) -> ResponseV1 {
    dispatch(invocation)
}

fn emit_response(
    mut response: ResponseV1,
    format: Format,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    response.redact_diagnostics();
    let events: Vec<_> = response
        .diagnostics
        .iter()
        .map(|diagnostic| {
            let mut event = response.diagnostic_event(diagnostic.clone());
            doctor::correlate_event(&response, &mut event);
            event
        })
        .collect();
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
    for event in events {
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
        if let Some(orientation) = response
            .extensions
            .get("orientation")
            .and_then(serde_json::Value::as_str)
        {
            writeln!(stderr, "{orientation}")?;
        }
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
        if let Some(engagements) = response
            .extensions
            .get("engagements")
            .and_then(serde_json::Value::as_array)
        {
            for engagement in engagements.iter().filter_map(serde_json::Value::as_str) {
                writeln!(stderr, "engagement  {engagement:?}")?;
            }
        }
        write_next(response, stderr)?;
    } else if entry::write_human(response, format, stdout)? {
    } else if let (Some(command), Some(result)) = (&response.command, &response.result) {
        if let Some(orientation) = response
            .extensions
            .get("orientation")
            .and_then(serde_json::Value::as_str)
        {
            writeln!(stdout, "{orientation}")?;
        }
        if !doctor::write_checks(response, format, stdout)?
            && !read::write_objects(response, format, stdout)?
        {
            if format == Format::Pretty {
                writeln!(stdout, "{}: {}", command.as_str(), result.as_str())?;
            } else {
                writeln!(stdout, "{}  {}", command.as_str(), result.as_str())?;
            }
        }
        for advice in &response.advice {
            if format == Format::Pretty {
                writeln!(stdout, "  [{:?}] {}", advice.level, advice.message.as_str())?;
            } else {
                writeln!(
                    stdout,
                    "{}  {}",
                    advice.r#type.as_str(),
                    advice.message.as_str()
                )?;
            }
        }
        for blocker in &response.blockers {
            if format == Format::Pretty {
                writeln!(stdout, "  [BLOCKED] {}", blocker.as_str())?;
            } else {
                writeln!(stdout, "{}  blocker", blocker.as_str())?;
            }
        }
        if let Some(engagements) = response
            .extensions
            .get("engagements")
            .and_then(serde_json::Value::as_array)
        {
            for engagement in engagements.iter().filter_map(serde_json::Value::as_str) {
                let mut escaped = String::new();
                for ch in engagement.chars() {
                    if ch.is_control() {
                        escaped.extend(ch.escape_default());
                    } else {
                        escaped.push(ch);
                    }
                }
                writeln!(stdout, "engagement  {escaped}")?;
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
