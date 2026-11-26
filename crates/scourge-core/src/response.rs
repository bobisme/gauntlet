//! Construction and diagnostics for the frozen CLI response.

use crate::{
    ids::{EngagementId, RequestKey, WireText},
    wire::{
        AbsolutePath, Action, ActionEffect, CommitStatus, Diagnostic, DiagnosticCode, DiagnosticV1,
        DiagnosticV1Tag, Effect, Error, ErrorCode, ResponseV1, ResponseV1Tag,
    },
};

/// Resolved identities for an invocation. Unavailable identities stay null.
#[derive(Clone, Debug, Default)]
pub struct Context {
    pub command: Option<WireText>,
    pub workspace: Option<AbsolutePath>,
    pub engagement: Option<EngagementId>,
    pub request_key: Option<RequestKey>,
}

impl Context {
    pub fn for_command(command: &'static str) -> Self {
        Self {
            command: Some(text(command)),
            ..Self::default()
        }
    }

    pub fn success(&self, result: &'static str) -> ResponseV1 {
        ResponseV1 {
            schema: ResponseV1Tag::ResponseV1,
            ok: true,
            command: self.command.clone(),
            workspace: self.workspace.clone(),
            engagement: self.engagement.clone(),
            request_key: self.request_key.clone(),
            result: Some(text(result)),
            effects: Effect::None,
            finding: None,
            finding_caveats: None,
            run: None,
            error: None,
            blockers: Vec::new(),
            diagnostics: Vec::new(),
            advice: Vec::new(),
            next: Vec::new(),
            transport: None,
            extensions: Default::default(),
        }
    }

    /// A read completed and discovered blockers. The caller can inspect them
    /// without implying an unsuccessful or effectful invocation.
    pub fn blocked(&self, blockers: Vec<ErrorCode>) -> ResponseV1 {
        ResponseV1 {
            blockers,
            ..self.success("blocked")
        }
    }

    /// The message is an operator-safe description of the failure. Commit
    /// durability and external effects are independent pieces of evidence.
    pub fn failure(
        &self,
        code: ErrorCode,
        message: &'static str,
        commit_status: CommitStatus,
        effects: Effect,
    ) -> ResponseV1 {
        ResponseV1 {
            ok: false,
            result: None,
            error: Some(Error {
                code,
                message: text(message),
                commit_status,
            }),
            effects,
            ..self.success("completed")
        }
    }

    /// Make a replayable argv with the resolved scope and an explicit format.
    /// Use an unscoped context for commands that do not take scope selectors.
    pub fn action(
        &self,
        effects: ActionEffect,
        args: impl IntoIterator<Item = WireText>,
    ) -> Action {
        let mut argv = ["scourge", "--format", "json"].map(text).to_vec();
        if let Some(workspace) = &self.workspace {
            argv.extend([text("--workspace"), text(workspace.as_str())]);
        }
        if let Some(engagement) = &self.engagement {
            if engagement.as_str().starts_with('-') {
                argv.push(text(&format!("--engagement={}", engagement.as_str())));
            } else {
                argv.extend([text("--engagement"), text(engagement.as_str())]);
            }
        }
        argv.extend(args);
        Action { effects, argv }
    }
}

impl ResponseV1 {
    pub fn exit_code(&self) -> u8 {
        self.error
            .as_ref()
            .map_or(0, |error| error.code.exit_code())
    }

    /// Drop free-form diagnostic messages before either output channel sees
    /// them. Diagnostics may originate in adapters with access to secrets.
    /// Stages name application-defined operations and must be supplied by the
    /// adapter, independently of native output.
    pub fn redact_diagnostics(&mut self) {
        for diagnostic in &mut self.diagnostics {
            diagnostic.message = diagnostic_message(diagnostic.code);
        }
    }

    /// Emit the same redacted diagnostic on stderr with correlation IDs.
    /// Call after [`Self::redact_diagnostics`].
    pub fn diagnostic_event(&self, diagnostic: Diagnostic) -> DiagnosticV1 {
        DiagnosticV1 {
            schema: DiagnosticV1Tag::DiagnosticV1,
            workspace: self.workspace.clone(),
            engagement: self.engagement.clone(),
            request_key: self.request_key.clone(),
            run_id: self.run.as_ref().map(|run| run.id.clone()),
            diagnostic,
        }
    }
}

/// Project typed diagnostic metadata without carrying through a native message.
pub fn diagnostic(
    code: DiagnosticCode,
    stage: WireText,
    native_exit: Option<i64>,
    wrapper_exit: Option<i64>,
) -> Diagnostic {
    Diagnostic {
        code,
        stage,
        message: diagnostic_message(code),
        native_exit,
        wrapper_exit,
    }
}

fn diagnostic_message(code: DiagnosticCode) -> WireText {
    text(match code {
        DiagnosticCode::WrongListener => "The peer did not match the configured engine.",
        DiagnosticCode::ToolUnavailable => "The bound executable was unavailable.",
        DiagnosticCode::InvalidNativeOutput => "The native response was invalid.",
        DiagnosticCode::NativeFailure => "The native operation failed.",
        DiagnosticCode::TransportUnavailable => "The bound transport was unavailable.",
    })
}

/// The success row plus one row for every error in the frozen registry.
pub fn exit_table() -> impl Iterator<Item = (u8, Option<ErrorCode>)> {
    std::iter::once((0, None)).chain(
        ErrorCode::ALL
            .iter()
            .map(|code| (code.exit_code(), Some(*code))),
    )
}

fn text(value: &str) -> WireText {
    value.parse().expect("valid response text")
}
