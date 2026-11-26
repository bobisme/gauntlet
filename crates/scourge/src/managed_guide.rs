//! CLI receipt for the optional, post-binding AGENTS.md write.

use std::path::Path;

use scourge_core::{
    response::Context,
    wire::{CommitStatus, Effect, ErrorCode, ResponseV1},
    workspace::{
        Authority,
        managed_guide::{self, Error, Receipt, Status},
    },
};
use serde_json::json;

pub(crate) fn init(
    mut context: Context,
    root: &Path,
    state: &Path,
    name: &str,
    declaration: &[u8],
) -> ResponseV1 {
    let (workspace, guide) =
        match managed_guide::init(root, state, name, declaration, Authority::default()) {
            Ok(result) => result,
            Err(error) => return crate::workspace_failure(&context, error),
        };
    context.workspace = workspace.root.to_str().and_then(|path| path.parse().ok());
    match guide {
        Ok(receipt) => {
            let mut response = context.success("bound");
            response.extensions.insert(
                "engagements".into(),
                workspace.engagements().collect::<Vec<_>>().into(),
            );
            response
                .extensions
                .insert("managed_guide".into(), receipt_json(receipt));
            response
        }
        Err(error) => write_failure(&context, error),
    }
}

pub(crate) fn receipt_json(receipt: Receipt) -> serde_json::Value {
    let status = match receipt.status {
        Status::Installed => "installed",
        Status::Unchanged => "unchanged",
    };
    json!({ "status": status, "sha256": receipt.digest })
}

pub(crate) fn write_failure(context: &Context, error: Error) -> ResponseV1 {
    let (status, code, message) = match error {
        Error::Ambiguous => (
            "ambiguous",
            ErrorCode::IntegrityFailure,
            "Workspace bound. Review the ambiguous Scourge markers in AGENTS.md before retrying.",
        ),
        Error::Edited => (
            "edited",
            ErrorCode::IntegrityFailure,
            "Workspace bound. Review the edited Scourge block in AGENTS.md before retrying.",
        ),
        Error::UnsafePath => (
            "unsafe-path",
            ErrorCode::IntegrityFailure,
            "Workspace bound. AGENTS.md must be a regular file with a single link.",
        ),
        Error::Busy => (
            "busy",
            ErrorCode::ConflictingRun,
            "Workspace bound. AGENTS.md changed or a guide install is running. Retry init.",
        ),
        Error::Io(_) => (
            "io-error",
            ErrorCode::DependencyUnavailable,
            "Workspace bound. Check AGENTS.md before retrying the guide installation.",
        ),
    };
    let mut failure = context.failure(code, message, CommitStatus::Committed, Effect::None);
    failure
        .extensions
        .insert("managed_guide".into(), json!({ "status": status }));
    failure
}
