//! Recover an enclosing path from a rejected TOML document's diagnostic span.

use std::borrow::Cow;

use toml_parser::{
    Source,
    parser::{self, Event, EventKind, RecursionGuard},
};

/// TOML validates duplicates before typed decoding and exposes the offending
/// token's byte range. Its syntax events identify the containing header and
/// inline containers without interpreting comments or string values as keys.
pub(crate) fn key_path(input: &str, key_start: usize) -> Option<Vec<Cow<'_, str>>> {
    let source = Source::new(input);
    let mut table = Vec::new();
    let mut inline_path = Vec::new();
    let mut containers = Vec::new();
    let mut pending = Vec::new();
    let mut path = None;

    let mut receive = |event: Event| {
        if path.is_some() || event.span().start() > key_start {
            return;
        }
        match event.kind() {
            EventKind::StdTableOpen | EventKind::ArrayTableOpen => {
                table.clear();
                pending.clear();
            }
            EventKind::StdTableClose | EventKind::ArrayTableClose => {
                std::mem::swap(&mut table, &mut pending);
                pending.clear();
            }
            EventKind::SimpleKey => {
                if let Some(raw) = source.get(event) {
                    let mut key = Cow::default();
                    raw.decode_key(&mut key, &mut ());
                    pending.push(key);
                    if event.span().start() == key_start {
                        path = Some(
                            table
                                .iter()
                                .chain(&inline_path)
                                .chain(&pending)
                                .cloned()
                                .collect(),
                        );
                    }
                }
            }
            EventKind::InlineTableOpen | EventKind::ArrayOpen => {
                containers.push(inline_path.len());
                inline_path.append(&mut pending);
            }
            EventKind::InlineTableClose | EventKind::ArrayClose => {
                if let Some(parent_depth) = containers.pop() {
                    inline_path.truncate(parent_depth);
                }
                pending.clear();
            }
            EventKind::Scalar => pending.clear(),
            _ => {}
        }
    };

    // Match the normal TOML parser's depth limit for malformed input.
    let mut receiver = RecursionGuard::new(&mut receive, 80);
    parser::parse_document(&source.lex().into_vec(), &mut receiver, &mut ());
    path
}
