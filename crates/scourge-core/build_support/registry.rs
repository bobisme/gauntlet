//! Validate the registry and generate the Rust wire types and exit table.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

use serde::Deserialize;

use crate::json_input::{self, MAX_SAFE_INTEGER};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema: String,
    enums: BTreeMap<String, Vec<String>>,
    error_exits: BTreeMap<String, u8>,
    shapes: BTreeMap<String, BTreeMap<String, String>>,
    extensible_shapes: Vec<String>,
}

pub(crate) fn generate(bytes: &[u8]) -> Result<String, String> {
    let value = json_input::parse(bytes, Some(MAX_SAFE_INTEGER)).map_err(|e| e.to_string())?;
    if !value.is_object() {
        return Err("contract registry must be a JSON object".into());
    }
    let registry: Registry = serde_json::from_value(value).map_err(|e| e.to_string())?;
    registry.validate()?;
    let mut output = String::new();

    for (name, options) in &registry.enums {
        emit_enum(
            &mut output,
            &rust_name(name),
            options.iter().map(String::as_str),
        );
    }
    let exits = &registry.error_exits;
    emit_enum(&mut output, "ErrorCode", exits.keys().map(String::as_str));
    output.push_str("impl ErrorCode { pub const fn exit_code(self) -> u8 { match self {\n");
    for (code, exit) in exits {
        writeln!(output, "Self::{} => {exit},", rust_name(code)).unwrap();
    }
    output.push_str("} } }\n");

    let mut literals = BTreeSet::new();
    for (name, fields) in &registry.shapes {
        for rule in fields.values() {
            if let Some(literal) = rule.strip_prefix('=')
                && literals.insert(literal)
            {
                emit_enum(&mut output, &literal_type(literal), [literal]);
            }
        }
        let allow_extra = registry.extensible_shapes.contains(name);
        let has_untyped_data = allow_extra || fields.values().any(|rule| rule == "object");
        let struct_name = rust_name(name);
        if !has_untyped_data {
            output.push_str("#[derive(Debug)]\n");
        }
        output.push_str("#[derive(Clone, PartialEq, Eq, Serialize)]\n");
        writeln!(output, "pub struct {struct_name} {{").unwrap();
        let mut members = Vec::with_capacity(fields.len() + usize::from(allow_extra));
        for (field, rule) in fields {
            let field_type = wire_type(&registry, name, field, rule);
            writeln!(output, "pub r#{field}: {field_type},").unwrap();
            members.push((field.as_str(), field_type, rule.ends_with('?')));
        }
        if allow_extra {
            output.push_str(
                "#[serde(flatten)] pub extensions: serde_json::Map<String, serde_json::Value>,\n",
            );
            members.push(("extensions", scalar_type("object").unwrap().into(), false));
        }
        output.push_str("}\n");
        emit_object_decoder(&mut output, &struct_name, &members, allow_extra);
        emit_sealed(&mut output, &struct_name);
        if has_untyped_data {
            writeln!(
                output,
                "impl std::fmt::Debug for {struct_name} {{
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
                    f.debug_struct({struct_name:?}).finish_non_exhaustive()
                }}
            }}"
            )
            .unwrap();
        }
    }

    Ok(output)
}

fn emit_enum<'a>(output: &mut String, name: &str, variants: impl IntoIterator<Item = &'a str>) {
    let variants: Vec<_> = variants.into_iter().collect();
    output.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]\n");
    output.push_str("#[serde(try_from = \"String\")]\n");
    writeln!(output, "pub enum {name} {{").unwrap();
    for variant in &variants {
        writeln!(
            output,
            "#[serde(rename = {variant:?})] {},",
            rust_name(variant)
        )
        .unwrap();
    }
    output.push_str("}\n");
    writeln!(
        output,
        "impl TryFrom<String> for {name} {{
        type Error = &'static str;
        fn try_from(value: String) -> Result<Self, &'static str> {{
            match value.as_str() {{"
    )
    .unwrap();
    for variant in variants {
        writeln!(output, "{variant:?} => Ok(Self::{}),", rust_name(variant)).unwrap();
    }
    output.push_str("_ => Err(\"unregistered wire value\"),\n} } }\n");
    emit_sealed(output, name);
}

fn emit_object_decoder(
    output: &mut String,
    name: &str,
    members: &[(&str, String, bool)],
    allow_extra: bool,
) {
    writeln!(output, "impl<'de> Deserialize<'de> for {name} {{
        fn deserialize<__WireDeserializer: Deserializer<'de>>(decoder: __WireDeserializer) -> Result<Self, __WireDeserializer::Error> {{
            #[derive(Deserialize)]").unwrap();
    if !allow_extra {
        output.push_str("#[serde(deny_unknown_fields)]\n");
    }
    output.push_str("struct __WireFields {\n");
    for (field, field_type, nullable) in members {
        if *nullable {
            output.push_str("#[serde(deserialize_with = \"required_nullable\")]\n");
        }
        if allow_extra && *field == "extensions" {
            output.push_str("#[serde(flatten)]\n");
        }
        writeln!(output, "r#{field}: {field_type},").unwrap();
    }
    output.push_str("}\nlet fields: __WireFields = deserialize_object(decoder)?;\nOk(Self {\n");
    for (field, _, _) in members {
        writeln!(output, "r#{field}: fields.r#{field},").unwrap();
    }
    output.push_str("}) } }\n");
}

fn emit_sealed(output: &mut String, name: &str) {
    writeln!(
        output,
        "impl crate::canonical::sealed::Sealed for {name} {{}}"
    )
    .unwrap();
}

impl Registry {
    fn validate(&self) -> Result<(), String> {
        if self.schema != "scourge.contract-registry.v1" {
            return Err("unsupported contract registry schema".into());
        }
        let mut types = BTreeMap::new();
        for name in [
            "ErrorCode",
            "Option",
            "Vec",
            "String",
            "Result",
            "Serialize",
            "Deserialize",
            "Deserializer",
            "TryFrom",
            "CanonicalJson",
            "JsonError",
            "Sha256Digest",
            "LeadId",
            "RunId",
            "FindingId",
            "VerificationId",
            "RequestKey",
            "PublicationIntentId",
            "EngagementId",
            "ArtifactId",
            "RunNonce",
            "WireText",
            "AbsolutePath",
            "GitCommit",
            "KebabCase",
            "ReasonCode",
            "Probability",
            "Timestamp",
        ] {
            types.insert(name.to_string(), "built-in type");
        }
        for name in self.enums.keys().chain(self.shapes.keys()) {
            checked_name(name, "type name")?;
            if scalar_type(name).is_some() {
                return Err(format!("type name {name:?} collides with a primitive rule"));
            }
            register_name(&mut types, rust_name(name), name)?;
        }

        for options in self.enums.values() {
            validate_variants(options.iter().map(String::as_str))?;
        }
        validate_variants(self.error_exits.keys().map(String::as_str))?;

        let mut extensible = BTreeSet::new();
        for name in &self.extensible_shapes {
            if !self.shapes.contains_key(name) || !extensible.insert(name) {
                return Err(format!("unknown or repeated extensible shape {name:?}"));
            }
        }

        let mut literals = BTreeSet::new();
        for (name, fields) in &self.shapes {
            for (field, rule) in fields {
                if !valid_field(field) || (extensible.contains(name) && field == "extensions") {
                    return Err(format!("invalid field name {name}.{field:?}"));
                }
                if let Some(literal) = rule.strip_prefix('=') {
                    if literals.insert(literal) {
                        checked_name(literal, "literal")?;
                        register_name(&mut types, literal_type(literal), literal)?;
                    }
                    continue;
                }
                let required = rule.strip_suffix('?').unwrap_or(rule);
                let base = required.strip_suffix("[]").unwrap_or(required);
                if !self.enums.contains_key(base)
                    && !self.shapes.contains_key(base)
                    && scalar_type(base).is_none()
                {
                    return Err(format!("unknown type {rule:?} in {name}.{field}"));
                }
            }
        }
        Ok(())
    }
}

fn validate_variants<'a>(options: impl Iterator<Item = &'a str>) -> Result<(), String> {
    let mut names = BTreeMap::new();
    for option in options {
        checked_name(option, "enum variant")?;
        register_name(&mut names, rust_name(option), option)?;
    }
    Ok(())
}

fn register_name<'a>(
    names: &mut BTreeMap<String, &'a str>,
    rust: String,
    source: &'a str,
) -> Result<(), String> {
    if let Some(previous) = names.insert(rust.clone(), source) {
        return Err(format!(
            "Rust name {rust} collides for {previous:?} and {source:?}"
        ));
    }
    Ok(())
}

fn valid_field(name: &str) -> bool {
    !matches!(name, "self" | "crate" | "super")
        && name.starts_with(|character: char| character.is_ascii_lowercase())
        && name.split('_').all(|piece| {
            !piece.is_empty()
                && piece
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn checked_name(name: &str, kind: &str) -> Result<(), String> {
    let local = name.strip_prefix("scourge.").unwrap_or(name);
    if local.starts_with(|character: char| character.is_ascii_alphabetic())
        && local.split(['_', '-', '.']).all(|piece| {
            !piece.is_empty() && piece.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        && rust_name(name) != "Self"
    {
        return Ok(());
    }
    Err(format!("invalid {kind} {name:?}"))
}

fn rust_name(name: &str) -> String {
    match name {
        "run" => "RunSummary".into(),
        "finding" => "FindingSummary".into(),
        name => name
            .trim_start_matches("scourge.")
            .split(['_', '-', '.'])
            .map(|piece| {
                let mut part = piece.to_ascii_lowercase();
                part[..1].make_ascii_uppercase();
                part
            })
            .collect(),
    }
}

fn literal_type(literal: &str) -> String {
    format!("{}Tag", rust_name(literal))
}

fn wire_type(registry: &Registry, shape: &str, field: &str, rule: &str) -> String {
    if let Some(inner) = rule.strip_suffix('?') {
        return format!("Option<{}>", wire_type(registry, shape, field, inner));
    }
    if let Some(inner) = rule.strip_suffix("[]") {
        return format!("Vec<{}>", wire_type(registry, shape, field, inner));
    }
    if let Some(literal) = rule.strip_prefix('=') {
        return literal_type(literal);
    }
    if registry.shapes.contains_key(rule) || registry.enums.contains_key(rule) {
        return rust_name(rule);
    }
    match rule {
        "string" => match (shape, field) {
            (_, "engagement") => "EngagementId",
            (_, "run_id") | ("run", "id") => "RunId",
            (_, "lead_id") => "LeadId",
            (_, "finding_id") | ("finding", "id") => "FindingId",
            (_, "record_id" | "status_record" | "deciding_record" | "baseline_record") => {
                "VerificationId"
            }
            (_, "intent_id") => "PublicationIntentId",
            (_, "artifact_id") => "ArtifactId",
            _ => "WireText",
        },
        _ => scalar_type(rule).expect("scalar type was validated"),
    }
    .into()
}

fn scalar_type(rule: &str) -> Option<&'static str> {
    Some(match rule {
        "string" => "WireText",
        "object" => "serde_json::Map<String, serde_json::Value>",
        "boolean" => "bool",
        "integer" => "i64",
        "uint" => "u64",
        "sha256" => "Sha256Digest",
        "nonce" => "RunNonce",
        "request_key" => "RequestKey",
        "git_commit" => "GitCommit",
        "kebab_case" => "KebabCase",
        "reason_code" => "ReasonCode",
        "probability" => "Probability",
        "timestamp" => "Timestamp",
        "absolute_path" => "AbsolutePath",
        "error_code" => "ErrorCode",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::generate;

    fn registry(exits: &str, enums: &str, shapes: &str) -> String {
        format!(
            r#"{{"schema":"scourge.contract-registry.v1","error_exits":{exits},"enums":{enums},"shapes":{shapes},"extensible_shapes":[]}}"#
        )
    }

    #[test]
    fn registry_rejects_duplicate_shapes_fields_and_error_exits_before_emission() {
        for input in [
            registry("{}", "{}", r#"{"run":{},"run":{}}"#),
            registry("{}", "{}", r#"{"run":{"id":"string","\u0069d":"string"}}"#),
            registry(r#"{"USAGE_ERROR":2,"USAGE_ERROR":7}"#, "{}", "{}"),
        ] {
            assert_eq!(
                generate(input.as_bytes()),
                Err("JSON object contains a duplicate key".into())
            );
        }
    }

    #[test]
    fn registry_checks_names_before_generation() {
        for (shapes, kind) in [
            (r#"{"bad--name":{}}"#, "type name"),
            (r#"{"nön_ascii":{}}"#, "type name"),
            (r#"{"run":{"unsafe field":"string"}}"#, "field name"),
            (r#"{"run":{"self":"string"}}"#, "field name"),
            (r#"{"run":{"schema":"=scourge..v1"}}"#, "literal"),
        ] {
            let error = generate(registry("{}", "{}", shapes).as_bytes()).unwrap_err();
            assert!(error.contains(kind), "{error}");
        }
    }

    #[test]
    fn registry_requires_an_object() {
        let input = br#"["scourge.contract-registry.v1",{},{},{},[]]"#;
        assert_eq!(
            generate(input),
            Err("contract registry must be a JSON object".into())
        );
    }

    #[test]
    fn registry_rejects_normalization_collisions_across_generated_names() {
        for (enums, shapes) in [
            (r#"{"profile":["a-b","a_b"]}"#, "{}"),
            (r#"{"proof-v1":[]}"#, r#"{"scourge.proof.v1":{}}"#),
            ("{}", r#"{"run":{},"run_summary":{}}"#),
            ("{}", r#"{"run":{"a":"=foo-bar","b":"=foo_bar"}}"#),
            ("{}", r#"{"run":{"schema":"=example"},"example_tag":{}}"#),
            ("{}", r#"{"option":{}}"#),
        ] {
            let error = generate(registry("{}", enums, shapes).as_bytes()).unwrap_err();
            assert!(error.contains("collides"), "{error}");
        }
    }
}
