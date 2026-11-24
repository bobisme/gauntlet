//! The subset used by the frozen Teapot schemas. Unknown schema keywords
//! fail closed, so a newer capture cannot silently weaken validation.

use serde_json::Value;

pub(super) fn accepts(schema: &Value, value: &Value) -> bool {
    matches_schema(schema, schema, value, 0)
}

fn matches_schema(schema: &Value, root: &Value, value: &Value, depth: usize) -> bool {
    if depth > 128 {
        return false;
    }
    if let Some(boolean) = schema.as_bool() {
        return boolean;
    }
    let Some(keywords) = schema.as_object() else {
        return false;
    };
    let check = |schema: &Value, value: &Value| matches_schema(schema, root, value, depth + 1);
    keywords
        .iter()
        .all(|(keyword, rule)| match keyword.as_str() {
            "$defs" | "default" | "description" | "format" => true,
            "$ref" => rule
                .as_str()
                .and_then(|reference| reference.strip_prefix("#/$defs/"))
                .and_then(|name| root.get("$defs")?.get(name))
                .is_some_and(|definition| check(definition, value)),
            "type" => match rule.as_str() {
                Some(kind) => has_type(value, kind),
                None => rule.as_array().is_some_and(|types| {
                    types
                        .iter()
                        .any(|kind| kind.as_str().is_some_and(|kind| has_type(value, kind)))
                }),
            },
            "const" => value == rule,
            "anyOf" => rule
                .as_array()
                .is_some_and(|options| options.iter().any(|option| check(option, value))),
            "oneOf" => rule.as_array().is_some_and(|options| {
                options
                    .iter()
                    .filter(|option| check(option, value))
                    .take(2)
                    .count()
                    == 1
            }),
            "minimum" => bound(value, rule, |value, bound| value >= bound),
            "maximum" => bound(value, rule, |value, bound| value <= bound),
            "items" => value
                .as_array()
                .is_none_or(|items| items.iter().all(|item| check(rule, item))),
            "required" => value.as_object().is_none_or(|fields| {
                rule.as_array().is_some_and(|names| {
                    names
                        .iter()
                        .all(|name| name.as_str().is_some_and(|name| fields.contains_key(name)))
                })
            }),
            "properties" => value.as_object().is_none_or(|fields| {
                rule.as_object().is_some_and(|rules| {
                    fields
                        .iter()
                        .all(|(name, value)| rules.get(name).is_none_or(|rule| check(rule, value)))
                })
            }),
            "additionalProperties" => value.as_object().is_none_or(|fields| {
                fields.iter().all(|(name, value)| {
                    schema
                        .get("properties")
                        .and_then(|properties| properties.get(name))
                        .is_some()
                        || check(rule, value)
                })
            }),
            _ => false,
        })
}

fn bound(value: &Value, rule: &Value, compare: impl Fn(f64, f64) -> bool) -> bool {
    value
        .as_f64()
        .is_none_or(|value| rule.as_f64().is_some_and(|bound| compare(value, bound)))
}

fn has_type(value: &Value, kind: &str) -> bool {
    match kind {
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "object" => value.is_object(),
        "string" => value.is_string(),
        _ => false,
    }
}
