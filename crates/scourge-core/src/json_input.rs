//! Duplicate-free JSON input for the runtime and the registry generator.

use std::{cell::RefCell, fmt};

use serde::{
    Deserializer,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};

pub(crate) const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ParseError {
    #[error("malformed JSON or trailing content")]
    Malformed,
    #[error("JSON object contains a duplicate key")]
    DuplicateKey,
    #[error("JSON number exceeds its exact representation")]
    UnsafeNumber,
}

pub(crate) fn parse(bytes: &[u8], max_integer: Option<u64>) -> Result<Value, ParseError> {
    parse_located(bytes, max_integer).map_err(|error| error.kind)
}

pub(crate) struct LocatedError {
    pub(crate) kind: ParseError,
    pub(crate) path: Vec<PathSegment>,
}

pub(crate) enum PathSegment {
    Key(String),
    Index(usize),
}

pub(crate) fn parse_located(bytes: &[u8], max_integer: Option<u64>) -> Result<Value, LocatedError> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let error = RefCell::new(None);
    let value = Checked {
        error: &error,
        max_integer,
        path: None,
    }
    .deserialize(&mut decoder)
    .map_err(|_| error.take().unwrap_or_else(malformed))?;
    decoder.end().map_err(|_| malformed())?;
    Ok(value)
}

fn malformed() -> LocatedError {
    LocatedError {
        kind: ParseError::Malformed,
        path: Vec::new(),
    }
}

struct Path<'a> {
    parent: Option<&'a Path<'a>>,
    segment: Segment<'a>,
}

#[derive(Clone, Copy)]
enum Segment<'a> {
    Key(&'a str),
    Index(usize),
}

#[derive(Clone, Copy)]
struct Checked<'a> {
    error: &'a RefCell<Option<LocatedError>>,
    max_integer: Option<u64>,
    path: Option<&'a Path<'a>>,
}

impl Checked<'_> {
    fn reject<E: de::Error>(self, error: ParseError) -> E {
        let mut path = Vec::new();
        let mut current = self.path;
        while let Some(node) = current {
            path.push(match node.segment {
                Segment::Key(key) => PathSegment::Key(key.into()),
                Segment::Index(index) => PathSegment::Index(index),
            });
            current = node.parent;
        }
        path.reverse();
        self.error.replace(Some(LocatedError { kind: error, path }));
        E::custom(error)
    }

    fn checked_integer<E: de::Error>(self, magnitude: u64, number: Number) -> Result<Value, E> {
        if self.max_integer.is_some_and(|max| magnitude > max) {
            return Err(self.reject(ParseError::UnsafeNumber));
        }
        Ok(Value::Number(number))
    }
}

impl<'de> DeserializeSeed<'de> for Checked<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Checked<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        self.checked_integer(value.unsigned_abs(), value.into())
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        self.checked_integer(value, value.into())
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        // serde_json also visits a float for an integer token outside its
        // integer range. Reject unsafe integer-valued floats in both modes.
        if value.abs() > MAX_SAFE_INTEGER as f64 && value.fract() == 0.0 {
            return Err(self.reject(ParseError::UnsafeNumber));
        }
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| self.reject(ParseError::UnsafeNumber))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        loop {
            let path = Path {
                parent: self.path,
                segment: Segment::Index(values.len()),
            };
            let child = Checked {
                path: Some(&path),
                ..self
            };
            let Some(value) = input.next_element_seed(child)? else {
                break;
            };
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = input.next_key::<String>()? {
            let path = Path {
                parent: self.path,
                segment: Segment::Key(&key),
            };
            let child = Checked {
                path: Some(&path),
                ..self
            };
            if values.contains_key(&key) {
                return Err(child.reject(ParseError::DuplicateKey));
            }
            let value = input.next_value_seed(child)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
