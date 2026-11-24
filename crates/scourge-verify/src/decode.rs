//! Bounded, offline decoding of saved response bodies (POR-09, F-42).
//!
//! The oracle matches canaries in the decoded body only. Every coding this
//! module undoes is named by a [`DecoderName`] and bounded by [`DecodeLimits`]:
//! a body over the size or expansion-ratio limit, a coding stream that ends
//! before its final bytes, trailing bytes that belong to no named coding, or an
//! undecodable body is a [`DecodeError`], which the oracle reports as
//! `EVIDENCE_INCOMPLETE`. Nothing here reads the network, writes to disk or
//! modifies the saved original bytes; the caller keeps those byte-exact
//! (INV-27).
//!
//! Every named coding decodes its whole input, never a prefix of it. A gzip
//! body is a series of members (RFC 1952) and all of them are decoded under one
//! shared bound; a zlib or raw-deflate body must end where its single stream
//! ends. A body that carries more coded bytes than its named codings account
//! for is corrupt, not silently truncated, so a canary cannot be hidden in a
//! second member or a trailing stream.
//!
//! Undo order is fixed: transfer coding, then content coding, then an optional
//! JSON string wrapper (`application/json` bodies that carry the real payload
//! as an escaped string, either as a bare JSON string literal or as the single
//! string member of a one-member object such as `{"document":"…"}`). The
//! canonical [`DecoderName`] is derived from that pipeline, so a verifier can
//! only name a decoder the code can actually run.
//!
//! The limits a saved document carries are untrusted input, so they are clamped
//! to the compiled ceilings below before anything is allocated. A document can
//! therefore narrow the bounds, never lift them (§6.5, POR-09).

use std::{borrow::Cow, io::Read};

use flate2::read::{DeflateDecoder, MultiGzDecoder, ZlibDecoder};
use serde::{Deserialize, Serialize};

/// Conservative default decoded-size bound: 1 MiB.
pub const DEFAULT_MAX_DECODED_BYTES: u64 = 1_048_576;

/// Conservative default expansion-ratio bound: 100x.
pub const DEFAULT_MAX_EXPANSION_RATIO: u64 = 100;

/// Compiled hard ceiling on the decoded-size limit a record may request: 16 MiB.
///
/// A saved observation document is untrusted input. Without this ceiling a
/// document could record `max_decoded_bytes: u64::MAX` and make the decoder
/// allocate without bound. The ceiling is compiled in, so no record, template
/// or agent can raise it.
pub const MAX_DECODED_BYTES_CEILING: u64 = 16 * 1_048_576;

/// Compiled hard ceiling on the expansion-ratio limit a record may request.
pub const MAX_EXPANSION_RATIO_CEILING: u64 = 10_000;

/// The frozen run limits that bound every decoding step.
///
/// The engagement supplies these limits; the oracle only applies what the run
/// recorded, clamped by [`DecodeLimits::clamped`] to the compiled ceilings. They
/// are measurement bounds, not policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeLimits {
    /// Largest accepted decoded body in bytes.
    pub max_decoded_bytes: u64,
    /// Largest accepted ratio of decoded bytes to coded bytes.
    pub max_expansion_ratio: u64,
}

impl DecodeLimits {
    /// The conservative fallback when a run records no explicit limits.
    pub const DEFAULT: Self = Self {
        max_decoded_bytes: DEFAULT_MAX_DECODED_BYTES,
        max_expansion_ratio: DEFAULT_MAX_EXPANSION_RATIO,
    };

    pub const fn new(max_decoded_bytes: u64, max_expansion_ratio: u64) -> Self {
        Self {
            max_decoded_bytes,
            max_expansion_ratio,
        }
    }

    /// These limits with every field clamped to its compiled ceiling.
    ///
    /// A record may ask for less than the ceiling; it can never ask for more,
    /// so an untrusted saved document cannot request unbounded allocation.
    pub const fn clamped(self) -> Self {
        Self {
            max_decoded_bytes: if self.max_decoded_bytes > MAX_DECODED_BYTES_CEILING {
                MAX_DECODED_BYTES_CEILING
            } else {
                self.max_decoded_bytes
            },
            max_expansion_ratio: if self.max_expansion_ratio > MAX_EXPANSION_RATIO_CEILING {
                MAX_EXPANSION_RATIO_CEILING
            } else {
                self.max_expansion_ratio
            },
        }
    }

    fn enforce(self, coded_bytes: u64, decoded_bytes: u64) -> Result<(), DecodeError> {
        if decoded_bytes > self.max_decoded_bytes {
            return Err(DecodeError::OverLimit);
        }
        if coded_bytes > 0 && decoded_bytes > coded_bytes.saturating_mul(self.max_expansion_ratio) {
            return Err(DecodeError::ExpansionRatio);
        }
        Ok(())
    }
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The transfer coding of a saved response body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferCoding {
    /// The body is the payload as sent.
    #[default]
    Identity,
    /// The body carries HTTP/1.1 chunk framing.
    Chunked,
}

/// The content coding of a saved response body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentCoding {
    /// The body is not content-coded.
    #[default]
    Identity,
    /// The body is a gzip stream.
    Gzip,
    /// The body is a zlib (`Content-Encoding: deflate`) or raw deflate stream.
    Deflate,
}

/// The named pipeline applied to one saved body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decoding {
    /// Transfer coding, undone first.
    #[serde(default)]
    pub transfer: TransferCoding,
    /// Content coding, undone second.
    #[serde(default)]
    pub content: ContentCoding,
    /// Whether the body is a JSON string that carries an escaped payload.
    #[serde(default)]
    pub json_string_body: bool,
}

impl Decoding {
    /// The canonical decoder name for this pipeline, or `None` when the body
    /// needs no decoding at all.
    pub fn decoder_name(self) -> Option<DecoderName> {
        let mut parts: Vec<&'static str> = Vec::with_capacity(3);
        if self.transfer == TransferCoding::Chunked {
            parts.push("chunked");
        }
        match self.content {
            ContentCoding::Identity => {}
            ContentCoding::Gzip => parts.push("gzip"),
            ContentCoding::Deflate => parts.push("deflate"),
        }
        if self.json_string_body {
            parts.push("json_string");
        }
        if parts.is_empty() {
            return None;
        }
        Some(DecoderName(parts.join("+")))
    }
}

/// Every canonical decoder name this build can produce.
pub const DECODER_NAMES: [&str; 11] = [
    "chunked",
    "chunked+deflate",
    "chunked+deflate+json_string",
    "chunked+gzip",
    "chunked+gzip+json_string",
    "chunked+json_string",
    "deflate",
    "deflate+json_string",
    "gzip",
    "gzip+json_string",
    "json_string",
];

/// A registered body-decoder name, the record's `flow.decoder` value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DecoderName(String);

impl DecoderName {
    /// The record spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DecoderName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for DecoderName {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if DECODER_NAMES.contains(&value.as_str()) {
            Ok(Self(value))
        } else {
            Err("unregistered body decoder name")
        }
    }
}

impl From<DecoderName> for String {
    fn from(value: DecoderName) -> Self {
        value.0
    }
}

/// Why a saved body could not be decoded within the frozen limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The decoded body is larger than the configured size limit.
    #[error("decoded body exceeds the size limit")]
    OverLimit,
    /// The decoded body is larger than the coded body by more than the ratio.
    #[error("decoded body exceeds the expansion-ratio limit")]
    ExpansionRatio,
    /// The coding stream ends before its final bytes.
    #[error("coded body is truncated")]
    Truncated,
    /// The body cannot be decoded as the named codings.
    #[error("coded body is corrupt")]
    Corrupt,
}

/// A body after the named pipeline, with the bounds that applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBody {
    /// The decoded bytes the oracle matches over.
    pub bytes: Vec<u8>,
    /// The named decoder, or `None` when the body needed no decoding.
    pub decoder: Option<DecoderName>,
    /// Coded body length as saved.
    pub coded_bytes: u64,
    /// Decoded body length.
    pub decoded_bytes: u64,
}

/// Undo the named codings under the frozen bounds.
pub fn decode(
    body: &[u8],
    decoding: Decoding,
    limits: DecodeLimits,
) -> Result<DecodedBody, DecodeError> {
    // The record's limits are untrusted: clamp before any allocation.
    let limits = limits.clamped();
    let coded_bytes = body.len() as u64;
    let mut current = Cow::Borrowed(body);

    if decoding.transfer == TransferCoding::Chunked {
        current = Cow::Owned(dechunk(&current, limits)?);
    }
    if decoding.content != ContentCoding::Identity {
        current = Cow::Owned(match decoding.content {
            ContentCoding::Gzip => gunzip(&current, limits)?,
            ContentCoding::Deflate => inflate(&current, limits)?,
            ContentCoding::Identity => unreachable!("guarded above"),
        });
    }
    if decoding.json_string_body {
        current = Cow::Owned(unescape_json_string(&current)?);
    }

    // Bound before copying: an oversized identity body is never cloned.
    limits.enforce(coded_bytes, current.len() as u64)?;
    let decoded_bytes = current.len() as u64;
    Ok(DecodedBody {
        decoded_bytes,
        bytes: current.into_owned(),
        decoder: decoding.decoder_name(),
        coded_bytes,
    })
}

fn read_bounded<R: Read>(
    reader: &mut R,
    coded_bytes: u64,
    limits: DecodeLimits,
) -> Result<Vec<u8>, DecodeError> {
    let mut bytes = Vec::new();
    let ceiling = limits.max_decoded_bytes.saturating_add(1);
    reader
        .take(ceiling)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    limits.enforce(coded_bytes, bytes.len() as u64)?;
    Ok(bytes)
}

fn io_error(error: std::io::Error) -> DecodeError {
    match error.kind() {
        std::io::ErrorKind::UnexpectedEof => DecodeError::Truncated,
        _ => DecodeError::Corrupt,
    }
}

/// Decode every gzip member, under one shared bound over the whole body.
///
/// RFC 1952 defines a gzip file as a series of members, and a response body may
/// legally carry several. [`MultiGzDecoder`] decodes each member and treats any
/// remaining non-member bytes, including a corrupt later member's header or
/// trailer, as an error, so no saved byte is dropped silently.
fn gunzip(input: &[u8], limits: DecodeLimits) -> Result<Vec<u8>, DecodeError> {
    read_bounded(&mut MultiGzDecoder::new(input), input.len() as u64, limits)
}

/// Decode a single zlib or raw-deflate stream and reject any trailing bytes.
///
/// `Content-Encoding: deflate` is ambiguous between the zlib framing (RFC 1950)
/// and a raw deflate stream (RFC 1951). A body with a valid zlib header is
/// decoded only as zlib, so its trailing bytes can never be reinterpreted as a
/// second stream; otherwise the body is decoded as raw deflate. Both paths
/// require the stream to end exactly at the end of the body.
fn inflate(input: &[u8], limits: DecodeLimits) -> Result<Vec<u8>, DecodeError> {
    let coded_bytes = input.len() as u64;
    match single_stream(
        &mut ZlibDecoder::new(input),
        coded_bytes,
        input.len(),
        limits,
    ) {
        Ok(bytes) => Ok(bytes),
        Err(bound @ (DecodeError::OverLimit | DecodeError::ExpansionRatio)) => Err(bound),
        Err(zlib_error) if has_zlib_header(input) => Err(zlib_error),
        Err(zlib_error) => {
            match single_stream(
                &mut DeflateDecoder::new(input),
                coded_bytes,
                input.len(),
                limits,
            ) {
                Ok(bytes) => Ok(bytes),
                Err(bound @ (DecodeError::OverLimit | DecodeError::ExpansionRatio)) => Err(bound),
                Err(_) => Err(zlib_error),
            }
        }
    }
}

/// Whether the body starts with a well-formed zlib header (RFC 1950 §2.2).
fn has_zlib_header(input: &[u8]) -> bool {
    let Some([cmf, flg]) = input.first_chunk::<2>() else {
        return false;
    };
    let method = cmf & 0x0f;
    let window = cmf >> 4;
    let check = (u16::from(*cmf) << 8) | u16::from(*flg);
    method == 8 && window <= 7 && check % 31 == 0
}

/// Read one bounded stream and require it to consume the whole body.
fn single_stream<R: Read + StreamConsumed>(
    reader: &mut R,
    coded_bytes: u64,
    body_bytes: usize,
    limits: DecodeLimits,
) -> Result<Vec<u8>, DecodeError> {
    let bytes = read_bounded(reader, coded_bytes, limits)?;
    if reader.consumed() != body_bytes as u64 {
        // The stream ended before the body did: the remaining bytes belong to
        // no named coding and would otherwise be dropped silently.
        return Err(DecodeError::Corrupt);
    }
    Ok(bytes)
}

/// The number of coded bytes a decoder has consumed.
trait StreamConsumed {
    fn consumed(&self) -> u64;
}

impl StreamConsumed for ZlibDecoder<&[u8]> {
    fn consumed(&self) -> u64 {
        self.total_in()
    }
}

impl StreamConsumed for DeflateDecoder<&[u8]> {
    fn consumed(&self) -> u64 {
        self.total_in()
    }
}

fn dechunk(input: &[u8], limits: DecodeLimits) -> Result<Vec<u8>, DecodeError> {
    let mut cursor = 0;
    let mut payload: Vec<u8> = Vec::new();

    loop {
        let (line, next) = split_line_at(input, cursor)?;
        cursor = next;
        let size_field = line.split(|byte| *byte == b';').next().unwrap_or_default();
        let size_field = std::str::from_utf8(size_field).map_err(|_| DecodeError::Corrupt)?;
        let size_field = size_field.trim_matches(|character: char| character == ' ');
        if size_field.is_empty() {
            return Err(DecodeError::Corrupt);
        }
        let size = u64::from_str_radix(size_field, 16).map_err(|_| DecodeError::Corrupt)?;

        if size == 0 {
            loop {
                let (trailer, next) = split_line_at(input, cursor)?;
                cursor = next;
                if trailer.is_empty() {
                    break;
                }
            }
            break;
        }

        if size > limits.max_decoded_bytes {
            return Err(DecodeError::OverLimit);
        }
        let size = usize::try_from(size).map_err(|_| DecodeError::OverLimit)?;
        let end = cursor.checked_add(size).ok_or(DecodeError::OverLimit)?;
        if end.saturating_add(2) > input.len() {
            return Err(DecodeError::Truncated);
        }
        if !input[end..].starts_with(b"\r\n") {
            return Err(DecodeError::Corrupt);
        }
        payload.extend_from_slice(&input[cursor..end]);
        if payload.len() as u64 > limits.max_decoded_bytes {
            return Err(DecodeError::OverLimit);
        }
        cursor = end + 2;
    }

    limits.enforce(input.len() as u64, payload.len() as u64)?;
    Ok(payload)
}

fn split_line_at(input: &[u8], from: usize) -> Result<(&[u8], usize), DecodeError> {
    let rest = input.get(from..).ok_or(DecodeError::Truncated)?;
    let position = rest
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(DecodeError::Truncated)?;
    Ok((&rest[..position], from + position + 2))
}

/// Undo one level of JSON string escaping around the real document.
///
/// Two shapes are accepted, both strictly: a bare JSON string literal, and a
/// one-member JSON object whose only member is a string (`{"document":"…"}`),
/// which is the shape the referee fixture emits for its `escaped_json` response
/// mode. Anything else - a second member, a non-string value, an empty object,
/// an unterminated literal, trailing bytes - is corrupt, so a wrapper cannot be
/// used to smuggle undecoded bytes past the canary match.
fn unescape_json_string(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let body = trim_json_whitespace(input);
    let (out, rest) = match body.first() {
        Some(b'"') => decode_json_string_literal(body)?,
        Some(b'{') => decode_json_document_wrapper(body)?,
        _ => return Err(DecodeError::Corrupt),
    };
    if !trim_json_whitespace(rest).is_empty() {
        return Err(DecodeError::Corrupt);
    }
    if std::str::from_utf8(&out).is_err() {
        return Err(DecodeError::Corrupt);
    }
    Ok(out)
}

/// Decode `{"<name>":"<document>"}`: exactly one member, string value.
fn decode_json_document_wrapper(input: &[u8]) -> Result<(Vec<u8>, &[u8]), DecodeError> {
    let rest = trim_json_whitespace(&input[1..]);
    if rest.first() == Some(&b'}') {
        // A wrapper with no member carries no document to decode.
        return Err(DecodeError::Corrupt);
    }
    let (_, rest) = decode_json_string_literal(rest)?;
    let rest = trim_json_whitespace(rest)
        .strip_prefix(b":")
        .ok_or(DecodeError::Corrupt)?;
    let rest = trim_json_whitespace(rest);
    if rest.first() != Some(&b'"') {
        return Err(DecodeError::Corrupt);
    }
    let (document, rest) = decode_json_string_literal(rest)?;
    let rest = trim_json_whitespace(rest)
        .strip_prefix(b"}")
        .ok_or(DecodeError::Corrupt)?;
    Ok((document, rest))
}

/// Decode one JSON string literal and return its bytes plus the rest.
fn decode_json_string_literal(input: &[u8]) -> Result<(Vec<u8>, &[u8]), DecodeError> {
    if input.first() != Some(&b'"') {
        return Err(DecodeError::Corrupt);
    }

    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut index = 1;
    loop {
        let byte = *input.get(index).ok_or(DecodeError::Corrupt)?;
        match byte {
            b'"' => return Ok((out, &input[index + 1..])),
            b'\\' => {
                let escape = *input.get(index + 1).ok_or(DecodeError::Corrupt)?;
                index += 2;
                match escape {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'u' => {
                        let (character, consumed) = read_unicode_escape(input, index)?;
                        index += consumed;
                        let mut buffer = [0_u8; 4];
                        out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                    }
                    _ => return Err(DecodeError::Corrupt),
                }
            }
            control if control < 0x20 => return Err(DecodeError::Corrupt),
            plain => {
                out.push(plain);
                index += 1;
            }
        }
    }
}

/// The input without leading or trailing JSON whitespace.
fn trim_json_whitespace(input: &[u8]) -> &[u8] {
    let Some(start) = input.iter().position(|byte| !is_json_whitespace(*byte)) else {
        return &input[input.len()..];
    };
    let end = input
        .iter()
        .rposition(|byte| !is_json_whitespace(*byte))
        .map_or(start, |position| position + 1);
    &input[start..end]
}

fn read_unicode_escape(input: &[u8], index: usize) -> Result<(char, usize), DecodeError> {
    let first = read_hex_quad(input, index)?;
    if (0xD800..=0xDBFF).contains(&first) {
        if input.get(index + 4) != Some(&b'\\') || input.get(index + 5) != Some(&b'u') {
            return Err(DecodeError::Corrupt);
        }
        let second = read_hex_quad(input, index + 6)?;
        if !(0xDC00..=0xDFFF).contains(&second) {
            return Err(DecodeError::Corrupt);
        }
        let combined = 0x1_0000 + (((first - 0xD800) as u32) << 10) + (second - 0xDC00) as u32;
        let character = char::from_u32(combined).ok_or(DecodeError::Corrupt)?;
        return Ok((character, 10));
    }
    if (0xDC00..=0xDFFF).contains(&first) {
        return Err(DecodeError::Corrupt);
    }
    let character = char::from_u32(first as u32).ok_or(DecodeError::Corrupt)?;
    Ok((character, 4))
}

fn read_hex_quad(input: &[u8], index: usize) -> Result<u16, DecodeError> {
    let digits = input.get(index..index + 4).ok_or(DecodeError::Corrupt)?;
    let digits = std::str::from_utf8(digits).map_err(|_| DecodeError::Corrupt)?;
    u16::from_str_radix(digits, 16).map_err(|_| DecodeError::Corrupt)
}

fn is_json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}
