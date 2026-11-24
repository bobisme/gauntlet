//! Named, bounded decoding: every mode, every bound and the oracle path.

mod common;

use scourge_verify::{
    ContentCoding, DecodeError, DecodeLimits, DecoderName, Decoding, FlowId, IncompleteCause,
    TransferCoding, Verdict, decode, evaluate,
};

const PAYLOAD: &[u8] = b"{\"secret\":\"0123456789abcdef0123456789abcdef\"}";

fn name(value: &str) -> DecoderName {
    DecoderName::try_from(value.to_owned()).expect("registered decoder name")
}

#[test]
fn identity_body_needs_no_decoder() {
    let decoded = decode(PAYLOAD, Decoding::default(), DecodeLimits::default()).expect("decode");

    assert_eq!(decoded.bytes, PAYLOAD);
    assert_eq!(decoded.decoder, None);
    assert_eq!(decoded.coded_bytes, PAYLOAD.len() as u64);
    assert_eq!(decoded.decoded_bytes, PAYLOAD.len() as u64);
}

#[test]
fn gzip_content_coding_is_undone_and_named() {
    let coded = common::gzip(PAYLOAD);
    let decoded = decode(
        &coded,
        Decoding {
            content: ContentCoding::Gzip,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect("gzip decode");

    assert_eq!(decoded.bytes, PAYLOAD);
    assert_eq!(decoded.decoder, Some(name("gzip")));
}

#[test]
fn zlib_deflate_content_coding_is_undone_and_named() {
    let coded = common::zlib(PAYLOAD);
    let decoded = decode(
        &coded,
        Decoding {
            content: ContentCoding::Deflate,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect("deflate decode");

    assert_eq!(decoded.bytes, PAYLOAD);
    assert_eq!(decoded.decoder, Some(name("deflate")));
}

#[test]
fn raw_deflate_content_coding_is_undone_and_named() {
    let coded = common::raw_deflate(PAYLOAD);
    let decoded = decode(
        &coded,
        Decoding {
            content: ContentCoding::Deflate,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect("raw deflate decode");

    assert_eq!(decoded.bytes, PAYLOAD);
    assert_eq!(decoded.decoder, Some(name("deflate")));
}

#[test]
fn chunked_transfer_coding_is_undone_and_named() {
    let coded = common::chunked(PAYLOAD, &[5, 7, 11]);
    let decoded = decode(
        &coded,
        Decoding {
            transfer: TransferCoding::Chunked,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect("chunked decode");

    assert_eq!(decoded.bytes, PAYLOAD);
    assert_eq!(decoded.decoder, Some(name("chunked")));
}

#[test]
fn an_empty_chunked_body_decodes_to_nothing() {
    let coded = b"0\r\n\r\n";
    let decoded = decode(
        coded,
        Decoding {
            transfer: TransferCoding::Chunked,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect("chunked decode");

    assert!(decoded.bytes.is_empty());
}

#[test]
fn chunked_and_gzip_are_undone_in_order() {
    let coded = common::chunked(&common::gzip(PAYLOAD), &[9, 4]);
    let decoded = decode(
        &coded,
        Decoding {
            transfer: TransferCoding::Chunked,
            content: ContentCoding::Gzip,
            json_string_body: false,
        },
        DecodeLimits::default(),
    )
    .expect("chunked gzip decode");

    assert_eq!(decoded.bytes, PAYLOAD);
    assert_eq!(decoded.decoder, Some(name("chunked+gzip")));
}

#[test]
fn an_escaped_json_string_body_is_unescaped_and_named() {
    let coded = common::escaped_json(PAYLOAD);
    assert_ne!(coded, PAYLOAD, "the fixture must actually be escaped");

    let decoded = decode(
        &coded,
        Decoding {
            json_string_body: true,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect("json string decode");

    assert_eq!(decoded.bytes, PAYLOAD);
    assert_eq!(decoded.decoder, Some(name("json_string")));
}

#[test]
fn a_json_string_body_unescapes_unicode_and_surrogate_pairs() {
    let coded = br#""{\"secret\":\"\u0030\u0031\\u0032\"}\n""#;
    let decoded = decode(
        coded,
        Decoding {
            json_string_body: true,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect("json string decode");

    assert_eq!(decoded.bytes, "{\"secret\":\"01\\u0032\"}\n".as_bytes());
}

#[test]
fn a_json_string_body_decodes_a_surrogate_pair() {
    let coded = br#""\ud83d\ude00""#;
    let decoded = decode(
        coded,
        Decoding {
            json_string_body: true,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect("json string decode");

    assert_eq!(decoded.bytes, "\u{1f600}".as_bytes());
}

#[test]
fn chunked_and_json_string_are_undone_in_order() {
    let coded = common::chunked(&common::escaped_json(PAYLOAD), &[3, 5]);
    let decoded = decode(
        &coded,
        Decoding {
            transfer: TransferCoding::Chunked,
            content: ContentCoding::Identity,
            json_string_body: true,
        },
        DecodeLimits::default(),
    )
    .expect("chunked json decode");

    assert_eq!(decoded.bytes, PAYLOAD);
    assert_eq!(decoded.decoder, Some(name("chunked+json_string")));
}

#[test]
fn every_decoder_name_is_derived_from_a_pipeline() {
    assert_eq!(
        Decoding::default().decoder_name(),
        None,
        "an identity body has no decoder"
    );
    assert_eq!(scourge_verify::decode::DECODER_NAMES.len(), 11);
    for registered in scourge_verify::decode::DECODER_NAMES {
        let derived = [TransferCoding::Identity, TransferCoding::Chunked]
            .into_iter()
            .flat_map(|transfer| {
                [
                    ContentCoding::Identity,
                    ContentCoding::Gzip,
                    ContentCoding::Deflate,
                ]
                .into_iter()
                .flat_map(move |content| {
                    [false, true]
                        .into_iter()
                        .map(move |json_string_body| Decoding {
                            transfer,
                            content,
                            json_string_body,
                        })
                })
            })
            .filter_map(Decoding::decoder_name)
            .any(|candidate| candidate.as_str() == registered);
        assert!(derived, "{registered} is not produced by any pipeline");
        assert_eq!(name(registered).as_str(), registered);
    }
    assert!(
        DecoderName::try_from("brotli".to_owned()).is_err(),
        "an unregistered decoder cannot be named"
    );
}

#[test]
fn a_body_over_the_size_limit_is_over_limit() {
    let body = vec![b'a'; 2048];
    let error =
        decode(&body, Decoding::default(), DecodeLimits::new(1024, 100)).expect_err("over limit");

    assert_eq!(error, DecodeError::OverLimit);
}

#[test]
fn a_coded_body_over_the_size_limit_is_over_limit() {
    let body = common::gzip(&vec![b'a'; 8192]);
    let error = decode(
        &body,
        Decoding {
            content: ContentCoding::Gzip,
            ..Decoding::default()
        },
        DecodeLimits::new(1024, 100_000),
    )
    .expect_err("over limit");

    assert_eq!(error, DecodeError::OverLimit);
}

#[test]
fn a_high_expansion_ratio_is_refused() {
    let body = common::gzip(&vec![0_u8; 65_536]);
    let error = decode(
        &body,
        Decoding {
            content: ContentCoding::Gzip,
            ..Decoding::default()
        },
        DecodeLimits::new(1_000_000, 10),
    )
    .expect_err("ratio limit");

    assert_eq!(error, DecodeError::ExpansionRatio);
}

#[test]
fn a_truncated_gzip_body_is_refused() {
    let coded = common::gzip(PAYLOAD);
    for cut in [coded.len() - 8, coded.len() / 2, 4] {
        let error = decode(
            &coded[..cut],
            Decoding {
                content: ContentCoding::Gzip,
                ..Decoding::default()
            },
            DecodeLimits::default(),
        )
        .expect_err("truncated gzip");
        assert!(
            matches!(error, DecodeError::Truncated | DecodeError::Corrupt),
            "cut at {cut} gave {error:?}"
        );
    }
}

#[test]
fn a_truncated_chunked_body_is_refused() {
    let coded = common::chunked(PAYLOAD, &[5]);
    let without_terminator = &coded[..coded.len() - 5];
    let error = decode(
        without_terminator,
        Decoding {
            transfer: TransferCoding::Chunked,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect_err("truncated chunked");
    assert_eq!(error, DecodeError::Truncated);

    let error = decode(
        &coded[..3],
        Decoding {
            transfer: TransferCoding::Chunked,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect_err("truncated chunk header");
    assert_eq!(error, DecodeError::Truncated);
}

#[test]
fn a_corrupt_gzip_body_is_refused() {
    let mut coded = common::gzip(PAYLOAD);
    coded[0] = 0x00;
    let error = decode(
        &coded,
        Decoding {
            content: ContentCoding::Gzip,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect_err("corrupt gzip");

    assert_eq!(error, DecodeError::Corrupt);
}

#[test]
fn a_corrupt_chunk_size_is_refused() {
    let error = decode(
        b"zz\r\nbody\r\n0\r\n\r\n",
        Decoding {
            transfer: TransferCoding::Chunked,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect_err("corrupt chunk size");

    assert_eq!(error, DecodeError::Corrupt);
}

#[test]
fn a_body_without_one_document_string_is_refused() {
    // The `json_string` decoder undoes exactly one level of escaping around one
    // document string. Structures that are not that shape stay corrupt.
    for body in [
        // Two members: which one is the document is undecidable.
        br#"{"secret":"plain","other":"plain"}"#.as_slice(),
        // A non-string member value carries no escaped document.
        br#"{"secret":42}"#.as_slice(),
        br#"{"secret":null}"#.as_slice(),
        // No document at all.
        b"{}".as_slice(),
        b"[]".as_slice(),
        b"plain".as_slice(),
        // A document string with trailing bytes is not one document.
        br#"{"document":"x"} trailing"#.as_slice(),
        // An unterminated literal.
        br#"{"document":"x}"#.as_slice(),
    ] {
        let error = decode(
            body,
            Decoding {
                json_string_body: true,
                ..Decoding::default()
            },
            DecodeLimits::default(),
        )
        .expect_err("not a single document string");

        assert_eq!(
            error,
            DecodeError::Corrupt,
            "{:?}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn a_one_member_document_wrapper_is_unescaped_to_its_string_value() {
    let coded = br#" { "document" : "{\"note\":\"plain\"}" } "#;
    let decoded = decode(
        coded,
        Decoding {
            json_string_body: true,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect("wrapper decode");

    assert_eq!(decoded.bytes, br#"{"note":"plain"}"#);
    assert_eq!(decoded.decoder, Some(name("json_string")));
}

#[test]
fn the_oracle_matches_canaries_in_decoded_bodies() {
    let mut observations = common::observations();
    let primary_body = common::body_with(&common::primary());
    let owner_read = common::saved_mut(&mut observations, FlowId::F1);
    owner_read.body = common::gzip(&primary_body);
    owner_read.decoding = Decoding {
        content: ContentCoding::Gzip,
        ..Decoding::default()
    };
    owner_read.decoder = Some(name("gzip"));

    let other_read = common::saved_mut(&mut observations, FlowId::F2);
    other_read.body = common::chunked(&primary_body, &[7]);
    other_read.decoding = Decoding {
        transfer: TransferCoding::Chunked,
        ..Decoding::default()
    };
    other_read.decoder = Some(name("chunked"));

    let anonymous_read = common::saved_mut(&mut observations, FlowId::F3);
    anonymous_read.body = common::escaped_json(&primary_body);
    anonymous_read.decoding = Decoding {
        json_string_body: true,
        ..Decoding::default()
    };
    anonymous_read.decoder = Some(name("json_string"));

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(
        evaluation.decoders,
        vec![name("chunked"), name("gzip"), name("json_string")]
    );
}

#[test]
fn an_undecodable_flow_is_evidence_incomplete_not_false() {
    let mut observations = common::observations();
    let other_read = common::saved_mut(&mut observations, FlowId::F2);
    other_read.body = common::gzip(&common::body_with(&common::primary()))[..12].to_vec();
    other_read.decoding = Decoding {
        content: ContentCoding::Gzip,
        ..Decoding::default()
    };
    other_read.decoder = Some(name("gzip"));

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(evaluation.reason_codes.len(), 1);
    assert_eq!(evaluation.reason_codes[0].as_str(), "EVIDENCE_INCOMPLETE");
    assert!(evaluation.evidence.iter().any(|cause| matches!(
        cause,
        IncompleteCause::Decode {
            flow: FlowId::F2,
            error: DecodeError::Truncated | DecodeError::Corrupt,
        }
    )));
}

#[test]
fn an_over_limit_flow_is_evidence_incomplete() {
    let mut observations = common::observations();
    observations.limits = DecodeLimits::new(64, 100);
    common::saved_mut(&mut observations, FlowId::F2).body = vec![b'a'; 4096];

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert!(evaluation.evidence.iter().any(|cause| matches!(
        cause,
        IncompleteCause::Decode {
            flow: FlowId::F2,
            error: DecodeError::OverLimit,
        }
    )));
}

#[test]
fn a_flow_whose_saved_decoder_name_is_missing_is_evidence_incomplete() {
    let mut observations = common::observations();
    let owner_read = common::saved_mut(&mut observations, FlowId::F1);
    owner_read.body = common::gzip(&common::body_with(&common::primary()));
    owner_read.decoding = Decoding {
        content: ContentCoding::Gzip,
        ..Decoding::default()
    };
    owner_read.decoder = None;

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert!(evaluation.evidence.iter().any(|cause| matches!(
        cause,
        IncompleteCause::DecoderNotNamed {
            flow: FlowId::F1,
            recorded: None,
            expected: Some(_),
        }
    )));
}

#[test]
fn a_flow_with_the_wrong_saved_decoder_name_is_evidence_incomplete() {
    let mut observations = common::observations();
    let owner_read = common::saved_mut(&mut observations, FlowId::F1);
    owner_read.body = common::gzip(&common::body_with(&common::primary()));
    owner_read.decoding = Decoding {
        content: ContentCoding::Gzip,
        ..Decoding::default()
    };
    owner_read.decoder = Some(name("deflate"));

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert!(evaluation.evidence.iter().any(|cause| matches!(
        cause,
        IncompleteCause::DecoderNotNamed {
            flow: FlowId::F1,
            recorded: Some(_),
            expected: Some(_),
        }
    )));
}

const GZIP: Decoding = Decoding {
    transfer: TransferCoding::Identity,
    content: ContentCoding::Gzip,
    json_string_body: false,
};

const DEFLATE: Decoding = Decoding {
    transfer: TransferCoding::Identity,
    content: ContentCoding::Deflate,
    json_string_body: false,
};

#[test]
fn every_gzip_member_is_decoded_under_one_shared_bound() {
    // Regression for th-16uz08: a second member must not be dropped.
    let second = common::body_with(&common::primary());
    let coded = common::gzip_members(&[b"{\"label\":\"\"}", second.as_slice()]);

    let decoded = decode(&coded, GZIP, DecodeLimits::default()).expect("multi-member gzip");

    assert_eq!(
        decoded.bytes,
        [b"{\"label\":\"\"}".as_slice(), second.as_slice()].concat()
    );
    assert_eq!(decoded.decoder, Some(name("gzip")));
}

#[test]
fn a_canary_in_the_second_gzip_member_is_found_by_the_oracle() {
    let mut observations = common::observations();
    let primary_body = common::body_with(&common::primary());
    let other_read = common::saved_mut(&mut observations, FlowId::F2);
    other_read.body = common::gzip_members(&[b"{\"label\":\"\"}", primary_body.as_slice()]);
    other_read.decoding = GZIP;
    other_read.decoder = Some(name("gzip"));

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert!(
        evaluation
            .fields_crossed
            .contains(&common::field(common::FIELD))
    );
    assert_eq!(evaluation.decoders, vec![name("gzip")]);
}

#[test]
fn a_corrupt_later_gzip_member_is_refused() {
    let mut coded =
        common::gzip_members(&[b"first", common::body_with(&common::primary()).as_slice()]);
    let last = coded.len() - 1;
    coded[last] ^= 0xff;

    let error = decode(&coded, GZIP, DecodeLimits::default()).expect_err("corrupt second member");

    assert!(
        matches!(error, DecodeError::Corrupt | DecodeError::Truncated),
        "{error:?}"
    );
}

#[test]
fn gzip_bytes_that_are_not_another_member_are_refused() {
    let mut coded = common::gzip(PAYLOAD);
    coded.extend_from_slice(b"not-a-gzip-member");

    let error = decode(&coded, GZIP, DecodeLimits::default()).expect_err("trailing gzip bytes");

    assert!(
        matches!(error, DecodeError::Corrupt | DecodeError::Truncated),
        "{error:?}"
    );
}

#[test]
fn the_gzip_member_bound_is_shared_across_members() {
    let coded = common::gzip_members(&[b"abcde", b"fghij"]);

    // Ten decoded bytes across both members.
    let decoded = decode(&coded, GZIP, DecodeLimits::new(10, 100)).expect("exactly at the bound");
    assert_eq!(decoded.bytes, b"abcdefghij");
    assert_eq!(decoded.decoded_bytes, 10);

    let error = decode(&coded, GZIP, DecodeLimits::new(9, 100)).expect_err("one byte over");
    assert_eq!(error, DecodeError::OverLimit);
}

#[test]
fn a_second_zlib_stream_is_refused() {
    let mut coded = common::zlib(PAYLOAD);
    coded.extend_from_slice(&common::zlib(b"second stream"));

    let error = decode(&coded, DEFLATE, DecodeLimits::default()).expect_err("trailing zlib stream");

    assert_eq!(error, DecodeError::Corrupt);
}

#[test]
fn trailing_bytes_after_a_zlib_stream_are_refused() {
    let mut coded = common::zlib(PAYLOAD);
    coded.extend_from_slice(b"trailing");

    let error = decode(&coded, DEFLATE, DecodeLimits::default()).expect_err("trailing bytes");

    assert_eq!(error, DecodeError::Corrupt);
}

#[test]
fn raw_deflate_trailing_bytes_are_refused() {
    let mut coded = common::raw_deflate(PAYLOAD);
    coded.extend_from_slice(b"trailing");

    let error = decode(&coded, DEFLATE, DecodeLimits::default()).expect_err("trailing bytes");

    assert!(
        matches!(error, DecodeError::Corrupt | DecodeError::Truncated),
        "{error:?}"
    );
}

#[test]
fn a_single_zlib_or_raw_deflate_stream_still_decodes() {
    for coded in [common::zlib(PAYLOAD), common::raw_deflate(PAYLOAD)] {
        let decoded = decode(&coded, DEFLATE, DecodeLimits::default()).expect("single stream");
        assert_eq!(decoded.bytes, PAYLOAD);
        assert_eq!(decoded.decoder, Some(name("deflate")));
    }
}

#[test]
fn the_fixture_escaped_json_wrapper_decodes_to_the_document_with_the_canary() {
    // The referee fixture's `escaped_json` mode returns
    // `{"document":"<serialized note>"}` and its ground truth expects the canary
    // found. Regression for th-3u51lj.
    let ground_truth_canary =
        scourge_verify::Canary::parse("0123456789abcdef0123456789abcdef").expect("canary form");
    let note = serde_json::json!({
        "note": ground_truth_canary.as_str(),
        "detail": "fixture note",
    });
    let document = serde_json::to_vec(&note).expect("serialize note");
    let coded = common::escaped_json_document(&document);
    assert_ne!(coded, document, "the fixture shape really is escaped");

    let decoded = decode(
        &coded,
        Decoding {
            json_string_body: true,
            ..Decoding::default()
        },
        DecodeLimits::default(),
    )
    .expect("fixture-shaped wrapper decode");

    assert_eq!(decoded.bytes, document);
    assert_eq!(decoded.decoder, Some(name("json_string")));
    assert!(
        ground_truth_canary.occurs_in(&decoded.bytes),
        "the ground-truth canary must be found after decoding the wrapper"
    );
}

#[test]
fn the_oracle_finds_the_canary_through_the_fixture_escaped_json_shape() {
    let mut observations = common::observations();
    let primary_body = common::body_with(&common::primary());
    let other_read = common::saved_mut(&mut observations, FlowId::F2);
    other_read.body = common::escaped_json_document(&primary_body);
    other_read.decoding = Decoding {
        json_string_body: true,
        ..Decoding::default()
    };
    other_read.decoder = Some(name("json_string"));

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.decoders, vec![name("json_string")]);
}

#[test]
fn a_record_cannot_request_more_than_the_compiled_decode_ceilings() {
    let huge = DecodeLimits::new(u64::MAX, u64::MAX).clamped();

    assert_eq!(
        huge,
        DecodeLimits::new(
            scourge_verify::decode::MAX_DECODED_BYTES_CEILING,
            scourge_verify::decode::MAX_EXPANSION_RATIO_CEILING
        )
    );
    assert!(
        DecodeLimits::DEFAULT.clamped() == DecodeLimits::DEFAULT,
        "the default is already inside the ceilings"
    );
    // The default must sit inside the compiled ceiling (compile-time check).
    const {
        assert!(
            DecodeLimits::DEFAULT.max_decoded_bytes
                < scourge_verify::decode::MAX_DECODED_BYTES_CEILING
        );
    }

    // A limit exactly at the ceiling is kept; one byte below it is kept too.
    let at_ceiling = DecodeLimits::new(
        scourge_verify::decode::MAX_DECODED_BYTES_CEILING,
        scourge_verify::decode::MAX_EXPANSION_RATIO_CEILING,
    )
    .clamped();
    assert_eq!(at_ceiling, huge);

    let below =
        DecodeLimits::new(scourge_verify::decode::MAX_DECODED_BYTES_CEILING - 1, 1).clamped();
    assert_eq!(
        below,
        DecodeLimits::new(scourge_verify::decode::MAX_DECODED_BYTES_CEILING - 1, 1)
    );
}

#[test]
fn an_unbounded_record_limit_still_stops_at_the_compiled_ceiling() {
    // A gzip bomb whose decoded size is one byte over the compiled ceiling is
    // refused even though the record asked for `u64::MAX` bytes.
    let over = vec![0_u8; (scourge_verify::decode::MAX_DECODED_BYTES_CEILING + 1) as usize];
    let coded = common::gzip(&over);

    let error = decode(&coded, GZIP, DecodeLimits::new(u64::MAX, u64::MAX))
        .expect_err("the compiled ceiling bounds the record limit");

    assert_eq!(error, DecodeError::OverLimit);
}

#[test]
fn an_identity_body_at_the_compiled_ceiling_is_accepted_and_one_byte_over_is_refused() {
    let ceiling = scourge_verify::decode::MAX_DECODED_BYTES_CEILING as usize;
    let at = vec![b'a'; ceiling];
    let decoded = decode(
        &at,
        Decoding::default(),
        DecodeLimits::new(u64::MAX, u64::MAX),
    )
    .expect("exactly at the compiled ceiling");
    assert_eq!(decoded.decoded_bytes, ceiling as u64);

    let mut over = at;
    over.push(b'a');
    let error = decode(
        &over,
        Decoding::default(),
        DecodeLimits::new(u64::MAX, u64::MAX),
    )
    .expect_err("one byte over the compiled ceiling");
    assert_eq!(error, DecodeError::OverLimit);
}
