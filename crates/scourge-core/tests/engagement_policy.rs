use scourge_core::{
    DeclarationIssue,
    canonical::{JsonError, Sha256Digest},
    engagement::{
        EngagementDraft, Label, ManifestRevision, PassPin, PassRef, PassRefusal, PassState,
    },
    policy::{Access, Policy, PolicyContext, PolicyDecision, PolicyRule, RuleSource},
    wire::Exposure,
};
use serde_json::{Value, json};

const FIXTURE: &[u8] = include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");
const ORDERS_RULE: &[u8] =
    include_bytes!("../../../fixtures/target/schema-examples/policy-rule-orders.json");

fn pass_ref() -> PassRef {
    "pass.development-fixture".parse().unwrap()
}

fn pass_digest() -> Sha256Digest {
    Sha256Digest::of(b"fixture pass")
}

fn pin(draft: EngagementDraft) -> ManifestRevision {
    draft
        .accept(PassPin {
            reference: &pass_ref(),
            digest: &pass_digest(),
        })
        .unwrap()
}

fn fixture_manifest() -> ManifestRevision {
    pin(EngagementDraft::parse_toml(FIXTURE).unwrap())
}

fn fixture_document() -> Value {
    let mut manifest: Value = serde_json::from_slice(fixture_manifest().canonical_bytes()).unwrap();
    manifest["declaration"].take()
}

fn parse_json(value: &Value) -> EngagementDraft {
    EngagementDraft::parse_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn parse_rule(value: &Value) -> PolicyRule {
    PolicyRule::parse_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn full_development_fixture_and_engagement_source_rule_load() {
    let draft = EngagementDraft::parse_toml(FIXTURE).unwrap();
    draft.validate().unwrap();
    assert_eq!(draft.principals().len(), 2);
    assert_eq!(draft.properties().len(), 12);

    let manifest = pin(draft);
    assert_eq!(manifest.target_version().as_str(), "version.fixture.v1");
    assert_eq!(manifest.source_digest(), &Sha256Digest::of(FIXTURE));
    assert_eq!(manifest.pass_digest(), &pass_digest());
    assert_eq!(
        manifest.digest(),
        &Sha256Digest::of(manifest.canonical_bytes())
    );

    let same =
        ManifestRevision::from_canonical_bytes(manifest.canonical_bytes(), manifest.digest())
            .unwrap();
    assert_eq!(same, manifest);
    let rule = PolicyRule::parse_json(ORDERS_RULE).unwrap();
    rule.validate_against(&manifest).unwrap();
    assert!(matches!(rule.source(), RuleSource::Engagement { .. }));
    assert_eq!(
        rule.admit(&manifest, |exact_rule, exact_manifest| exact_rule == &rule
            && exact_manifest.digest() == manifest.digest())
            .unwrap()
            .manifest_digest(),
        manifest.digest()
    );
}

#[test]
fn amendments_preserve_previous_bytes_and_bind_their_parent() {
    let original = fixture_manifest();
    let original_bytes = original.canonical_bytes().to_vec();
    let changed_pin = Sha256Digest::of(b"replacement pass");
    let same_source = EngagementDraft::parse_toml(FIXTURE).unwrap();
    let pin = PassPin {
        reference: &pass_ref(),
        digest: &pass_digest(),
    };
    let repeated = original.amend(same_source.clone(), pin).unwrap();
    assert_ne!(repeated.digest(), original.digest());
    assert_eq!(repeated.source_digest(), original.source_digest());
    let changed = original
        .amend(
            same_source,
            PassPin {
                reference: &pass_ref(),
                digest: &changed_pin,
            },
        )
        .unwrap();
    assert_eq!(original.revision(), 1);
    assert_eq!(original.parent_digest(), None);
    assert_eq!(changed.revision(), 2);
    assert_eq!(changed.parent_digest(), Some(original.digest()));
    assert_eq!(changed.pass_digest(), &changed_pin);
    assert_ne!(changed.digest(), repeated.digest());
    assert_eq!(original.canonical_bytes(), original_bytes);
    assert_eq!(fixture_manifest().canonical_bytes(), original_bytes);

    let error =
        ManifestRevision::from_canonical_bytes(changed.canonical_bytes(), original.digest())
            .unwrap_err();
    assert_eq!(
        error.issue(),
        DeclarationIssue::Canonical(JsonError::DigestMismatch)
    );
    let noncanonical = [b" ".as_slice(), &original_bytes].concat();
    let error =
        ManifestRevision::from_canonical_bytes(&noncanonical, &Sha256Digest::of(&noncanonical))
            .unwrap_err();
    assert_eq!(
        error.issue(),
        DeclarationIssue::Canonical(JsonError::NonCanonical)
    );
}

#[test]
fn pass_gate_uses_the_current_adapter_verdict_for_the_pinned_reference() {
    let manifest = fixture_manifest();
    let reference = pass_ref();
    assert_eq!(
        manifest.check_new_run(&reference, PassState::Active(&pass_digest())),
        Ok(())
    );
    for (state, refusal) in [
        (
            PassState::Active(&Sha256Digest::of(b"changed pass")),
            PassRefusal::Changed,
        ),
        (PassState::Changed, PassRefusal::Changed),
        (PassState::Expired, PassRefusal::Expired),
        (PassState::Revoked, PassRefusal::Revoked),
    ] {
        assert_eq!(manifest.check_new_run(&reference, state), Err(refusal));
    }
    let different = "pass.different".parse().unwrap();
    assert_eq!(
        manifest.check_new_run(&different, PassState::Active(&pass_digest())),
        Err(PassRefusal::WrongReference)
    );
    let error = EngagementDraft::parse_toml(FIXTURE)
        .unwrap()
        .accept(PassPin {
            reference: &different,
            digest: &pass_digest(),
        })
        .unwrap_err();
    assert_eq!(error.stanza(), "engagement.pass");
}

#[test]
fn absent_version_remains_a_partial_draft_and_unset_audiences_are_valid() {
    let mut input = fixture_document();
    let orders = input["property"]["orders"].as_object_mut().unwrap();
    orders.remove("readers");
    orders.remove("writers");
    let accepted = pin(parse_json(&input));
    let label = "orders".parse().unwrap();
    let orders = &accepted.properties()[&label];
    assert!(orders.write.is_some());
    assert_eq!(orders.readers, None);
    assert_eq!(orders.writers, None);

    let rule = PolicyRule::parse_json(ORDERS_RULE).unwrap();
    assert_eq!(
        rule.validate_against(&accepted).unwrap_err().stanza(),
        "readers"
    );
    assert_eq!(
        Policy::allows(
            None,
            Exposure::Unauthenticated,
            PolicyContext {
                manifest: &accepted,
                property: &label,
                resource: &orders.resource,
                target_version: accepted.target_version(),
                access: Access::Read,
                owner: &"alice".parse().unwrap(),
                actor: None,
            }
        ),
        PolicyDecision::NoRule
    );

    input["engagement"]
        .as_object_mut()
        .unwrap()
        .remove("target_version");
    let partial = parse_json(&input);
    assert!(partial.settings().target_version.is_none());
    assert_eq!(
        partial.validate().unwrap_err().stanza(),
        "engagement.target_version"
    );
    assert_eq!(
        partial
            .accept(PassPin {
                reference: &pass_ref(),
                digest: &pass_digest()
            })
            .unwrap_err()
            .issue(),
        DeclarationIssue::MissingTargetVersion
    );

    let source = std::str::from_utf8(FIXTURE)
        .unwrap()
        .replace("target_version = \"version.fixture.v1\"\n", "");
    assert!(
        EngagementDraft::parse_toml(source.as_bytes())
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn malformed_engagements_use_safe_stanza_diagnostics() {
    let base = fixture_document();
    for (pointer, value, stanza) in [
        (
            "/schema_version",
            json!("scourge.engagement.v2"),
            "schema_version",
        ),
        (
            "/schema_version",
            json!({"scourge.engagement.v1": null}),
            "schema_version",
        ),
        (
            "/engagement/instrument",
            json!(["teapot", "project.teapot.development"]),
            "engagement.instrument",
        ),
        (
            "/engagement/pass",
            json!("secret marker"),
            "engagement.pass",
        ),
        (
            "/engagement/instrument/project",
            json!("https://secret-marker"),
            "engagement.instrument.project",
        ),
        (
            "/engagement/target_version",
            json!(null),
            "engagement.target_version",
        ),
        (
            "/engagement/allow_effects",
            json!(["none"]),
            "engagement.allow_effects",
        ),
        (
            "/engagement/allow_effects",
            json!(["observe", "observe"]),
            "engagement.allow_effects",
        ),
        (
            "/engagement/objective",
            json!("curl secret-marker"),
            "engagement.objective",
        ),
        (
            "/engagement/max_verify_runs",
            json!(true),
            "engagement.max_verify_runs",
        ),
        (
            "/engagement/max_verify_runs",
            json!(1.0),
            "engagement.max_verify_runs",
        ),
        (
            "/engagement/max_verify_runs",
            json!(0),
            "engagement.max_verify_runs",
        ),
        (
            "/engagement/retest_miss_threshold",
            json!(1),
            "engagement.retest_miss_threshold",
        ),
        ("/principal", json!({}), "principal"),
        (
            "/principal/alice/identity_probe",
            json!(["operation.identity.probe", "selector.identity.subject"]),
            "principal.*.identity_probe",
        ),
        (
            "/principal/bob/session",
            json!("session.alice.verify"),
            "principal.*.session",
        ),
        (
            "/principal/alice/groups",
            json!(["group.tenant-a", "group.tenant-a"]),
            "principal.*.groups",
        ),
        (
            "/principal/alice/identity_probe/subject",
            json!("/id"),
            "principal.*.identity_probe.subject",
        ),
        ("/property", json!({}), "property"),
        (
            "/property/orders/read",
            json!("GET /secret-marker"),
            "property.*.read",
        ),
        (
            "/property/orders/plant/id_from",
            json!("/secret-marker"),
            "property.*.plant.id_from",
        ),
        (
            "/property/orders/plant/fields",
            json!([]),
            "property.*.plant.fields",
        ),
        (
            "/property/orders/write/fields",
            json!(["selector.one", "selector.one"]),
            "property.*.write.fields",
        ),
        (
            "/property/orders/readers",
            json!(null),
            "property.*.readers",
        ),
        (
            "/property/orders/readers",
            json!({"owner": null}),
            "property.*.readers",
        ),
        (
            "/property/orders/policy",
            json!("Policy token=secret-marker"),
            "property.*.policy",
        ),
    ] {
        let mut input = base.clone();
        *input.pointer_mut(pointer).unwrap() = value;
        let error = EngagementDraft::parse_json(&serde_json::to_vec(&input).unwrap()).unwrap_err();
        assert_eq!(error.stanza(), stanza, "{pointer}");
        assert!(!format!("{error:?} {error}").contains("secret-marker"));
    }

    let mut input = base;
    input["property"]["orders"]
        .as_object_mut()
        .unwrap()
        .remove("write");
    let error = EngagementDraft::parse_json(&serde_json::to_vec(&input).unwrap()).unwrap_err();
    assert_eq!(error.issue(), DeclarationIssue::WriteRequired);

    input["principal"]["secret_marker"] = json!({"secret-marker": "credential"});
    let error = EngagementDraft::parse_json(&serde_json::to_vec(&input).unwrap()).unwrap_err();
    assert!(error.stanza().starts_with("principal.*"));
    assert!(!format!("{error:?} {error}").contains("secret"));

    let duplicate = br#"{"\u0061":{"x":1,"x":2},"a":2}"#;
    assert_eq!(
        EngagementDraft::parse_json(duplicate).unwrap_err().issue(),
        DeclarationIssue::DuplicateKey
    );
    let duplicate = [
        b"schema_version = \"scourge.engagement.v1\"\n".as_slice(),
        FIXTURE,
    ]
    .concat();
    assert!(EngagementDraft::parse_toml(&duplicate).is_err());
    let toml_request = std::str::from_utf8(FIXTURE).unwrap().replace(
        "read = \"operation.orders.read\"",
        "read = \"GET /secret-marker\"",
    );
    assert_eq!(
        EngagementDraft::parse_toml(toml_request.as_bytes())
            .unwrap_err()
            .stanza(),
        "property.*.read"
    );
    let toml_array = std::str::from_utf8(FIXTURE).unwrap().replace(
        "instrument = { kind = \"teapot\", project = \"project.teapot.development\" }",
        "instrument = [\"teapot\", \"project.teapot.development\"]",
    );
    assert_eq!(
        EngagementDraft::parse_toml(toml_array.as_bytes())
            .unwrap_err()
            .stanza(),
        "engagement.instrument"
    );
}

#[test]
fn integer_fields_enforce_the_canonical_boundary_during_parsing() {
    const MAX_SAFE: u64 = (1 << 53) - 1;
    let source = std::str::from_utf8(FIXTURE).unwrap();
    let mut json_fixture = fixture_document();
    for (value, accepted) in [(MAX_SAFE, true), (MAX_SAFE + 1, false)] {
        let toml = source.replace(
            "max_verify_runs = 50",
            &format!("max_verify_runs = {value}"),
        );
        json_fixture["engagement"]["max_verify_runs"] = json!(value);
        let json = serde_json::to_vec(&json_fixture).unwrap();
        for result in [
            EngagementDraft::parse_toml(toml.as_bytes()),
            EngagementDraft::parse_json(&json),
        ] {
            if accepted {
                let manifest = pin(result.unwrap());
                assert_eq!(manifest.settings().max_verify_runs, Some(MAX_SAFE));
                ManifestRevision::from_canonical_bytes(
                    manifest.canonical_bytes(),
                    manifest.digest(),
                )
                .unwrap();
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.issue(), DeclarationIssue::UnsafeNumber);
                assert_eq!(error.stanza(), "engagement.max_verify_runs");
            }
        }
    }

    let mut rule = rule_for("owner");
    let citation = json!({
        "artifact_id": "artifact.fixture.document",
        "sha256": pass_digest().as_str(),
        "selector": {"type": "byte_range", "start": MAX_SAFE - 1, "end": MAX_SAFE}
    });
    let admission = rule["source"]["admission"].take();
    rule["source"] = json!({"kind": "document", "citation": citation, "admission": admission});
    parse_rule(&rule)
        .validate_against(&fixture_manifest())
        .unwrap();
    for (field, value) in [
        ("start", json!(MAX_SAFE + 1)),
        ("end", json!(MAX_SAFE + 1)),
        ("end", json!(-i64::try_from(MAX_SAFE + 1).unwrap())),
    ] {
        let mut invalid = rule.clone();
        invalid["source"]["citation"]["selector"][field] = value;
        let error = PolicyRule::parse_json(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
        assert_eq!(error.issue(), DeclarationIssue::UnsafeNumber);
        assert_eq!(error.stanza(), format!("source.citation.selector.{field}"));
    }
}

#[test]
fn nested_duplicate_paths_keep_the_stanza_and_redact_labels_and_values() {
    let json_principal = br#"{"principal":{"marked_private_label":{
        "session":"seeded_secret_value","sess\u0069on":"second_secret_value"
    }}}"#;
    let toml_property = br#"
        [property."marked_private_label"]
        read = "seeded_secret_value"
        "\u0072ead" = "second_secret_value"
    "#;
    let toml_inline = br#"
        [property.'marked_private_label']
        plant = { operation = "seeded_secret_value", "operation" = "second_secret_value" }
    "#;
    let toml_dotted = br#"
        principal."marked_private_label".session = "seeded_secret_value"
        principal.marked_private_label."session" = "second_secret_value"
    "#;
    let toml_header = br#"
        [principal.marked_private_label]
        session = "seeded_secret_value"
        [principal."marked_private_label"]
        session = "second_secret_value"
    "#;
    let json_policy = br#"{"source":{"admission":{
        "identity":"seeded_secret_value","identity":"second_secret_value"
    }}}"#;
    let json_unknown = br#"{"property":{"marked_private_label":{
        "arbitrary_secret_key":"seeded_secret_value","arbitrary_secret_key":"second_secret_value"
    }}}"#;
    for (error, stanza) in [
        (
            EngagementDraft::parse_json(json_principal).unwrap_err(),
            "principal.*.session",
        ),
        (
            EngagementDraft::parse_toml(toml_property).unwrap_err(),
            "property.*.read",
        ),
        (
            EngagementDraft::parse_toml(toml_inline).unwrap_err(),
            "property.*.plant.operation",
        ),
        (
            EngagementDraft::parse_toml(toml_dotted).unwrap_err(),
            "principal.*.session",
        ),
        (
            EngagementDraft::parse_toml(toml_header).unwrap_err(),
            "principal.*",
        ),
        (
            PolicyRule::parse_json(json_policy).unwrap_err(),
            "source.admission.identity",
        ),
        (
            EngagementDraft::parse_json(json_unknown).unwrap_err(),
            "property.*.*",
        ),
    ] {
        assert_eq!(error.issue(), DeclarationIssue::DuplicateKey);
        assert_eq!(error.stanza(), stanza);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("marked_private_label"));
        assert!(!diagnostic.contains("secret"));
    }
}

fn rule_for(audience: &str) -> Value {
    let mut rule: Value = serde_json::from_slice(ORDERS_RULE).unwrap();
    rule["readers"] = json!(audience);
    rule["writers"] = json!(audience);
    let admission = rule["source"]["admission"].take();
    let statement = rule["source"]["revision"].take();
    rule["source"] = json!({"kind": "operator", "admission": admission, "statement": statement});
    rule
}

#[test]
fn policy_matrix_uses_admitted_read_and_write_rules_for_both_exposures() {
    use PolicyDecision::{Allowed, Denied, NoRule};

    let owner = "alice".parse().unwrap();
    let actor = "bob".parse().unwrap();
    let property = "orders".parse().unwrap();
    let mut input = fixture_document();
    for (audience, same_group, different_group, anonymous) in [
        ("owner", Denied, Denied, Denied),
        ("group", Allowed, Denied, Denied),
        ("authenticated", Allowed, Allowed, Denied),
        ("public", Allowed, Allowed, Allowed),
    ] {
        input["property"]["orders"]["readers"] = json!(audience);
        input["property"]["orders"]["writers"] = json!(audience);
        for (group, expected) in [
            ("group.tenant-a", same_group),
            ("group.tenant-b", different_group),
        ] {
            input["principal"]["bob"]["groups"] = json!([group]);
            let manifest = pin(parse_json(&input));
            let rule = parse_rule(&rule_for(audience));
            let admitted = rule.admit(&manifest, |_, _| true).unwrap();
            for access in [Access::Read, Access::Write] {
                let context = |actor| PolicyContext {
                    manifest: &manifest,
                    property: &property,
                    resource: &manifest.properties()[&property].resource,
                    target_version: manifest.target_version(),
                    access,
                    owner: &owner,
                    actor,
                };
                assert_eq!(
                    Policy::allows(None, Exposure::CrossPrincipal, context(Some(&actor))),
                    NoRule
                );
                assert_eq!(
                    Policy::allows(
                        Some(&admitted),
                        Exposure::CrossPrincipal,
                        context(Some(&actor))
                    ),
                    expected,
                    "{audience} {access:?} {group}",
                );
                assert_eq!(
                    Policy::allows(Some(&admitted), Exposure::Unauthenticated, context(None)),
                    anonymous,
                    "{audience} {access:?}",
                );
                assert_eq!(
                    Policy::allows(
                        Some(&admitted),
                        Exposure::CrossPrincipal,
                        context(Some(&owner))
                    ),
                    NoRule,
                );
            }
        }
    }
}

#[test]
fn policy_cannot_cover_another_access_resource_version_or_revision() {
    let manifest = fixture_manifest();
    let next = manifest
        .amend(
            EngagementDraft::parse_toml(FIXTURE).unwrap(),
            PassPin {
                reference: &pass_ref(),
                digest: &pass_digest(),
            },
        )
        .unwrap();
    let mut input = rule_for("owner");
    input.as_object_mut().unwrap().remove("writers");
    let rule = parse_rule(&input);
    let admitted = rule.admit(&manifest, |_, _| true).unwrap();
    let property = "orders".parse().unwrap();
    let owner = "alice".parse::<Label>().unwrap();
    let unrelated_resource = "resource.invoices".parse().unwrap();
    let unrelated_version = "version.fixture.v2".parse().unwrap();
    let unrelated_property = "invoices".parse().unwrap();
    let context = || PolicyContext {
        manifest: &manifest,
        property: &property,
        resource: &manifest.properties()[&property].resource,
        target_version: manifest.target_version(),
        access: Access::Read,
        owner: &owner,
        actor: None,
    };
    assert_eq!(
        Policy::allows(Some(&admitted), Exposure::Unauthenticated, context()),
        PolicyDecision::Denied
    );
    for observation in [
        PolicyContext {
            access: Access::Write,
            ..context()
        },
        PolicyContext {
            resource: &unrelated_resource,
            ..context()
        },
        PolicyContext {
            property: &unrelated_property,
            ..context()
        },
        PolicyContext {
            target_version: &unrelated_version,
            ..context()
        },
        PolicyContext {
            manifest: &next,
            ..context()
        },
    ] {
        assert_eq!(
            Policy::allows(Some(&admitted), Exposure::Unauthenticated, observation),
            PolicyDecision::NoRule
        );
    }
}

#[test]
fn policy_sources_are_shape_checked_and_only_operator_admittable_in_scope() {
    let manifest = fixture_manifest();
    let mut input = rule_for("owner");
    let admission = input["source"]["admission"].clone();
    let artifact = input["source"]["statement"].clone();
    let mut citation = artifact.clone();
    citation["selector"] = json!({"type": "byte_range", "start": 0, "end": 1});
    input["source"] = json!({"kind": "document", "citation": citation, "admission": admission});
    assert!(parse_rule(&input).admit(&manifest, |_, _| true).is_ok());
    assert_eq!(
        parse_rule(&input)
            .admit(&manifest, |_, _| false)
            .unwrap_err()
            .issue(),
        DeclarationIssue::Unapproved
    );
    input["source"] = json!({"kind": "inferred", "citation": citation});
    input.as_object_mut().unwrap().remove("target_version");
    let inferred = parse_rule(&input);
    assert!(inferred.validate_against(&manifest).is_ok());
    assert_eq!(
        inferred
            .admit(&manifest, |_, _| panic!(
                "inferred rules cannot reach approval"
            ))
            .unwrap_err()
            .issue(),
        DeclarationIssue::Unadmitted
    );

    input["source"]["citation"]["selector"]["end"] = json!(0);
    let error = PolicyRule::parse_json(&serde_json::to_vec(&input).unwrap()).unwrap_err();
    assert_eq!(error.issue(), DeclarationIssue::InvalidRange);

    let base: Value = serde_json::from_slice(ORDERS_RULE).unwrap();
    for (pointer, value) in [
        ("/schema_version", json!({"scourge.policy-rule.v1": null})),
        ("/policy", json!("https://secret-marker")),
        ("/readers", json!(null)),
        (
            "/source/revision",
            json!([
                "artifact.engagement.fixture",
                manifest.source_digest().as_str()
            ]),
        ),
        (
            "/source/admission/recorded_at",
            json!("2026-11-23T00:00:00.1Z"),
        ),
        (
            "/source/admission/recorded_at",
            json!("2026-02-31T00:00:00Z"),
        ),
        ("/source/revision/sha256", json!("secret-marker")),
        ("/source/revision/artifact_id", json!("secret-marker")),
        ("/source/kind", json!("inferred")),
    ] {
        let mut invalid = base.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        let error = PolicyRule::parse_json(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
        assert!(
            !format!("{error:?} {error}").contains("secret-marker"),
            "{pointer}"
        );
    }

    for (pointer, value, stanza) in [
        (
            "/target_version",
            json!("version.fixture.v2"),
            "target_version",
        ),
        ("/property", json!("unknown"), "property"),
        ("/readers", json!("group"), "readers"),
        (
            "/source/revision/sha256",
            json!(pass_digest().as_str()),
            "source.revision.sha256",
        ),
        (
            "/source/admission/identity",
            json!("authenticated"),
            "source.admission.identity",
        ),
    ] {
        let mut wrong_scope = base.clone();
        *wrong_scope.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            parse_rule(&wrong_scope)
                .admit(&manifest, |_, _| panic!(
                    "out-of-scope rules cannot reach approval"
                ))
                .unwrap_err()
                .stanza(),
            stanza
        );
    }

    let mut incomplete = base;
    incomplete.as_object_mut().unwrap().remove("target_version");
    let error = PolicyRule::parse_json(&serde_json::to_vec(&incomplete).unwrap()).unwrap_err();
    assert_eq!(error.stanza(), "target_version");
}
