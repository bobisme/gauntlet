use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use rustix::fs::{self as rfs, Dir, FileType, Mode, OFlags, RenameFlags};
use scourge_core::{
    canonical::Sha256Digest,
    engagement::{EngagementDraft, ManifestRevision, PassPin},
    rounds::TargetOrigin,
    workspace::ManifestArtifactPin,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::instrument::{AUTHENTICATED_SESSIONS, IdentityFlow, PREPARED_SESSIONS, PassCounter};

const SCHEMA: &str = "scourge.skeleton-preparation.v1";
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const TEAPOT_SHA256: &str = "6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458";
const INVESTIGATION_SHA256: &str =
    "c368ab4d8e0511524674692b039c4f248cee2b5676d143a23f5ab9025a31d4fc";
const PREPARED_ARTIFACTS: [&str; 17] = [
    "transaction.json",
    "reset.json",
    "target.json",
    "engagement.toml",
    "pass.toml",
    "manifest-r1.json",
    "manifest-history.json",
    "identity-alice.json",
    "identity-bob.json",
    "identity-alice_same.json",
    "identity-alice_verify.json",
    "identity-bob_verify.json",
    "identity-alice_verify_same.json",
    "identity-scourge_anonymous.json",
    "session-access.json",
    "accounting.json",
    "preparation.json",
];

pub(super) struct ProtectedRoot {
    directory: File,
    identity: RootIdentity,
    workspace: PathBuf,
    workspace_identity: RefCell<Option<RootIdentity>>,
    managed_guide: bool,
    transaction: RefCell<TransactionState>,
    artifacts: RefCell<BTreeMap<String, ProtectedArtifact>>,
}

pub(super) struct PreparedMaterials<'a> {
    pub(super) token: Uuid,
    pub(super) origin: &'a TargetOrigin,
    pub(super) teapot: &'a [u8],
    pub(super) investigation: &'a [u8],
    pub(super) declaration: &'a [u8],
    pub(super) pass: &'a [u8],
    pub(super) manifest: &'a ManifestRevision,
    pub(super) artifact: &'a ManifestArtifactPin,
    pub(super) cookies: &'a [String; 6],
    pub(super) identities: Vec<IdentityFlow>,
    pub(super) counter_before: PassCounter,
    pub(super) counter_after: PassCounter,
}

struct ProtectedArtifact {
    file: File,
    identity: FileIdentity,
    digest: Sha256Digest,
    size_bytes: usize,
}

#[derive(Clone)]
enum TransactionState {
    Fresh {
        token: Uuid,
    },
    Pending {
        preparation_id: Sha256Digest,
        token: Option<Uuid>,
    },
    PreSettlement {
        preparation_id: Sha256Digest,
    },
    Settled {
        preparation_id: Sha256Digest,
    },
    Invalid,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct RootIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct FileRef {
    path: String,
    sha256: Sha256Digest,
    size_bytes: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionReceipt {
    schema: String,
    transaction_state: String,
    preparation_id: Sha256Digest,
    workspace: String,
    workspace_root: RootIdentity,
    managed_guide: bool,
    protected_root: RootIdentity,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResetReceipt {
    schema: String,
    preparation_id: Sha256Digest,
    reset_id: Sha256Digest,
    method: String,
    fixture_state: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetReceipt {
    schema: String,
    origin: String,
    address: String,
    tls_identity: Option<String>,
    deployment: String,
    evidence_strength: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionReceipt {
    name: String,
    identity_probe: String,
    flow_id: u64,
    original: FileRef,
    status: u64,
    cookie_sha256: Option<Sha256Digest>,
    subject_sha256: Option<Sha256Digest>,
    response_sha256: Sha256Digest,
}

#[derive(Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseSessions {
    owner: String,
    other: String,
    verifier_owner: String,
    verifier_other: String,
    anonymous: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionAccess {
    schema: String,
    identity_probe: String,
    sessions: Vec<SessionReceipt>,
    cases: BTreeMap<String, CaseSessions>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccountingReceipt {
    schema: String,
    scope: String,
    fresh_private_project: bool,
    exclusive_engine: bool,
    pass_sha256: Sha256Digest,
    native_pass_digest: Sha256Digest,
    before: PassCounter,
    after: PassCounter,
    observed_spend: u64,
    completeness_claim: String,
    attribution: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PreparationReceipt {
    schema: String,
    preparation_id: Sha256Digest,
    reset_id: Sha256Digest,
    pins: BTreeMap<String, Sha256Digest>,
    manifest_revision: u64,
    manifest_sha256: Sha256Digest,
    manifest_artifact_sha256: Sha256Digest,
    files: BTreeMap<String, FileRef>,
}

#[derive(Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct VisibleFile {
    sha256: Sha256Digest,
    size_bytes: usize,
    mode: u32,
}

#[derive(Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceReceipt {
    schema: String,
    mode: String,
    managed_guide: bool,
    files: BTreeMap<String, VisibleFile>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SettlementReceipt {
    schema: String,
    transaction_state: String,
    preparation_id: Sha256Digest,
    settled: bool,
    managed_guide: bool,
    protected_files: BTreeMap<String, Sha256Digest>,
}

impl ProtectedRoot {
    pub(super) fn open(
        path: &Path,
        workspace: &Path,
        state: &Path,
        managed_guide: bool,
    ) -> io::Result<Self> {
        if !path.is_absolute() || path.starts_with(workspace) || workspace.starts_with(path) {
            return Err(invalid());
        }
        let directory = File::from(rfs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = directory.metadata()?;
        private_directory(&metadata)?;
        let canonical = fs::canonicalize(path)?;
        let named = fs::symlink_metadata(path)?;
        if canonical != path
            || canonical.starts_with(state)
            || state.starts_with(&canonical)
            || named.dev() != metadata.dev()
            || named.ino() != metadata.ino()
        {
            return Err(invalid());
        }
        let identity = RootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let mut root = Self {
            directory,
            identity,
            workspace: workspace.to_owned(),
            workspace_identity: RefCell::new(None),
            managed_guide,
            transaction: RefCell::new(TransactionState::Fresh {
                token: Uuid::new_v4(),
            }),
            artifacts: RefCell::new(BTreeMap::new()),
        };
        root.load_existing()?;
        Ok(root)
    }

    pub(super) fn is_fresh(&self) -> bool {
        matches!(*self.transaction.borrow(), TransactionState::Fresh { .. })
    }

    pub(super) fn can_settle(&self) -> bool {
        self.validate_current_state().is_ok()
    }

    pub(super) fn begin(&self) -> io::Result<()> {
        let token = match &*self.transaction.borrow() {
            TransactionState::Fresh { token } => *token,
            _ => return Err(invalid()),
        };
        let preparation_id = domain_id(b"cold-trial-preparation-v1", token);
        let workspace_root = directory_identity(&self.workspace)?;
        *self.workspace_identity.borrow_mut() = Some(workspace_root);
        self.write_json(
            "transaction.json",
            &TransactionReceipt {
                schema: SCHEMA.into(),
                transaction_state: "pending".into(),
                preparation_id: preparation_id.clone(),
                workspace: self.workspace.to_str().ok_or_else(invalid)?.into(),
                workspace_root,
                managed_guide: self.managed_guide,
                protected_root: self.identity,
            },
        )?;
        *self.transaction.borrow_mut() = TransactionState::Pending {
            preparation_id,
            token: Some(token),
        };
        Ok(())
    }

    pub(super) fn token(&self) -> io::Result<Uuid> {
        let state = self.transaction.borrow().clone();
        match state {
            TransactionState::Pending {
                token: Some(token), ..
            } => Ok(token),
            _ => Err(invalid()),
        }
    }

    pub(super) fn write_prepared(&self, materials: PreparedMaterials<'_>) -> io::Result<()> {
        let PreparedMaterials {
            token,
            origin,
            teapot,
            investigation,
            declaration,
            pass,
            manifest,
            artifact,
            cookies,
            identities,
            counter_before,
            counter_after,
        } = materials;
        let preparation_id = domain_id(b"cold-trial-preparation-v1", token);
        if self.preparation_id()? != preparation_id
            || !matches!(
                *self.transaction.borrow(),
                TransactionState::Pending { token: Some(_), .. }
            )
        {
            return Err(invalid());
        }
        let reset_id = domain_id(b"fresh-fixture-reset-v1", token);
        let reset = self.write_json(
            "reset.json",
            &ResetReceipt {
                schema: SCHEMA.into(),
                preparation_id: preparation_id.clone(),
                reset_id: reset_id.clone(),
                method: "fresh-process".into(),
                fixture_state: "seeded".into(),
            },
        )?;
        let target = self.write_json(
            "target.json",
            &TargetReceipt {
                schema: SCHEMA.into(),
                origin: origin.as_str().into(),
                address: origin.as_str().trim_start_matches("http://").to_owned(),
                tls_identity: None,
                deployment: "scourge-development-fixture".into(),
                evidence_strength: "native-owned-process".into(),
            },
        )?;
        let source = self.write_bytes("engagement.toml", declaration)?;
        let pass_ref = self.write_bytes("pass.toml", pass)?;
        let manifest_ref = self.write_bytes("manifest-r1.json", manifest.canonical_bytes())?;
        let history = self.write_bytes("manifest-history.json", b"[]\n")?;

        let cookie_digests: BTreeMap<_, _> = AUTHENTICATED_SESSIONS
            .into_iter()
            .zip(cookies)
            .map(|(name, cookie)| (name, Sha256Digest::of(cookie.as_bytes())))
            .collect();
        let mut sessions = identities
            .into_iter()
            .map(|identity| {
                let original = self.write_bytes(
                    &format!("identity-{}.json", identity.session),
                    &identity.response_body,
                )?;
                Ok(SessionReceipt {
                    name: identity.session.into(),
                    identity_probe: "GET /app/api/me".into(),
                    flow_id: identity.flow,
                    original,
                    status: identity.status,
                    cookie_sha256: cookie_digests.get(identity.session).cloned(),
                    subject_sha256: identity
                        .subject
                        .as_deref()
                        .map(|subject| Sha256Digest::of(subject.as_bytes())),
                    response_sha256: Sha256Digest::of(&identity.response_body),
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        sessions.sort_by(|left, right| left.name.cmp(&right.name));
        let by_name: BTreeMap<_, _> = sessions
            .iter()
            .map(|session| (session.name.as_str(), session))
            .collect();
        let alice = by_name.get("alice").ok_or_else(invalid)?;
        let alice_same = by_name.get("alice_same").ok_or_else(invalid)?;
        let alice_verify = by_name.get("alice_verify").ok_or_else(invalid)?;
        let alice_verify_same = by_name.get("alice_verify_same").ok_or_else(invalid)?;
        if alice.cookie_sha256 == alice_same.cookie_sha256
            || alice.subject_sha256 != alice_same.subject_sha256
            || alice_verify.cookie_sha256 == alice_verify_same.cookie_sha256
            || alice_verify.subject_sha256 != alice_verify_same.subject_sha256
        {
            return Err(invalid());
        }
        let cases = BTreeMap::from([
            ("positive".into(), ordinary_case()),
            ("public".into(), ordinary_case()),
            ("login".into(), ordinary_case()),
            (
                "same_subject".into(),
                CaseSessions {
                    owner: "alice".into(),
                    other: "alice_same".into(),
                    verifier_owner: "alice_verify".into(),
                    verifier_other: "alice_verify_same".into(),
                    anonymous: "scourge_anonymous".into(),
                },
            ),
        ]);
        let access = self.write_json(
            "session-access.json",
            &SessionAccess {
                schema: SCHEMA.into(),
                identity_probe: "GET /app/api/me".into(),
                sessions,
                cases,
            },
        )?;
        if counter_before.spent != 0
            || counter_before.native_pass_digest != counter_after.native_pass_digest
            || counter_before.total != counter_after.total
            || counter_after.spent < counter_before.spent
            || counter_before.left + counter_before.spent != counter_before.total
            || counter_after.left + counter_after.spent != counter_after.total
            || counter_before.unused != 0
            || counter_after.unused != 0
        {
            return Err(invalid());
        }
        let accounting = self.write_json(
            "accounting.json",
            &AccountingReceipt {
                schema: SCHEMA.into(),
                scope: "fresh-private-teapot-project-and-unique-pass".into(),
                fresh_private_project: true,
                exclusive_engine: true,
                pass_sha256: Sha256Digest::of(pass),
                native_pass_digest: counter_before.native_pass_digest.clone(),
                observed_spend: counter_after.spent - counter_before.spent,
                before: counter_before,
                after: counter_after,
                completeness_claim: "fixture-specific-lower-bound".into(),
                attribution: "unestablished".into(),
            },
        )?;
        let pins = BTreeMap::from([
            ("teapot_sha256".into(), Sha256Digest::of(teapot)),
            (
                "investigation_sha256".into(),
                Sha256Digest::of(investigation),
            ),
        ]);
        let files = BTreeMap::from([
            ("reset".into(), reset),
            ("target".into(), target),
            ("engagement_source".into(), source),
            ("pass".into(), pass_ref),
            ("manifest".into(), manifest_ref),
            ("manifest_history".into(), history),
            ("session_access".into(), access),
            ("accounting".into(), accounting),
        ]);
        self.write_json(
            "preparation.json",
            &PreparationReceipt {
                schema: SCHEMA.into(),
                preparation_id,
                reset_id,
                pins,
                manifest_revision: manifest.revision(),
                manifest_sha256: manifest.digest().clone(),
                manifest_artifact_sha256: artifact.reference.digest.clone(),
                files,
            },
        )?;
        Ok(())
    }

    pub(super) fn settle(&self, workspace: &Path, managed_guide: bool) -> io::Result<()> {
        self.settle_with(workspace, managed_guide, &mut |_| Ok(()))
    }

    fn settle_with(
        &self,
        workspace: &Path,
        managed_guide: bool,
        hook: &mut impl FnMut(&str) -> io::Result<()>,
    ) -> io::Result<()> {
        if workspace != self.workspace || managed_guide != self.managed_guide {
            return Err(invalid());
        }
        self.validate_current_state()?;
        self.validate_workspace_identity()?;
        let files = visible_files(workspace)?;
        self.validate_workspace_identity()?;
        if files.contains_key("AGENTS.md") != managed_guide {
            return Err(invalid());
        }
        let workspace_value = WorkspaceReceipt {
            schema: SCHEMA.into(),
            mode: if managed_guide {
                "managed".into()
            } else {
                "executable".into()
            },
            managed_guide,
            files,
        };
        let state = self.transaction.borrow().clone();
        match state {
            TransactionState::Settled { .. } => {
                self.validate_workspace(&workspace_value)?;
                return self
                    .validate_current_state()
                    .and_then(|()| self.directory.sync_all());
            }
            TransactionState::PreSettlement { .. } => {
                self.validate_workspace(&workspace_value)?;
            }
            TransactionState::Pending { preparation_id, .. } => {
                self.write_json("workspace.json", &workspace_value)?;
                *self.transaction.borrow_mut() = TransactionState::PreSettlement { preparation_id };
                hook("workspace_durable")?;
            }
            TransactionState::Fresh { .. } | TransactionState::Invalid => return Err(invalid()),
        }
        self.validate_current_state()?;
        let protected_files = self
            .artifacts
            .borrow()
            .iter()
            .map(|(name, artifact)| (name.clone(), artifact.digest.clone()))
            .collect();
        let preparation_id = self.preparation_id()?;
        self.write_json(
            "settlement.json",
            &SettlementReceipt {
                schema: SCHEMA.into(),
                transaction_state: "settled".into(),
                preparation_id: preparation_id.clone(),
                settled: true,
                managed_guide,
                protected_files,
            },
        )?;
        *self.transaction.borrow_mut() = TransactionState::Settled { preparation_id };
        self.validate_current_state()?;
        self.directory.sync_all()
    }

    fn load_existing(&mut self) -> io::Result<()> {
        let names = self.names()?;
        if names.is_empty() {
            return Ok(());
        }
        let mut artifacts = BTreeMap::new();
        for name in names {
            let artifact = self.open_artifact(&name)?;
            artifacts.insert(name, artifact);
        }
        *self.artifacts.borrow_mut() = artifacts;
        let state = self
            .classify_existing()
            .unwrap_or(TransactionState::Invalid);
        *self.transaction.borrow_mut() = state;
        if self.validate_current_state().is_err() {
            *self.transaction.borrow_mut() = TransactionState::Invalid;
        }
        Ok(())
    }

    fn preparation_id(&self) -> io::Result<Sha256Digest> {
        match &*self.transaction.borrow() {
            TransactionState::Pending { preparation_id, .. }
            | TransactionState::PreSettlement { preparation_id }
            | TransactionState::Settled { preparation_id } => Ok(preparation_id.clone()),
            TransactionState::Fresh { .. } | TransactionState::Invalid => Err(invalid()),
        }
    }

    fn classify_existing(&self) -> io::Result<TransactionState> {
        let transaction: TransactionReceipt = self.decode("transaction.json")?;
        *self.workspace_identity.borrow_mut() = Some(transaction.workspace_root);
        self.validate_transaction(&transaction)?;
        let names: BTreeSet<_> = self.artifacts.borrow().keys().cloned().collect();
        let prepared = prepared_names();
        if names == prepared {
            return Ok(TransactionState::Pending {
                preparation_id: transaction.preparation_id,
                token: None,
            });
        }
        let mut pre_settlement = prepared;
        pre_settlement.insert("workspace.json".into());
        if names == pre_settlement {
            return Ok(TransactionState::PreSettlement {
                preparation_id: transaction.preparation_id,
            });
        }
        let mut settled = pre_settlement;
        settled.insert("settlement.json".into());
        if names == settled {
            return Ok(TransactionState::Settled {
                preparation_id: transaction.preparation_id,
            });
        }
        Err(invalid())
    }

    fn validate_current_state(&self) -> io::Result<()> {
        self.verify_artifacts()?;
        self.validate_workspace_identity()?;
        let names: BTreeSet<_> = self.artifacts.borrow().keys().cloned().collect();
        let mut expected = prepared_names();
        match &*self.transaction.borrow() {
            TransactionState::Pending { .. } => {
                if names != expected {
                    return Err(invalid());
                }
                self.validate_prepared_graph()
            }
            TransactionState::PreSettlement { .. } => {
                expected.insert("workspace.json".into());
                if names != expected {
                    return Err(invalid());
                }
                self.validate_prepared_graph()?;
                self.validate_saved_workspace()
            }
            TransactionState::Settled { .. } => {
                expected.extend(["workspace.json".into(), "settlement.json".into()]);
                if names != expected {
                    return Err(invalid());
                }
                self.validate_prepared_graph()?;
                self.validate_saved_workspace()?;
                self.validate_settlement()
            }
            TransactionState::Fresh { .. } | TransactionState::Invalid => Err(invalid()),
        }
    }

    fn validate_prepared_graph(&self) -> io::Result<()> {
        let transaction: TransactionReceipt = self.decode("transaction.json")?;
        self.validate_transaction(&transaction)?;
        if transaction.preparation_id != self.preparation_id()? {
            return Err(invalid());
        }

        let reset: ResetReceipt = self.decode("reset.json")?;
        if reset.schema != SCHEMA
            || reset.preparation_id != transaction.preparation_id
            || reset.method != "fresh-process"
            || reset.fixture_state != "seeded"
        {
            return Err(invalid());
        }
        let target: TargetReceipt = self.decode("target.json")?;
        let origin = TargetOrigin::parse(&target.origin).map_err(|_| invalid())?;
        let address: std::net::SocketAddr = target.address.parse().map_err(|_| invalid())?;
        if target.schema != SCHEMA
            || target.origin != format!("http://{}", target.address)
            || origin.as_str() != target.origin
            || !address.ip().is_loopback()
            || target.tls_identity.is_some()
            || target.deployment != "scourge-development-fixture"
            || target.evidence_strength != "native-owned-process"
        {
            return Err(invalid());
        }

        let access: SessionAccess = self.decode("session-access.json")?;
        self.validate_sessions(&access)?;
        let accounting: AccountingReceipt = self.decode("accounting.json")?;
        self.validate_accounting(&accounting)?;
        let preparation: PreparationReceipt = self.decode("preparation.json")?;
        let expected_pins = BTreeMap::from([
            ("teapot_sha256".into(), TEAPOT_SHA256.parse().expect("pin")),
            (
                "investigation_sha256".into(),
                INVESTIGATION_SHA256.parse().expect("pin"),
            ),
        ]);
        let expected_files = BTreeMap::from([
            ("reset".into(), self.file_ref("reset.json")?),
            ("target".into(), self.file_ref("target.json")?),
            (
                "engagement_source".into(),
                self.file_ref("engagement.toml")?,
            ),
            ("pass".into(), self.file_ref("pass.toml")?),
            ("manifest".into(), self.file_ref("manifest-r1.json")?),
            (
                "manifest_history".into(),
                self.file_ref("manifest-history.json")?,
            ),
            (
                "session_access".into(),
                self.file_ref("session-access.json")?,
            ),
            ("accounting".into(), self.file_ref("accounting.json")?),
        ]);
        let manifest = self.file_ref("manifest-r1.json")?;
        let declaration = self.read_artifact("engagement.toml")?;
        if declaration != super::DECLARATION {
            return Err(invalid());
        }
        let pass = self.file_ref("pass.toml")?;
        let pass_reference = "pass.development-fixture".parse().map_err(|_| invalid())?;
        let expected_manifest = EngagementDraft::parse_toml(&declaration)
            .and_then(|draft| {
                draft.accept(PassPin {
                    reference: &pass_reference,
                    digest: &pass.sha256,
                })
            })
            .map_err(|_| invalid())?;
        if preparation.schema != SCHEMA
            || preparation.preparation_id != transaction.preparation_id
            || preparation.reset_id != reset.reset_id
            || preparation.pins != expected_pins
            || preparation.manifest_revision != 1
            || preparation.manifest_sha256 != manifest.sha256
            || preparation.manifest_artifact_sha256 != manifest.sha256
            || preparation.files != expected_files
            || expected_manifest.canonical_bytes() != self.read_artifact("manifest-r1.json")?
            || expected_manifest.digest() != &preparation.manifest_sha256
            || self.read_artifact("manifest-history.json")? != b"[]\n"
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_transaction(&self, receipt: &TransactionReceipt) -> io::Result<()> {
        if receipt.schema != SCHEMA
            || receipt.transaction_state != "pending"
            || receipt.workspace != self.workspace.to_str().ok_or_else(invalid)?
            || Some(receipt.workspace_root) != *self.workspace_identity.borrow()
            || receipt.managed_guide != self.managed_guide
            || receipt.protected_root != self.identity
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_sessions(&self, access: &SessionAccess) -> io::Result<()> {
        if access.schema != SCHEMA || access.identity_probe != "GET /app/api/me" {
            return Err(invalid());
        }
        let expected_cases = BTreeMap::from([
            ("positive".into(), ordinary_case()),
            ("public".into(), ordinary_case()),
            ("login".into(), ordinary_case()),
            (
                "same_subject".into(),
                CaseSessions {
                    owner: "alice".into(),
                    other: "alice_same".into(),
                    verifier_owner: "alice_verify".into(),
                    verifier_other: "alice_verify_same".into(),
                    anonymous: "scourge_anonymous".into(),
                },
            ),
        ]);
        if access.cases != expected_cases || access.sessions.len() != 7 {
            return Err(invalid());
        }
        let mut flows = BTreeSet::new();
        let mut cookies = BTreeSet::new();
        let mut subjects = BTreeMap::new();
        let mut names = BTreeSet::new();
        for session in &access.sessions {
            if !names.insert(session.name.as_str())
                || session.identity_probe != "GET /app/api/me"
                || session.flow_id == 0
                || !flows.insert(session.flow_id)
            {
                return Err(invalid());
            }
            let file = format!("identity-{}.json", session.name);
            let reference = self.file_ref(&file)?;
            let body = self.read_artifact(&file)?;
            if session.original != reference || session.response_sha256 != reference.sha256 {
                return Err(invalid());
            }
            let value: serde_json::Value =
                scourge_core::wire::from_slice(&body).map_err(|_| invalid())?;
            if session.name == "scourge_anonymous" {
                if session.status != 401
                    || session.cookie_sha256.is_some()
                    || session.subject_sha256.is_some()
                {
                    return Err(invalid());
                }
            } else {
                let cookie = session.cookie_sha256.as_ref().ok_or_else(invalid)?;
                let subject = value["id"].as_str().ok_or_else(invalid)?;
                if session.status != 200
                    || !cookies.insert(cookie.as_str())
                    || session.subject_sha256.as_ref()
                        != Some(&Sha256Digest::of(subject.as_bytes()))
                {
                    return Err(invalid());
                }
                subjects.insert(session.name.as_str(), subject.to_owned());
            }
        }
        if names != PREPARED_SESSIONS.into_iter().collect()
            || subjects.get("alice") != subjects.get("alice_same")
            || subjects.get("alice_verify") != subjects.get("alice_verify_same")
            || subjects.get("alice") == subjects.get("bob")
            || subjects.get("alice_verify") == subjects.get("bob_verify")
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_accounting(&self, receipt: &AccountingReceipt) -> io::Result<()> {
        let before = &receipt.before;
        let after = &receipt.after;
        let spend = after.spent.checked_sub(before.spent).ok_or_else(invalid)?;
        if receipt.schema != SCHEMA
            || receipt.scope != "fresh-private-teapot-project-and-unique-pass"
            || !receipt.fresh_private_project
            || !receipt.exclusive_engine
            || receipt.pass_sha256 != self.file_ref("pass.toml")?.sha256
            || receipt.native_pass_digest != before.native_pass_digest
            || before.native_pass_digest != after.native_pass_digest
            || before.spent != 0
            || before.total != after.total
            || before.spent.checked_add(before.left) != Some(before.total)
            || after.spent.checked_add(after.left) != Some(after.total)
            || before.unused != 0
            || after.unused != 0
            || spend == 0
            || receipt.observed_spend != spend
            || receipt.completeness_claim != "fixture-specific-lower-bound"
            || receipt.attribution != "unestablished"
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_saved_workspace(&self) -> io::Result<()> {
        self.validate_workspace_identity()?;
        let files = visible_files(&self.workspace)?;
        self.validate_workspace_identity()?;
        if files.contains_key("AGENTS.md") != self.managed_guide {
            return Err(invalid());
        }
        let current = WorkspaceReceipt {
            schema: SCHEMA.into(),
            mode: if self.managed_guide {
                "managed".into()
            } else {
                "executable".into()
            },
            managed_guide: self.managed_guide,
            files,
        };
        self.validate_workspace(&current)
    }

    fn validate_workspace_identity(&self) -> io::Result<()> {
        if self.workspace_identity.borrow().as_ref() != Some(&directory_identity(&self.workspace)?)
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_workspace(&self, current: &WorkspaceReceipt) -> io::Result<()> {
        let saved: WorkspaceReceipt = self.decode("workspace.json")?;
        if &saved != current {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_settlement(&self) -> io::Result<()> {
        let settlement: SettlementReceipt = self.decode("settlement.json")?;
        let expected: BTreeMap<_, _> = self
            .artifacts
            .borrow()
            .iter()
            .filter(|(name, _)| name.as_str() != "settlement.json")
            .map(|(name, artifact)| (name.clone(), artifact.digest.clone()))
            .collect();
        if settlement.schema != SCHEMA
            || settlement.transaction_state != "settled"
            || settlement.preparation_id != self.preparation_id()?
            || !settlement.settled
            || settlement.managed_guide != self.managed_guide
            || settlement.protected_files != expected
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn file_ref(&self, name: &str) -> io::Result<FileRef> {
        self.artifacts
            .borrow()
            .get(name)
            .map(|artifact| FileRef {
                path: name.into(),
                sha256: artifact.digest.clone(),
                size_bytes: artifact.size_bytes,
            })
            .ok_or_else(invalid)
    }

    fn decode<T: serde::de::DeserializeOwned>(&self, name: &str) -> io::Result<T> {
        scourge_core::wire::from_slice(&self.read_artifact(name)?).map_err(|_| invalid())
    }

    fn write_json(&self, name: &str, value: &impl Serialize) -> io::Result<FileRef> {
        self.write_bytes(name, &json_bytes(value)?)
    }

    fn write_bytes(&self, name: &str, bytes: &[u8]) -> io::Result<FileRef> {
        self.write_bytes_with(name, bytes, &mut |_| Ok(()))
    }

    fn write_bytes_with(
        &self,
        name: &str,
        bytes: &[u8],
        hook: &mut impl FnMut(&str) -> io::Result<()>,
    ) -> io::Result<FileRef> {
        if !valid_name(name) || bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(invalid());
        }
        self.verify_artifacts()?;
        let temporary = format!(".tmp-{}", Uuid::new_v4());
        let mut file = File::from(rfs::openat(
            &self.directory,
            &temporary,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        hook("temp_created")?;
        let middle = bytes.len() / 2;
        file.write_all(&bytes[..middle])?;
        hook("partial_write")?;
        file.write_all(&bytes[middle..])?;
        hook("write_complete")?;
        file.sync_all()?;
        hook("file_synced")?;
        let metadata = file.metadata()?;
        private_file(&metadata)?;
        rfs::renameat_with(
            &self.directory,
            &temporary,
            &self.directory,
            name,
            RenameFlags::NOREPLACE,
        )?;
        hook("renamed")?;
        self.directory.sync_all()?;
        hook("directory_synced")?;
        let artifact = ProtectedArtifact {
            identity: FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            digest: Sha256Digest::of(bytes),
            size_bytes: bytes.len(),
            file,
        };
        let reference = FileRef {
            path: name.to_owned(),
            sha256: artifact.digest.clone(),
            size_bytes: bytes.len(),
        };
        if self
            .artifacts
            .borrow_mut()
            .insert(name.to_owned(), artifact)
            .is_some()
        {
            return Err(invalid());
        }
        self.verify_artifacts()?;
        Ok(reference)
    }

    fn read_artifact(&self, name: &str) -> io::Result<Vec<u8>> {
        let artifact = self
            .artifacts
            .borrow()
            .get(name)
            .map(|artifact| {
                (
                    artifact.identity,
                    artifact.digest.clone(),
                    artifact.size_bytes,
                )
            })
            .ok_or_else(invalid)?;
        let mut file = self.open_named(name)?;
        let metadata = file.metadata()?;
        if (FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }) != artifact.0
        {
            return Err(invalid());
        }
        let bytes = read_all(&mut file)?;
        if bytes.len() != artifact.2 || Sha256Digest::of(&bytes) != artifact.1 {
            return Err(invalid());
        }
        Ok(bytes)
    }

    fn verify_artifacts(&self) -> io::Result<()> {
        self.verify_directory()?;
        let names = self.names()?;
        let expected_names: BTreeSet<_> = self.artifacts.borrow().keys().cloned().collect();
        if names != expected_names {
            return Err(invalid());
        }
        for name in names {
            let expected = self
                .artifacts
                .borrow()
                .get(&name)
                .map(|artifact| {
                    (
                        artifact.identity,
                        artifact.digest.clone(),
                        artifact.size_bytes,
                        artifact.file.metadata(),
                    )
                })
                .ok_or_else(invalid)?;
            let held = expected.3?;
            private_file(&held)?;
            if (FileIdentity {
                device: held.dev(),
                inode: held.ino(),
            }) != expected.0
            {
                return Err(invalid());
            }
            let mut file = self.open_named(&name)?;
            let metadata = file.metadata()?;
            if (FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }) != expected.0
            {
                return Err(invalid());
            }
            let bytes = read_all(&mut file)?;
            if bytes.len() != expected.2 || Sha256Digest::of(&bytes) != expected.1 {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn verify_directory(&self) -> io::Result<()> {
        let metadata = self.directory.metadata()?;
        private_directory(&metadata)?;
        if metadata.dev() != self.identity.device || metadata.ino() != self.identity.inode {
            return Err(invalid());
        }
        Ok(())
    }

    fn names(&self) -> io::Result<BTreeSet<String>> {
        self.verify_directory()?;
        let mut directory = Dir::read_from(&self.directory)?;
        let mut names = BTreeSet::new();
        while let Some(entry) = directory.read() {
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = OsStr::from_bytes(bytes)
                .to_str()
                .filter(|name| valid_name(name))
                .ok_or_else(invalid)?
                .to_owned();
            names.insert(name);
        }
        Ok(names)
    }

    fn open_named(&self, name: &str) -> io::Result<File> {
        if !valid_name(name) {
            return Err(invalid());
        }
        let file = File::from(rfs::openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        private_file(&file.metadata()?)?;
        Ok(file)
    }

    fn open_artifact(&self, name: &str) -> io::Result<ProtectedArtifact> {
        let mut file = self.open_named(name)?;
        let metadata = file.metadata()?;
        let bytes = read_all(&mut file)?;
        Ok(ProtectedArtifact {
            identity: FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            digest: Sha256Digest::of(&bytes),
            size_bytes: bytes.len(),
            file,
        })
    }
}

fn ordinary_case() -> CaseSessions {
    CaseSessions {
        owner: "alice".into(),
        other: "bob".into(),
        verifier_owner: "alice_verify".into(),
        verifier_other: "bob_verify".into(),
        anonymous: "scourge_anonymous".into(),
    }
}

fn prepared_names() -> BTreeSet<String> {
    PREPARED_ARTIFACTS.into_iter().map(str::to_owned).collect()
}

fn domain_id(domain: &[u8], token: Uuid) -> Sha256Digest {
    Sha256Digest::of(&[domain, token.as_bytes()].concat())
}

fn json_bytes(value: &impl Serialize) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_all(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_ARTIFACT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

fn directory_identity(path: &Path) -> io::Result<RootIdentity> {
    let directory = File::from(rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(invalid());
    }
    Ok(RootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn private_directory(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid());
    }
    Ok(())
}

fn private_file(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_file()
        || FileType::from_raw_mode(metadata.mode()) != FileType::RegularFile
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(invalid());
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.as_bytes().contains(&b'/')
}

fn visible_files(root: &Path) -> io::Result<BTreeMap<String, VisibleFile>> {
    fn walk(
        root: &Path,
        current: &Path,
        files: &mut BTreeMap<String, VisibleFile>,
    ) -> io::Result<()> {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(invalid());
            }
            if metadata.is_dir() {
                walk(root, &path, files)?;
            } else if metadata.is_file() {
                let relative = path.strip_prefix(root).map_err(|_| invalid())?;
                let name = relative.to_str().ok_or_else(invalid)?.to_owned();
                let bytes = fs::read(&path)?;
                files.insert(
                    name,
                    VisibleFile {
                        sha256: Sha256Digest::of(&bytes),
                        size_bytes: bytes.len(),
                        mode: metadata.permissions().mode() & 0o777,
                    },
                );
            } else {
                return Err(invalid());
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files)?;
    Ok(files)
}

fn invalid() -> io::Error {
    io::Error::other("invalid cold-trial preparation boundary")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Roots {
        _temp: tempfile::TempDir,
        referee: PathBuf,
        workspace: PathBuf,
        state: PathBuf,
    }

    impl Roots {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let referee = temp.path().join("referee");
            let workspace = temp.path().join("workspace");
            fs::create_dir(&referee).unwrap();
            fs::create_dir(&workspace).unwrap();
            fs::set_permissions(&referee, fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                workspace,
                state: temp.path().join("state"),
                referee,
                _temp: temp,
            }
        }

        fn open(&self) -> ProtectedRoot {
            ProtectedRoot::open(&self.referee, &self.workspace, &self.state, false).unwrap()
        }
    }

    #[derive(Clone, Copy)]
    enum GraphFault {
        None,
        ResetReference,
        OriginalReference,
        OriginalJson,
        SameSubject,
        Accounting,
        TruncatedPreparation,
        DuplicatePreparationMember,
        UnknownPreparationMember,
    }

    fn write_valid_prepared(protected: &ProtectedRoot, fault: GraphFault) {
        protected.begin().unwrap();
        let preparation_id = protected.preparation_id().unwrap();
        let reset_id = Sha256Digest::of(b"reset");
        let reset = protected
            .write_json(
                "reset.json",
                &ResetReceipt {
                    schema: SCHEMA.into(),
                    preparation_id: preparation_id.clone(),
                    reset_id: reset_id.clone(),
                    method: "fresh-process".into(),
                    fixture_state: "seeded".into(),
                },
            )
            .unwrap();
        let target = protected
            .write_json(
                "target.json",
                &TargetReceipt {
                    schema: SCHEMA.into(),
                    origin: "http://127.0.0.1:12345".into(),
                    address: "127.0.0.1:12345".into(),
                    tls_identity: None,
                    deployment: "scourge-development-fixture".into(),
                    evidence_strength: "native-owned-process".into(),
                },
            )
            .unwrap();
        let source = protected
            .write_bytes("engagement.toml", super::super::DECLARATION)
            .unwrap();
        let pass = protected.write_bytes("pass.toml", b"format = 1\n").unwrap();
        let pass_reference = "pass.development-fixture".parse().unwrap();
        let manifest_value = EngagementDraft::parse_toml(super::super::DECLARATION)
            .and_then(|draft| {
                draft.accept(PassPin {
                    reference: &pass_reference,
                    digest: &pass.sha256,
                })
            })
            .unwrap();
        let manifest = protected
            .write_bytes("manifest-r1.json", manifest_value.canonical_bytes())
            .unwrap();
        let history = protected
            .write_bytes("manifest-history.json", b"[]\n")
            .unwrap();

        let rows = [
            ("alice", 200, Some("alice")),
            ("bob", 200, Some("bob")),
            (
                "alice_same",
                200,
                Some(if matches!(fault, GraphFault::SameSubject) {
                    "mallory"
                } else {
                    "alice"
                }),
            ),
            ("alice_verify", 200, Some("alice-verify")),
            ("bob_verify", 200, Some("bob-verify")),
            ("alice_verify_same", 200, Some("alice-verify")),
            ("scourge_anonymous", 401, None),
        ];
        let mut sessions = Vec::new();
        for (index, (name, status, subject)) in rows.into_iter().enumerate() {
            let body = if name == "alice" && matches!(fault, GraphFault::OriginalJson) {
                b"{".to_vec()
            } else if let Some(subject) = subject {
                format!("{{\"id\":\"{subject}\"}}").into_bytes()
            } else {
                b"{\"error\":\"unauthorized\"}".to_vec()
            };
            let mut original = protected
                .write_bytes(&format!("identity-{name}.json"), &body)
                .unwrap();
            if name == "alice" && matches!(fault, GraphFault::OriginalReference) {
                original.sha256 = Sha256Digest::of(b"wrong original");
            }
            sessions.push(SessionReceipt {
                name: name.into(),
                identity_probe: "GET /app/api/me".into(),
                flow_id: index as u64 + 1,
                original,
                status,
                cookie_sha256: subject
                    .is_some()
                    .then(|| Sha256Digest::of(format!("cookie-{name}").as_bytes())),
                subject_sha256: subject.map(|value| Sha256Digest::of(value.as_bytes())),
                response_sha256: Sha256Digest::of(&body),
            });
        }
        sessions.sort_by(|left, right| left.name.cmp(&right.name));
        let access = protected
            .write_json(
                "session-access.json",
                &SessionAccess {
                    schema: SCHEMA.into(),
                    identity_probe: "GET /app/api/me".into(),
                    sessions,
                    cases: BTreeMap::from([
                        ("positive".into(), ordinary_case()),
                        ("public".into(), ordinary_case()),
                        ("login".into(), ordinary_case()),
                        (
                            "same_subject".into(),
                            CaseSessions {
                                owner: "alice".into(),
                                other: "alice_same".into(),
                                verifier_owner: "alice_verify".into(),
                                verifier_other: "alice_verify_same".into(),
                                anonymous: "scourge_anonymous".into(),
                            },
                        ),
                    ]),
                },
            )
            .unwrap();
        let native_pass_digest = Sha256Digest::of(b"native pass");
        let accounting = protected
            .write_json(
                "accounting.json",
                &AccountingReceipt {
                    schema: SCHEMA.into(),
                    scope: "fresh-private-teapot-project-and-unique-pass".into(),
                    fresh_private_project: true,
                    exclusive_engine: true,
                    pass_sha256: pass.sha256.clone(),
                    native_pass_digest: native_pass_digest.clone(),
                    before: PassCounter {
                        native_pass_digest: native_pass_digest.clone(),
                        total: 100,
                        spent: 0,
                        left: 100,
                        unused: 0,
                    },
                    after: PassCounter {
                        native_pass_digest,
                        total: 100,
                        spent: 7,
                        left: 93,
                        unused: 0,
                    },
                    observed_spend: if matches!(fault, GraphFault::Accounting) {
                        6
                    } else {
                        7
                    },
                    completeness_claim: "fixture-specific-lower-bound".into(),
                    attribution: "unestablished".into(),
                },
            )
            .unwrap();
        let mut reset_ref = reset;
        if matches!(fault, GraphFault::ResetReference) {
            reset_ref.sha256 = Sha256Digest::of(b"wrong reset");
        }
        let preparation = PreparationReceipt {
            schema: SCHEMA.into(),
            preparation_id,
            reset_id,
            pins: BTreeMap::from([
                ("teapot_sha256".into(), TEAPOT_SHA256.parse().unwrap()),
                (
                    "investigation_sha256".into(),
                    INVESTIGATION_SHA256.parse().unwrap(),
                ),
            ]),
            manifest_revision: 1,
            manifest_sha256: manifest.sha256.clone(),
            manifest_artifact_sha256: manifest.sha256.clone(),
            files: BTreeMap::from([
                ("reset".into(), reset_ref),
                ("target".into(), target),
                ("engagement_source".into(), source),
                ("pass".into(), pass),
                ("manifest".into(), manifest),
                ("manifest_history".into(), history),
                ("session_access".into(), access),
                ("accounting".into(), accounting),
            ]),
        };
        let mut bytes = json_bytes(&preparation).unwrap();
        match fault {
            GraphFault::TruncatedPreparation => bytes.truncate(bytes.len() / 2),
            GraphFault::DuplicatePreparationMember => {
                bytes.splice(1..1, b"\"schema\":\"duplicate\",".iter().copied());
            }
            GraphFault::UnknownPreparationMember => {
                bytes.splice(1..1, b"\"unknown\":true,".iter().copied());
            }
            _ => {}
        }
        protected.write_bytes("preparation.json", &bytes).unwrap();
    }

    #[test]
    fn directory_path_replacement_does_not_redirect_protected_writes() {
        let roots = Roots::new();
        let protected = roots.open();
        protected.begin().unwrap();
        let held = roots.referee.with_extension("held");
        fs::rename(&roots.referee, &held).unwrap();
        fs::create_dir(&roots.referee).unwrap();
        fs::set_permissions(&roots.referee, fs::Permissions::from_mode(0o700)).unwrap();

        protected.write_bytes("probe", b"held directory\n").unwrap();

        assert_eq!(fs::read(held.join("probe")).unwrap(), b"held directory\n");
        assert!(!roots.referee.join("probe").exists());
    }

    #[test]
    fn symlink_and_regular_file_replacement_are_rejected() {
        for symlink_replacement in [true, false] {
            let roots = Roots::new();
            let protected = roots.open();
            protected.begin().unwrap();
            protected.write_bytes("probe", b"original\n").unwrap();
            fs::remove_file(roots.referee.join("probe")).unwrap();
            if symlink_replacement {
                let outside = roots.referee.with_extension("outside");
                fs::write(&outside, b"replacement\n").unwrap();
                symlink(outside, roots.referee.join("probe")).unwrap();
            } else {
                fs::write(roots.referee.join("probe"), b"replacement\n").unwrap();
                fs::set_permissions(
                    roots.referee.join("probe"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            assert!(protected.verify_artifacts().is_err());
        }
    }

    #[test]
    fn interrupted_transaction_reopens_as_unsettled_and_keeps_partial_evidence() {
        let roots = Roots::new();
        let protected = roots.open();
        protected.begin().unwrap();
        protected
            .write_bytes("partial.json", b"partial evidence\n")
            .unwrap();
        drop(protected);

        let recovered = roots.open();

        assert!(!recovered.is_fresh());
        assert!(!recovered.can_settle());
        assert!(roots.referee.join("partial.json").is_file());
        let transaction: serde_json::Value =
            serde_json::from_slice(&fs::read(roots.referee.join("transaction.json")).unwrap())
                .unwrap();
        assert_eq!(transaction["transaction_state"], "pending");
        assert!(recovered.settle(&roots.workspace, false).is_err());
        assert!(!roots.referee.join("workspace.json").exists());
    }

    #[test]
    fn valid_pending_and_settled_transactions_recover_idempotently() {
        let roots = Roots::new();
        let protected = roots.open();
        write_valid_prepared(&protected, GraphFault::None);
        drop(protected);

        let pending = roots.open();
        assert!(pending.can_settle());
        pending.settle(&roots.workspace, false).unwrap();
        drop(pending);

        let settled = roots.open();
        assert!(settled.can_settle());
        settled.settle(&roots.workspace, false).unwrap();
        assert!(roots.referee.join("settlement.json").is_file());
    }

    #[test]
    fn corrupt_receipt_graphs_and_originals_never_become_settleable() {
        for fault in [
            GraphFault::ResetReference,
            GraphFault::OriginalReference,
            GraphFault::OriginalJson,
            GraphFault::SameSubject,
            GraphFault::Accounting,
            GraphFault::TruncatedPreparation,
            GraphFault::DuplicatePreparationMember,
            GraphFault::UnknownPreparationMember,
        ] {
            let roots = Roots::new();
            let protected = roots.open();
            write_valid_prepared(&protected, fault);
            drop(protected);

            let recovered = roots.open();
            assert!(!recovered.can_settle());
            assert!(!roots.referee.join("settlement.json").exists());
        }
    }

    #[test]
    fn corruption_of_each_prepared_artifact_is_independently_rejected() {
        for name in PREPARED_ARTIFACTS {
            let roots = Roots::new();
            let protected = roots.open();
            write_valid_prepared(&protected, GraphFault::None);
            drop(protected);
            fs::write(roots.referee.join(name), b"corrupt\n").unwrap();

            let recovered = roots.open();
            assert!(!recovered.can_settle(), "{name}");
            assert!(!roots.referee.join("settlement.json").exists(), "{name}");
        }
    }

    #[test]
    fn crash_after_workspace_receipt_recovers_and_finishes_settlement() {
        let roots = Roots::new();
        let protected = roots.open();
        write_valid_prepared(&protected, GraphFault::None);
        let failure = protected.settle_with(&roots.workspace, false, &mut |point| {
            if point == "workspace_durable" {
                Err(io::Error::other("injected crash"))
            } else {
                Ok(())
            }
        });
        assert!(failure.is_err());
        assert!(roots.referee.join("workspace.json").is_file());
        assert!(!roots.referee.join("settlement.json").exists());
        drop(protected);

        let recovered = roots.open();
        assert!(recovered.can_settle());
        recovered.settle(&roots.workspace, false).unwrap();
        assert!(roots.referee.join("settlement.json").is_file());
    }

    #[test]
    fn pre_settlement_recovery_rejects_same_content_workspace_inode_replacement() {
        let roots = Roots::new();
        let protected = roots.open();
        write_valid_prepared(&protected, GraphFault::None);
        assert!(
            protected
                .settle_with(&roots.workspace, false, &mut |point| {
                    if point == "workspace_durable" {
                        Err(io::Error::other("injected crash"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        drop(protected);
        let original = roots.workspace.with_extension("original");
        fs::rename(&roots.workspace, original).unwrap();
        fs::create_dir(&roots.workspace).unwrap();

        let recovered = roots.open();
        assert!(!recovered.can_settle());
        assert!(roots.referee.join("workspace.json").is_file());
        assert!(!roots.referee.join("settlement.json").exists());
    }

    #[test]
    fn atomic_publication_never_exposes_partial_final_artifacts() {
        for stage in [
            "temp_created",
            "partial_write",
            "write_complete",
            "file_synced",
            "renamed",
            "directory_synced",
        ] {
            let roots = Roots::new();
            let protected = roots.open();
            protected.begin().unwrap();
            let failure =
                protected.write_bytes_with("probe", b"complete artifact\n", &mut |point| {
                    if point == stage {
                        Err(io::Error::other("injected publication crash"))
                    } else {
                        Ok(())
                    }
                });
            assert!(failure.is_err(), "{stage}");
            let final_path = roots.referee.join("probe");
            if stage == "renamed" || stage == "directory_synced" {
                assert_eq!(fs::read(final_path).unwrap(), b"complete artifact\n");
            } else {
                assert!(!final_path.exists(), "{stage}");
            }
            drop(protected);
            let recovered = roots.open();
            assert!(!recovered.can_settle(), "{stage}");
        }
    }

    #[test]
    fn atomic_publication_never_replaces_a_racing_final_name() {
        let roots = Roots::new();
        let protected = roots.open();
        protected.begin().unwrap();
        let final_path = roots.referee.join("probe");
        let failure = protected.write_bytes_with("probe", b"owned artifact\n", &mut |point| {
            if point == "file_synced" {
                fs::write(&final_path, b"racing artifact\n")?;
                fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        });
        assert!(failure.is_err());
        assert_eq!(fs::read(final_path).unwrap(), b"racing artifact\n");
    }

    #[test]
    fn root_symlinks_and_hardlinked_artifacts_are_rejected() {
        let roots = Roots::new();
        let alias = roots.referee.with_extension("alias");
        symlink(&roots.referee, &alias).unwrap();
        assert!(ProtectedRoot::open(&alias, &roots.workspace, &roots.state, false).is_err());

        let protected = roots.open();
        protected.begin().unwrap();
        let linked = roots.referee.with_extension("linked");
        fs::hard_link(roots.referee.join("transaction.json"), linked).unwrap();
        assert!(protected.verify_artifacts().is_err());
    }
}
