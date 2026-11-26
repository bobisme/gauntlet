use std::process::{Command, Output};

use scourge_core::wire::{self, CommitStatus, Effect, ErrorCode, ResponseV1};

const README: &str = include_str!("../../../README.md");
const MANAGED_GUIDE: &str = include_str!("../../scourge-core/src/workspace/managed-guide.md");

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_scourge"));
    command.env_clear().env("FORMAT", "json");
    command
}

fn response(output: Output, exit: u8) -> ResponseV1 {
    assert_eq!(output.status.code(), Some(i32::from(exit)), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
        1,
        "{output:?}"
    );
    wire::from_slice(&output.stdout).unwrap()
}

fn runnable_readme_script() -> &'static str {
    README
        .split_once("```sh\n")
        .expect("README M1 example fence")
        .1
        .split_once("\n```")
        .expect("README M1 example fence")
        .0
}

#[test]
fn readme_m1_block_is_a_syntax_checked_lead_to_verification_path() {
    assert_eq!(
        runnable_readme_script(),
        r#"workspace=./scourge-demo
scourge demo "$workspace"
scourge --workspace "$workspace" status
lead_id="$(
    scourge --format json --workspace "$workspace" lead add "bob reads alice's order" \
        --class web-authz/private-object-read --property orders \
        --slot other=bob |
        jq -er '.lead.id'
)"
scourge --workspace "$workspace" verify "$lead_id" --plan
scourge --workspace "$workspace" verify "$lead_id"
scourge demo --stop "$workspace""#
    );
    let syntax = Command::new("/bin/bash")
        .args(["-n", "-c", runnable_readme_script()])
        .output()
        .unwrap();
    assert!(syntax.status.success(), "{syntax:?}");
}

#[test]
fn every_printed_future_command_is_milestone_labelled_and_unadvertised() {
    assert!(MANAGED_GUIDE.contains(
        "supports `scourge verify LEAD --plan` and live `scourge verify LEAD` for the\nM1 private-object-read class."
    ));
    for (document, name) in [(README, "README"), (MANAGED_GUIDE, "managed guide")] {
        assert!(
            !document.contains("Live verification is planned for M1.")
                && !document.contains("Live verification is\nplanned for M1."),
            "{name} retains a stale M1 future label"
        );
        for (future, milestone) in [
            ("scourge report", "planned for M2"),
            ("scourge retest", "planned for M2"),
        ] {
            for paragraph in document
                .split("\n\n")
                .filter(|paragraph| paragraph.contains(future))
            {
                assert!(
                    paragraph.contains(milestone),
                    "{name} prints {future:?} without {milestone:?}: {paragraph:?}"
                );
            }
        }
    }

    let help = response(command().args(["help", "verify"]).output().unwrap(), 0);
    let help = help.extensions["help"].as_str().unwrap();
    assert!(help.contains("Retest is planned for M2."));

    for future in ["report", "retest"] {
        let refused = response(command().arg(future).output().unwrap(), 2);
        let error = refused.error.unwrap();
        assert_eq!(error.code, ErrorCode::UsageError);
        assert_eq!(error.commit_status, CommitStatus::NotCommitted);
        assert_eq!(refused.effects, Effect::None);
        assert_eq!(refused.command, None);
        assert_eq!(refused.workspace, None);
        assert_eq!(refused.engagement, None);
        assert_eq!(refused.request_key, None);
        assert_eq!(refused.run, None);
    }
}
