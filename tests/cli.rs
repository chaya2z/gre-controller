use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gre-controller"))
        .args(args)
        .output()
        .expect("failed to run gre-controller")
}

fn write_config(file_name: &str, contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(file_name);
    fs::write(&path, contents).expect("failed to write test configuration");
    path
}

const VALID: &str = r#"
[tunnels.gre-peer01]
family = "ipv4"
local = "192.0.2.1"
remote = "peer.example.com"
addresses = ["10.0.1.1/31"]
"#;

#[test]
fn validate_accepts_valid_configuration() {
    let path = write_config("cli-valid.toml", VALID);
    let output = run(&["--config", path.to_str().unwrap(), "validate"]);
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("valid"));
}

#[test]
fn validate_accepts_config_option_after_subcommand() {
    let path = write_config("cli-valid-after.toml", VALID);
    let output = run(&["validate", "--config", path.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn validate_rejects_invalid_configuration() {
    let path = write_config(
        "cli-invalid.toml",
        &VALID.replace("10.0.1.1/31", "10.0.1.1"),
    );
    let output = run(&["--config", path.to_str().unwrap(), "validate"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("gre-peer01"));
}

#[test]
fn validate_rejects_blank_configuration() {
    let path = write_config("cli-blank.toml", "");
    let output = run(&["--config", path.to_str().unwrap(), "validate"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

#[test]
fn validate_rejects_missing_file() {
    let output = run(&["--config", "/nonexistent/gre-controller.toml", "validate"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

#[test]
fn no_subcommand_prints_help_and_fails() {
    let output = run(&[]);
    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage"));
}

#[test]
fn version_flag_succeeds() {
    let output = run(&["--version"]);
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));
}
