use std::{env, fs, process::Command};

fn command(args: &[&str]) -> Option<String> {
    let output = Command::new(args[0]).args(&args[1..]).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn value(name: &str, fallback: Option<String>) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or(fallback)
        .unwrap_or_else(|| "unknown".into())
        .lines()
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_owned()
}

fn main() {
    for name in [
        "GDB_AI_BUILD_COMMIT",
        "GDB_AI_BUILD_DIRTY",
        "GDB_AI_BUILD_RUSTC",
        "GDB_AI_BUILD_TAG",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    println!("cargo:rerun-if-changed=../../schemas/SHA256SUMS");

    let commit = value(
        "GDB_AI_BUILD_COMMIT",
        command(&["git", "rev-parse", "HEAD"]),
    );
    let tag = value(
        "GDB_AI_BUILD_TAG",
        command(&["git", "describe", "--tags", "--exact-match"]),
    );
    let dirty = value(
        "GDB_AI_BUILD_DIRTY",
        command(&["git", "status", "--porcelain"])
            .map(|status| if status.is_empty() { "false" } else { "true" }.into()),
    );
    let rustc = value(
        "GDB_AI_BUILD_RUSTC",
        env::var("RUSTC")
            .ok()
            .and_then(|rustc| command(&[&rustc, "--version"])),
    );
    let schema = fs::read_to_string("../../schemas/SHA256SUMS")
        .ok()
        .and_then(|sums| {
            sums.lines()
                .find(|line| line.ends_with("  gdb.ai.v1.json"))
                .and_then(|line| line.split_whitespace().next())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=GDB_AI_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=GDB_AI_BUILD_DIRTY={dirty}");
    println!("cargo:rustc-env=GDB_AI_BUILD_TAG={tag}");
    println!("cargo:rustc-env=GDB_AI_BUILD_RUSTC={rustc}");
    println!("cargo:rustc-env=GDB_AI_BUILD_SCHEMA_SHA256={schema}");
}
