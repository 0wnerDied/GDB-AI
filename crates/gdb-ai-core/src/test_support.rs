use std::process::Command;

pub(crate) fn require_commands(commands: &[&str]) -> bool {
    let missing = commands
        .iter()
        .copied()
        .filter(|command| Command::new(command).arg("--version").output().is_err())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return true;
    }
    // 2026-08-29: Unit tests silently returned when GDB tooling was absent,
    // so required CI could pass without running its debugger-dependent cases.
    if std::env::var_os("GDB_AI_REQUIRE_INTEGRATION").is_some() {
        panic!("required test commands are missing: {missing:?}");
    }
    eprintln!("skipped debugger-dependent unit test; missing commands: {missing:?}");
    false
}
