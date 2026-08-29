use std::process::Command;

pub fn require_commands(commands: &[&str]) -> bool {
    let missing = commands
        .iter()
        .copied()
        .filter(|command| {
            // 2026-08-29: Compatibility jobs qualify an exact GDB release
            // without replacing the runner's system binary.
            let executable = if *command == "gdb" {
                std::env::var_os("GDB_AI_GDB_PATH").unwrap_or_else(|| (*command).into())
            } else {
                (*command).into()
            };
            Command::new(executable).arg("--version").output().is_err()
        })
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return true;
    }

    // 2026-08-28: Integration tests silently returned when GDB tooling was
    // absent, allowing required CI to report green without exercising GDB.
    if std::env::var_os("GDB_AI_REQUIRE_INTEGRATION").is_some() {
        panic!("required integration commands are missing: {missing:?}");
    }
    eprintln!("skipped integration test; missing commands: {missing:?}");
    false
}
