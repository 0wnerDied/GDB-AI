#![allow(
    dead_code,
    reason = "Integration targets use different helper subsets."
)]

use std::process::Command;

use gdb_ai_core::{
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest, ApiResponse},
};
use serde_json::Value;

pub fn request(
    id: impl Into<String>,
    session_id: Option<&str>,
    method: &str,
    revision: Option<u64>,
    parameters: Value,
) -> ApiRequest {
    ApiRequest {
        api_version: API_VERSION.into(),
        request_id: id.into(),
        session_id: session_id.map(str::to_owned),
        method: method.parse().unwrap(),
        expected_revision: revision,
        idempotency_key: None,
        parameters,
    }
}

#[track_caller]
pub fn successful(response: ApiResponse) -> ApiResponse {
    assert!(
        response.error.is_none(),
        "{} response error: {:?}; state: {:?}; result: {:?}",
        response.request_id,
        response.error,
        response.state,
        response.result
    );
    response
}

pub async fn call(gateway: &Gateway, caller: &Caller, request: ApiRequest) -> ApiResponse {
    successful(gateway.dispatch(request, caller).await)
}

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
