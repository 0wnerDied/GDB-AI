use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    domain::Consistency,
    gateway::{Caller, Gateway},
    policy::Profile,
    protocol::{API_VERSION, ApiRequest, ApiResponse},
};
use serde_json::{Value, json};
use tempfile::tempdir;

mod support;

fn request(
    id: &str,
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

async fn call(gateway: &Gateway, caller: &Caller, request: ApiRequest) -> ApiResponse {
    let response = gateway.dispatch(request, caller).await;
    assert!(
        response.error.is_none(),
        "response error: {:?}",
        response.error
    );
    response
}

#[tokio::test]
async fn raw_admin_defers_reconciliation_until_structured_inspection() {
    if !support::require_commands(&["gdb"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        security: gdb_ai_core::config::SecurityConfig {
            default_profile: Profile::RawAdmin,
            ..Default::default()
        },
        ..Config::default()
    };
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller {
        identity: "raw-admin-test".into(),
        admin: true,
    };

    let created = call(
        &gateway,
        &caller,
        request("create", None, "session.create", None, json!({})),
    )
    .await;
    let session_id = created.session_id.as_ref().unwrap().clone();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let raw_mi = call(
        &gateway,
        &caller,
        request(
            "raw-mi",
            Some(&session_id),
            "raw.mi",
            created.revision,
            json!({
                "lease_id": lease_id,
                "command": "-thread-info",
                "arguments": []
            }),
        ),
    )
    .await;
    assert_eq!(
        raw_mi.state.as_ref().unwrap().consistency,
        Consistency::ManagedDirty
    );
    assert_eq!(
        raw_mi.result.as_ref().unwrap()["reconciliation"]["status"],
        "deferred"
    );
    let breakpoint = call(
        &gateway,
        &caller,
        request(
            "breakpoint",
            Some(&session_id),
            "breakpoint.create",
            raw_mi.revision,
            json!({"lease_id": lease_id, "location": {"function": "main"}, "pending": true}),
        ),
    )
    .await;
    assert!(!breakpoint.state.as_ref().unwrap().reconciliation_required);

    let raw_console = call(
        &gateway,
        &caller,
        request(
            "raw-console",
            Some(&session_id),
            "raw.console",
            breakpoint.revision,
            json!({
                "lease_id": lease_id,
                "command": "show version"
            }),
        ),
    )
    .await;
    assert_eq!(
        raw_console.state.as_ref().unwrap().consistency,
        Consistency::Tainted
    );
    assert_eq!(
        raw_console.result.as_ref().unwrap()["reconciliation"]["status"],
        "deferred"
    );

    let failed = gateway
        .dispatch(
            request(
                "raw-console-error",
                Some(&session_id),
                "raw.console",
                raw_console.revision,
                json!({
                    "lease_id": lease_id,
                    "command": "info address gdb_ai_missing_symbol"
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        failed.error.as_ref().unwrap().code,
        gdb_ai_core::ErrorCode::GdbError
    );
    assert!(failed.state.as_ref().unwrap().reconciliation_required);
    assert!(
        gateway
            .metrics()
            .contains("gdbai_reconciliations_total 1\n")
    );
    let (inspected, capabilities) = tokio::join!(
        call(
            &gateway,
            &caller,
            request(
                "inspect",
                Some(&session_id),
                "breakpoint.list",
                None,
                json!({}),
            ),
        ),
        call(
            &gateway,
            &caller,
            request(
                "capabilities",
                Some(&session_id),
                "session.capabilities",
                None,
                json!({}),
            )
        )
    );
    assert!(!inspected.state.as_ref().unwrap().reconciliation_required);
    assert!(!capabilities.state.as_ref().unwrap().reconciliation_required);
    assert!(
        gateway
            .metrics()
            .contains("gdbai_reconciliations_total 2\n")
    );

    call(
        &gateway,
        &caller,
        request(
            "close",
            Some(&session_id),
            "session.close",
            inspected.revision,
            json!({"lease_id": lease_id}),
        ),
    )
    .await;
}
