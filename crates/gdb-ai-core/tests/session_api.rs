use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    domain::Consistency,
    gateway::{Caller, Gateway},
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

fn successful(response: ApiResponse) -> ApiResponse {
    assert!(
        response.error.is_none(),
        "response error: {:?}",
        response.error
    );
    response
}

#[tokio::test]
async fn public_session_lifecycle_round_trips() {
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
        ..Config::default()
    };
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("session-api-test");

    let created = successful(
        gateway
            .dispatch(
                request("create", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let session_id = created.session_id.as_ref().unwrap().clone();
    let first_lease = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let status = successful(
        gateway
            .dispatch(
                request("get", Some(&session_id), "session.get", None, json!({})),
                &caller,
            )
            .await,
    );
    assert_eq!(status.result.as_ref().unwrap()["session_id"], session_id);

    let sessions = successful(
        gateway
            .dispatch(
                request("list", None, "session.list", None, json!({})),
                &caller,
            )
            .await,
    );
    assert!(
        sessions
            .result
            .as_ref()
            .unwrap()
            .as_array()
            .is_some_and(|sessions| sessions
                .iter()
                .any(|session| session["session_id"] == session_id))
    );

    let capabilities = successful(
        gateway
            .dispatch(
                request(
                    "capabilities",
                    Some(&session_id),
                    "session.capabilities",
                    None,
                    json!({}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(
        capabilities.result.as_ref().unwrap()["backend"]["name"],
        "gdb"
    );

    let providers = successful(
        gateway
            .dispatch(
                request(
                    "providers",
                    Some(&session_id),
                    "session.providers",
                    None,
                    json!({}),
                ),
                &caller,
            )
            .await,
    );
    assert!(
        providers
            .result
            .as_ref()
            .unwrap()
            .as_array()
            .is_some_and(|providers| providers
                .iter()
                .any(|provider| provider["name"] == "generic-gdb"))
    );

    let transcript = successful(
        gateway
            .dispatch(
                request(
                    "transcript",
                    Some(&session_id),
                    "session.transcript",
                    None,
                    json!({"max_bytes": 4096}),
                ),
                &caller,
            )
            .await,
    );
    assert!(
        transcript.result.as_ref().unwrap()["total_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0)
    );

    let released = successful(
        gateway
            .dispatch(
                request(
                    "release",
                    Some(&session_id),
                    "session.release_write_lease",
                    created.revision,
                    json!({"lease_id": first_lease}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(released.result.as_ref().unwrap()["released"], first_lease);

    let acquired = successful(
        gateway
            .dispatch(
                request(
                    "acquire",
                    Some(&session_id),
                    "session.acquire_write_lease",
                    released.revision,
                    json!({}),
                ),
                &caller,
            )
            .await,
    );
    let second_lease = acquired.result.as_ref().unwrap()["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(second_lease, first_lease);

    let recovered = successful(
        gateway
            .dispatch(
                request(
                    "recover",
                    Some(&session_id),
                    "session.attempt_recovery",
                    acquired.revision,
                    json!({"lease_id": second_lease}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(
        recovered.state.as_ref().unwrap().consistency,
        Consistency::Clean
    );

    let closed = successful(
        gateway
            .dispatch(
                request(
                    "close",
                    Some(&session_id),
                    "session.close",
                    recovered.revision,
                    json!({"lease_id": second_lease}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(closed.result.as_ref().unwrap()["closed"], true);

    let persisted = successful(
        gateway
            .dispatch(
                request(
                    "persisted-get",
                    Some(&session_id),
                    "session.get",
                    None,
                    json!({}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(persisted.result.as_ref().unwrap()["session_id"], session_id);
    successful(
        gateway
            .dispatch(
                request(
                    "persisted-transcript",
                    Some(&session_id),
                    "session.transcript",
                    None,
                    json!({"max_bytes": 4096}),
                ),
                &caller,
            )
            .await,
    );
}
