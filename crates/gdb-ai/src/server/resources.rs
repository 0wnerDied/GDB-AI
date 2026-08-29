use std::sync::atomic::AtomicU64;

use gdb_ai_core::{
    gateway::{Caller, Gateway},
    protocol::CanonicalMethod,
};
use serde_json::{Value, json};

use super::{ErrorCodeName, RpcFault, canonical_request, core_fault};

pub(super) async fn list_resources(
    gateway: &Gateway,
    caller: &Caller,
    sequence: &AtomicU64,
) -> Result<Value, RpcFault> {
    let response = gateway
        .dispatch(
            canonical_request(sequence, None, CanonicalMethod::SessionList, json!({})),
            caller,
        )
        .await;
    if let Some(error) = response.error {
        return Err(core_fault(error.code.code_name(), error.message));
    }
    let resources = response
        .result
        .and_then(|result| result.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|state| {
            let id = state.get("session_id")?.as_str()?;
            Some(json!({
                "uri": format!("gdbai://session/{id}/status"),
                "name": format!("Session {id} status"),
                "mimeType": "application/json"
            }))
        })
        .collect::<Vec<_>>();
    Ok(json!({"resources": resources}))
}

pub(super) fn resource_templates() -> Value {
    json!({"resourceTemplates": [
        {
            "uriTemplate": "gdbai://session/{session_id}/status",
            "name": "Session status",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/capabilities",
            "name": "Session capabilities",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/events",
            "name": "Current event state",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/transcript",
            "name": "Paged MI transcript",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/event/{event_seq}",
            "name": "Journal evidence entry",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/snapshot/{snapshot_id}",
            "name": "Stop snapshot",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/output/pty",
            "name": "Paged session PTY output",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/breakpoints",
            "name": "Session breakpoints",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://artifact/sha256:{digest}",
            "name": "Content-addressed artifact manifest",
            "mimeType": "application/vnd.gdb-ai.artifact-manifest+json"
        },
        {
            "uriTemplate": "gdbai://artifact/sha256:{digest}?offset={offset}&length={length}",
            "name": "Content-addressed artifact range",
            "mimeType": "application/octet-stream"
        }
    ]})
}

#[derive(Debug, PartialEq)]
enum ArtifactResource {
    Manifest {
        uri: String,
        digest: String,
    },
    Range {
        uri: String,
        artifact_uri: String,
        digest: String,
        offset: u64,
        length: u64,
    },
}

fn parse_artifact_resource(uri: &str) -> Result<ArtifactResource, RpcFault> {
    let (artifact_uri, query) = match uri.split_once('?') {
        Some(parts) => (parts.0, Some(parts.1)),
        None => (uri, None),
    };
    let digest = artifact_uri
        .strip_prefix("gdbai://artifact/sha256:")
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .ok_or_else(|| RpcFault::invalid("invalid artifact resource URI"))?
        .to_owned();
    let Some(query) = query else {
        return Ok(ArtifactResource::Manifest {
            uri: artifact_uri.to_owned(),
            digest,
        });
    };
    let (offset, length) = query
        .strip_prefix("offset=")
        .and_then(|query| query.split_once("&length="))
        .ok_or_else(|| RpcFault::invalid("artifact range requires offset and length"))?;
    let offset = offset
        .parse::<u64>()
        .ok()
        .filter(|value| value.to_string() == offset)
        .ok_or_else(|| RpcFault::invalid("artifact range offset is invalid"))?;
    let length = length
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == length)
        .ok_or_else(|| RpcFault::invalid("artifact range length is invalid"))?;
    Ok(ArtifactResource::Range {
        uri: uri.to_owned(),
        artifact_uri: artifact_uri.to_owned(),
        digest,
        offset,
        length,
    })
}

fn artifact_resource_contents(
    resource: ArtifactResource,
    result: Value,
) -> Result<Value, RpcFault> {
    let size = result
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcFault::invalid("artifact response contained no size"))?;
    let page_size = result
        .get("max_page_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcFault::invalid("artifact response contained no page limit"))?;
    match resource {
        ArtifactResource::Manifest { uri, digest } => {
            let manifest = json!({
                "uri": uri,
                "sha256": digest,
                "size": size,
                "mime_type": "application/octet-stream",
                "sensitivity": result.get("sensitivity").cloned().unwrap_or(Value::Null),
                "page_size": page_size,
                "range_uri_template": format!(
                    "gdbai://artifact/sha256:{digest}?offset={{offset}}&length={{length}}"
                )
            });
            let text = serde_json::to_string(&manifest)
                .map_err(|error| RpcFault::invalid(error.to_string()))?;
            Ok(json!({"contents": [{
                "uri": uri,
                "mimeType": "application/vnd.gdb-ai.artifact-manifest+json",
                "text": text
            }]}))
        }
        ArtifactResource::Range {
            uri,
            digest,
            offset,
            length,
            ..
        } => {
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= size)
                .ok_or_else(|| RpcFault::invalid("artifact range is outside the artifact"))?;
            if length > page_size {
                return Err(RpcFault::invalid("artifact range exceeds the page limit"));
            }
            let returned_offset = result.get("offset").and_then(Value::as_u64);
            let returned_end = result.get("next_offset").and_then(Value::as_u64);
            if returned_offset != Some(offset) || returned_end != Some(end) {
                return Err(RpcFault::invalid(
                    "artifact response did not contain the exact range",
                ));
            }
            let blob = result
                .get("data_base64")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcFault::invalid("artifact response contained no data"))?;
            Ok(json!({"contents": [{
                "uri": uri,
                "mimeType": "application/octet-stream",
                "blob": blob,
                "_meta": {
                    "sha256": digest,
                    "artifactSize": size,
                    "offset": offset,
                    "length": length
                }
            }]}))
        }
    }
}

pub(super) async fn read_resource(
    gateway: &Gateway,
    caller: &Caller,
    sequence: &AtomicU64,
    params: &Value,
) -> Result<Value, RpcFault> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFault::invalid("resources/read requires uri"))?;
    if uri.starts_with("gdbai://artifact/sha256:") {
        let resource = parse_artifact_resource(uri)?;
        let parameters = match &resource {
            ArtifactResource::Manifest { uri, .. } => json!({"uri": uri, "max_bytes": 1}),
            ArtifactResource::Range {
                artifact_uri,
                offset,
                length,
                ..
            } => json!({"uri": artifact_uri, "offset": offset, "max_bytes": length}),
        };
        let response = gateway
            .dispatch(
                canonical_request(sequence, None, CanonicalMethod::ArtifactGet, parameters),
                caller,
            )
            .await;
        if let Some(error) = response.error {
            return Err(core_fault(error.code.code_name(), error.message));
        }
        let result = response
            .result
            .ok_or_else(|| RpcFault::invalid("artifact response contained no result"))?;
        // 2026-08-29: resources/read previously discarded artifact paging
        // metadata and mislabeled the first page as the complete digest URI.
        // Return a manifest or an exact URI-bound range so evidence is whole.
        return artifact_resource_contents(resource, result);
    }
    let path = uri
        .strip_prefix("gdbai://session/")
        .ok_or_else(|| RpcFault {
            code: -32002,
            message: "resource not found".into(),
            data: Some(json!({"uri": uri})),
        })?;
    let parts = path.split('/').collect::<Vec<_>>();
    let session = parts
        .first()
        .copied()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| RpcFault {
            code: -32002,
            message: "resource not found".into(),
            data: Some(json!({"uri": uri})),
        })?;
    let (method, parameters) = match parts.as_slice() {
        [_, "status"] | [_, "events"] => (CanonicalMethod::SessionGet, json!({})),
        [_, "capabilities"] => (CanonicalMethod::SessionCapabilities, json!({})),
        [_, "transcript"] => (CanonicalMethod::SessionTranscript, json!({})),
        [_, "event", event_seq] => (
            CanonicalMethod::SessionEvent,
            json!({"event_seq": event_seq.parse::<u64>().map_err(|_| RpcFault::invalid("invalid event sequence"))?}),
        ),
        [_, "breakpoints"] => (CanonicalMethod::BreakpointList, json!({})),
        [_, "snapshot", snapshot_id] => (
            CanonicalMethod::InspectionSnapshotGet,
            json!({"snapshot_id": snapshot_id}),
        ),
        // 2026-08-29: The PTY ring is session-scoped. The old per-inferior
        // resource URI ignored its inferior ID and promised false isolation.
        [_, "output", "pty"] => (
            CanonicalMethod::InferiorIoRead,
            json!({"stream": "pty", "after_offset": 0, "max_bytes": 65536}),
        ),
        _ => {
            return Err(RpcFault {
                code: -32002,
                message: "resource not found".into(),
                data: Some(json!({"uri": uri})),
            });
        }
    };
    let response = gateway
        .dispatch(
            canonical_request(sequence, Some(session.into()), method, parameters),
            caller,
        )
        .await;
    if let Some(error) = response.error {
        return Err(core_fault(error.code.code_name(), error.message));
    }
    let text = serde_json::to_string(&response.result.unwrap_or(Value::Null))
        .map_err(|error| RpcFault::invalid(error.to_string()))?;
    Ok(json!({"contents": [{
        "uri": uri,
        "mimeType": "application/json",
        "text": text
    }]}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_resources_are_manifests_or_exact_ranges() {
        let digest = "a".repeat(64);
        let uri = format!("gdbai://artifact/sha256:{digest}");
        let result = json!({
            "size": 8,
            "sensitivity": "target-memory",
            "max_page_bytes": 4,
            "offset": 0,
            "next_offset": 1,
            "data_base64": "AA==",
            "truncated": true
        });
        let manifest =
            artifact_resource_contents(parse_artifact_resource(&uri).unwrap(), result.clone())
                .unwrap();
        assert_eq!(
            manifest["contents"][0]["mimeType"],
            "application/vnd.gdb-ai.artifact-manifest+json"
        );
        let manifest: Value =
            serde_json::from_str(manifest["contents"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(manifest["sha256"], digest);
        assert_eq!(manifest["size"], 8);
        assert_eq!(manifest["page_size"], 4);

        let range_uri = format!("{uri}?offset=4&length=4");
        let range = artifact_resource_contents(
            parse_artifact_resource(&range_uri).unwrap(),
            json!({
                "size": 8,
                "sensitivity": "target-memory",
                "max_page_bytes": 4,
                "offset": 4,
                "next_offset": 8,
                "data_base64": "BAUGBw==",
                "truncated": false
            }),
        )
        .unwrap();
        assert_eq!(range["contents"][0]["uri"], range_uri);
        assert_eq!(range["contents"][0]["blob"], "BAUGBw==");
        assert_eq!(range["contents"][0]["_meta"]["offset"], 4);
        assert_eq!(range["contents"][0]["_meta"]["length"], 4);

        assert!(
            artifact_resource_contents(
                parse_artifact_resource(&format!("{uri}?offset=4&length=4")).unwrap(),
                result,
            )
            .is_err()
        );
    }

    #[test]
    fn artifact_resource_ranges_reject_ambiguous_or_invalid_bounds() {
        let uri = format!("gdbai://artifact/sha256:{}", "b".repeat(64));
        for invalid in [
            format!("{uri}?length=1&offset=0"),
            format!("{uri}?offset=00&length=1"),
            format!("{uri}?offset=0&length=0"),
            format!("{uri}?offset=0&length=1&extra=1"),
        ] {
            assert!(parse_artifact_resource(&invalid).is_err(), "{invalid}");
        }
        let response = json!({
            "size": 8,
            "sensitivity": "target-memory",
            "max_page_bytes": 4,
            "offset": 7,
            "next_offset": 8,
            "data_base64": "AA==",
            "truncated": false
        });
        assert!(
            artifact_resource_contents(
                parse_artifact_resource(&format!("{uri}?offset=7&length=2")).unwrap(),
                response.clone(),
            )
            .is_err()
        );
        assert!(
            artifact_resource_contents(
                parse_artifact_resource(&format!("{uri}?offset=0&length=5")).unwrap(),
                response,
            )
            .is_err()
        );
    }

    #[test]
    fn resource_templates_describe_session_scoped_pty_output() {
        let templates = resource_templates().to_string();
        assert!(templates.contains("gdbai://session/{session_id}/output/pty"));
        assert!(!templates.contains("/inferior/{inferior_id}/output"));
    }
}
