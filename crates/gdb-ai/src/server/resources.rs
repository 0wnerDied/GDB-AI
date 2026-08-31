use std::sync::atomic::AtomicU64;

use gdb_ai_core::{
    gateway::{Caller, Gateway},
    protocol::CanonicalMethod,
};
use serde_json::{Value, json};

use super::{ErrorCodeName, RpcFault, canonical_request, core_fault};

pub(super) async fn list_resources(gateway: &Gateway, caller: &Caller) -> Result<Value, RpcFault> {
    let resources = gateway
        .list_session_ids(caller)
        .map_err(|error| core_fault(error.code.code_name(), error.message))?
        .into_iter()
        .map(|id| {
            json!({
                "uri": format!("gdbai://session/{id}/status"),
                "name": format!("Session {id} status"),
                "mimeType": "application/json"
            })
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
            "name": "MI transcript manifest",
            "mimeType": "application/vnd.gdb-ai.transcript-manifest+json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/transcript?offset={offset}&length={length}",
            "name": "Exact MI transcript range",
            "mimeType": "application/x-ndjson"
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
            "name": "Session PTY output manifest",
            "mimeType": "application/vnd.gdb-ai.output-manifest+json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/output/pty?offset={offset}&length={length}",
            "name": "Exact session PTY output range",
            "mimeType": "application/octet-stream"
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

#[derive(Clone, Copy, Debug, PartialEq)]
struct ExactRange {
    offset: u64,
    length: u64,
}

#[derive(Debug, PartialEq)]
enum SessionResource {
    Json {
        method: CanonicalMethod,
        parameters: Value,
    },
    TranscriptManifest,
    TranscriptRange(ExactRange),
    PtyManifest,
    PtyRange(ExactRange),
}

fn resource_not_found() -> RpcFault {
    // 2026-08-31: Returning an arbitrary rejected URI duplicated nearly the
    // full inbound MCP message. The caller already has the requested URI.
    RpcFault {
        code: -32002,
        message: "resource not found".into(),
        data: None,
    }
}

fn parse_exact_range(query: &str, name: &str) -> Result<ExactRange, RpcFault> {
    let (offset, length) = query
        .strip_prefix("offset=")
        .and_then(|query| query.split_once("&length="))
        .ok_or_else(|| RpcFault::invalid(format!("{name} range requires offset and length")))?;
    let offset = offset
        .parse::<u64>()
        .ok()
        .filter(|value| value.to_string() == offset)
        .ok_or_else(|| RpcFault::invalid(format!("{name} range offset is invalid")))?;
    let length = length
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == length)
        .ok_or_else(|| RpcFault::invalid(format!("{name} range length is invalid")))?;
    Ok(ExactRange { offset, length })
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
    let ExactRange { offset, length } = parse_exact_range(query, "artifact")?;
    Ok(ArtifactResource::Range {
        uri: uri.to_owned(),
        artifact_uri: artifact_uri.to_owned(),
        digest,
        offset,
        length,
    })
}

fn parse_session_resource(uri: &str) -> Result<(String, SessionResource), RpcFault> {
    let (base_uri, query) = match uri.split_once('?') {
        Some(parts) => (parts.0, Some(parts.1)),
        None => (uri, None),
    };
    let path = base_uri
        .strip_prefix("gdbai://session/")
        .ok_or_else(resource_not_found)?;
    let parts = path.split('/').collect::<Vec<_>>();
    let session = parts
        .first()
        .copied()
        .filter(|id| !id.is_empty())
        .ok_or_else(resource_not_found)?
        .to_owned();
    let resource = match (parts.as_slice(), query) {
        ([_, "status"] | [_, "events"], None) => SessionResource::Json {
            method: CanonicalMethod::SessionGet,
            parameters: json!({}),
        },
        ([_, "capabilities"], None) => SessionResource::Json {
            method: CanonicalMethod::SessionCapabilities,
            parameters: json!({}),
        },
        ([_, "transcript"], None) => SessionResource::TranscriptManifest,
        ([_, "transcript"], Some(query)) => {
            SessionResource::TranscriptRange(parse_exact_range(query, "transcript")?)
        }
        ([_, "event", event_seq], None) => SessionResource::Json {
            method: CanonicalMethod::SessionEvent,
            parameters: json!({
                "event_seq": event_seq
                    .parse::<u64>()
                    .map_err(|_| RpcFault::invalid("invalid event sequence"))?
            }),
        },
        ([_, "breakpoints"], None) => SessionResource::Json {
            method: CanonicalMethod::BreakpointList,
            parameters: json!({}),
        },
        ([_, "snapshot", snapshot_id], None) => SessionResource::Json {
            method: CanonicalMethod::InspectionSnapshotGet,
            parameters: json!({"snapshot_id": snapshot_id}),
        },
        ([_, "output", "pty"], None) => SessionResource::PtyManifest,
        ([_, "output", "pty"], Some(query)) => {
            SessionResource::PtyRange(parse_exact_range(query, "PTY output")?)
        }
        _ => return Err(resource_not_found()),
    };
    Ok((session, resource))
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

fn session_resource_request(
    resource: &SessionResource,
) -> Result<(CanonicalMethod, Value), RpcFault> {
    let bounded_range = |range: ExactRange| {
        if range.length > 64 * 1024 {
            Err(RpcFault::invalid("session resource range exceeds 64 KiB"))
        } else {
            Ok(range)
        }
    };
    match resource {
        SessionResource::Json { method, parameters } => Ok((*method, parameters.clone())),
        SessionResource::TranscriptManifest => Ok((
            CanonicalMethod::SessionTranscript,
            json!({"offset": 0, "max_bytes": 1}),
        )),
        SessionResource::TranscriptRange(range) => {
            let range = bounded_range(*range)?;
            Ok((
                CanonicalMethod::SessionTranscript,
                json!({"offset": range.offset, "max_bytes": range.length}),
            ))
        }
        SessionResource::PtyManifest => Ok((
            CanonicalMethod::InferiorIoRead,
            json!({"stream": "pty", "after_offset": u64::MAX, "max_bytes": 0}),
        )),
        SessionResource::PtyRange(range) => {
            let range = bounded_range(*range)?;
            Ok((
                CanonicalMethod::InferiorIoRead,
                json!({
                    "stream": "pty",
                    "after_offset": range.offset,
                    "max_bytes": range.length
                }),
            ))
        }
    }
}

fn session_resource_contents(
    uri: &str,
    resource: SessionResource,
    result: Value,
) -> Result<Value, RpcFault> {
    let manifest = |mime_type: &str, body: Value| -> Result<Value, RpcFault> {
        Ok(json!({"contents": [{
            "uri": uri,
            "mimeType": mime_type,
            "text": serde_json::to_string(&body)
                .map_err(|error| RpcFault::invalid(error.to_string()))?
        }]}))
    };
    let exact_content = |mime_type: &str,
                         range: ExactRange,
                         requested_offset: Option<u64>,
                         next_offset: Option<u64>,
                         gap: bool,
                         available_from: Option<u64>|
     -> Result<Value, RpcFault> {
        let end = range
            .offset
            .checked_add(range.length)
            .ok_or_else(|| RpcFault::invalid("session resource range overflows"))?;
        if requested_offset != Some(range.offset)
            || next_offset != Some(end)
            || gap
            || available_from.is_some_and(|available| available > range.offset)
        {
            return Err(RpcFault::invalid(
                "session resource did not contain the exact requested range",
            ));
        }
        let mut content = json!({
            "uri": uri,
            "mimeType": mime_type,
            "_meta": {"offset": range.offset, "length": range.length}
        });
        if let Some(blob) = result.get("data_base64").and_then(Value::as_str) {
            content["blob"] = Value::String(blob.to_owned());
        } else if let Some(text) = result.get("text").and_then(Value::as_str) {
            // 2026-08-31: UTF-8 ranges were needlessly base64-encoded again
            // after core had selected their lossless text representation.
            content["text"] = Value::String(text.to_owned());
        } else {
            return Err(RpcFault::invalid("session resource contained no data"));
        }
        Ok(json!({"contents": [content]}))
    };

    match resource {
        SessionResource::Json { .. } => manifest("application/json", result),
        SessionResource::TranscriptManifest => {
            let size = result
                .get("total_bytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| RpcFault::invalid("transcript response contained no size"))?;
            manifest(
                "application/vnd.gdb-ai.transcript-manifest+json",
                json!({
                    "uri": uri,
                    "size": size,
                    "mime_type": "application/x-ndjson",
                    "page_size": 64 * 1024,
                    "range_uri_template": format!("{uri}?offset={{offset}}&length={{length}}")
                }),
            )
        }
        SessionResource::TranscriptRange(range) => exact_content(
            "application/x-ndjson",
            range,
            result.get("offset").and_then(Value::as_u64),
            result.get("next_offset").and_then(Value::as_u64),
            false,
            None,
        ),
        SessionResource::PtyManifest => {
            let available_from = result
                .get("available_from")
                .and_then(Value::as_u64)
                .ok_or_else(|| RpcFault::invalid("PTY response contained no lower bound"))?;
            let end_offset = result
                .get("next_offset")
                .and_then(Value::as_u64)
                .ok_or_else(|| RpcFault::invalid("PTY response contained no upper bound"))?;
            manifest(
                "application/vnd.gdb-ai.output-manifest+json",
                json!({
                    "uri": uri,
                    "available_from": available_from,
                    "end_offset": end_offset,
                    "mime_type": "application/octet-stream",
                    "page_size": 64 * 1024,
                    "range_uri_template": format!("{uri}?offset={{offset}}&length={{length}}"),
                    "evidence": result.get("evidence").cloned().unwrap_or(Value::Null)
                }),
            )
        }
        SessionResource::PtyRange(range) => exact_content(
            "application/octet-stream",
            range,
            result.get("requested_offset").and_then(Value::as_u64),
            result.get("next_offset").and_then(Value::as_u64),
            result.get("gap").and_then(Value::as_bool) != Some(false),
            result.get("available_from").and_then(Value::as_u64),
        ),
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
    let (session, resource) = parse_session_resource(uri)?;
    let (method, parameters) = session_resource_request(&resource)?;
    let response = gateway
        .dispatch(
            canonical_request(sequence, Some(session), method, parameters),
            caller,
        )
        .await;
    if let Some(error) = response.error {
        return Err(core_fault(error.code.code_name(), error.message));
    }
    // 2026-08-29: Session resources returned paged bytes under a base URI,
    // leaving clients unable to name or verify the next page. Base URIs now
    // describe current bounds and range URIs return only exact bytes.
    session_resource_contents(uri, resource, response.result.unwrap_or(Value::Null))
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
        assert!(templates.contains("output/pty?offset={offset}&length={length}"));
        assert!(templates.contains("transcript?offset={offset}&length={length}"));
        assert!(!templates.contains("/inferior/{inferior_id}/output"));
    }

    #[test]
    fn resource_errors_do_not_echo_rejected_uris() {
        assert!(resource_not_found().data.is_none());
    }

    #[test]
    fn session_resources_are_manifests_or_exact_ranges() {
        let transcript = "gdbai://session/sess_test/transcript";
        let (_, resource) = parse_session_resource(transcript).unwrap();
        let manifest = session_resource_contents(
            transcript,
            resource,
            json!({"total_bytes": 8, "offset": 0, "next_offset": 1}),
        )
        .unwrap();
        let manifest: Value =
            serde_json::from_str(manifest["contents"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(manifest["size"], 8);

        let transcript_range = format!("{transcript}?offset=4&length=4");
        let (_, resource) = parse_session_resource(&transcript_range).unwrap();
        let range = session_resource_contents(
            &transcript_range,
            resource,
            json!({"offset": 4, "next_offset": 8, "data_base64": "BAUGBw=="}),
        )
        .unwrap();
        assert_eq!(range["contents"][0]["uri"], transcript_range);
        assert_eq!(range["contents"][0]["blob"], "BAUGBw==");

        let text_range = format!("{transcript}?offset=0&length=4");
        let (_, resource) = parse_session_resource(&text_range).unwrap();
        let range = session_resource_contents(
            &text_range,
            resource,
            json!({"offset": 0, "next_offset": 4, "text": "ABCD"}),
        )
        .unwrap();
        assert_eq!(range["contents"][0]["text"], "ABCD");
        assert!(range["contents"][0].get("blob").is_none());

        let pty_range = "gdbai://session/sess_test/output/pty?offset=4&length=4";
        let (_, resource) = parse_session_resource(pty_range).unwrap();
        assert!(
            session_resource_contents(
                pty_range,
                resource,
                json!({
                    "requested_offset": 4,
                    "available_from": 5,
                    "next_offset": 8,
                    "gap": true,
                    "data_base64": "BAUGBw=="
                }),
            )
            .is_err()
        );
    }
}
