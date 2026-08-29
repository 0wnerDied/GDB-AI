use serde::Deserialize;
use serde_json::Value;

#[cfg(test)]
use serde_json::json;

use crate::{Error, ErrorCode, Result, protocol::ApiRequest};

#[cfg(test)]
use crate::protocol::CanonicalMethod;

pub(super) fn required_session(request: &ApiRequest) -> Result<&str> {
    request
        .session_id
        .as_deref()
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "method requires session_id"))
}

pub(super) fn parameters<T: for<'de> Deserialize<'de>>(request: &ApiRequest) -> Result<T> {
    let mut parameters = request.parameters.clone();
    // 2026-08-28: Strict operation structs rejected the lease and revision
    // controls that the shared Gateway contract adds to every parameter map.
    // Consume those transport controls before decoding operation-owned fields.
    if let Some(parameters) = parameters.as_object_mut() {
        parameters.remove("lease_id");
        parameters.remove("accept_latest_revision");
    }
    serde_json::from_value(parameters)
        .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))
}

pub(super) fn string(value: &Value, name: &str) -> Result<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, format!("{name} is required")))
}

pub(super) fn unsigned(value: &Value, name: &str) -> Result<u64> {
    value.get(name).and_then(Value::as_u64).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("{name} must be unsigned"),
        )
    })
}

pub(super) fn bool_value(value: &Value, name: &str, default: bool) -> bool {
    value.get(name).and_then(Value::as_bool).unwrap_or(default)
}

pub(super) fn bounded_limit(value: &Value, default: usize, maximum: usize) -> Result<usize> {
    let limit = value
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(default as u64);
    if limit == 0 || limit > maximum as u64 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("limit must be between 1 and {maximum}"),
        ));
    }
    Ok(limit as usize)
}

pub(super) fn bounded_offset(value: &Value, maximum: usize, subject: &str) -> Result<usize> {
    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
    if offset > maximum as u64 {
        return Err(Error::new(
            ErrorCode::OutputLimit,
            format!("{subject} offset must not exceed {maximum}"),
        ));
    }
    Ok(offset as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::operations::lifecycle::StartPolicy;

    #[test]
    fn strict_parameters_ignore_gateway_controls() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StrictParameters {
            stop: StartPolicy,
        }

        let request = ApiRequest {
            api_version: crate::protocol::API_VERSION.into(),
            request_id: "strict-parameters".into(),
            session_id: Some("sess_test".into()),
            method: CanonicalMethod::TargetRestart,
            expected_revision: Some(1),
            idempotency_key: None,
            parameters: json!({
                "stop": "main",
                "lease_id": "lease_test",
                "accept_latest_revision": true
            }),
        };
        let decoded: StrictParameters = parameters(&request).unwrap();
        assert_eq!(decoded.stop.as_str(), "main");
    }
}
