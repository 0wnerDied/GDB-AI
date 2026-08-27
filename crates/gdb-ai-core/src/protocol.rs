use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, domain::SessionState};

pub const API_VERSION: &str = "gdb.ai/v1";

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ApiRequest {
    pub api_version: String,
    pub request_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    pub method: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub parameters: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiResponse {
    pub api_version: &'static str,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<SessionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    pub warnings: Vec<Warning>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<String>,
    pub artifacts: Vec<String>,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub kind: String,
    pub uri: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiError {
    pub code: crate::ErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl ApiResponse {
    pub fn success(request: &ApiRequest, state: Option<SessionState>, result: Value) -> Self {
        Self {
            api_version: API_VERSION,
            request_id: request.request_id.clone(),
            session_id: request.session_id.clone(),
            revision: state.as_ref().map(|state| state.revision),
            state,
            result: Some(result),
            warnings: Vec::new(),
            truncated: false,
            continuation: None,
            artifacts: Vec::new(),
            evidence: Vec::new(),
            error: None,
        }
    }

    pub fn failure(request: &ApiRequest, error: Error, state: Option<SessionState>) -> Self {
        Self {
            api_version: API_VERSION,
            request_id: request.request_id.clone(),
            session_id: request.session_id.clone(),
            revision: state.as_ref().map(|state| state.revision),
            state,
            result: None,
            warnings: Vec::new(),
            truncated: false,
            continuation: None,
            artifacts: Vec::new(),
            evidence: Vec::new(),
            error: Some(ApiError {
                code: error.code,
                message: error.message,
                retryable: error.retryable,
                details: error.details,
            }),
        }
    }
}
