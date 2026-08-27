use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};

use crate::{
    Error, ErrorCode, Result,
    artifact::ArtifactStore,
    config::Config,
    persistence::Store,
    policy::{Effect, Profile, effect_for_method},
    protocol::{API_VERSION, ApiRequest, ApiResponse},
    session::SessionHandle,
};

#[derive(Clone, Debug)]
pub struct Caller {
    pub identity: String,
    pub admin: bool,
}

impl Caller {
    pub fn local(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            admin: false,
        }
    }
}

pub(crate) struct SessionEntry {
    pub handle: SessionHandle,
    pub owner: String,
    pub mutation: Mutex<()>,
}

pub struct Gateway {
    pub(crate) config: Arc<Config>,
    pub(crate) store: Arc<Store>,
    pub(crate) artifacts: ArtifactStore,
    pub(crate) sessions: RwLock<BTreeMap<String, Arc<SessionEntry>>>,
    idempotency: Mutex<BTreeMap<String, ApiResponse>>,
}

impl Gateway {
    pub fn new(config: Config) -> Result<Self> {
        let store = Arc::new(Store::open(&config.persistence.sqlite)?);
        let artifacts = ArtifactStore::new(&config.artifacts.path)?;
        Ok(Self {
            config: Arc::new(config),
            store,
            artifacts,
            sessions: RwLock::new(BTreeMap::new()),
            idempotency: Mutex::new(BTreeMap::new()),
        })
    }

    pub async fn dispatch(&self, request: ApiRequest, caller: &Caller) -> ApiResponse {
        let state = self
            .entry_for_request(&request)
            .await
            .map(|entry| entry.handle.state());
        let result = self.dispatch_checked(&request, caller).await;
        let mut response = match result {
            Ok((state, result)) => ApiResponse::success(&request, state, result),
            Err(error) => ApiResponse::failure(&request, error, state),
        };
        self.bound_response(&mut response);

        if request.idempotency_key.is_some() && response.error.is_none() {
            let key = idempotency_key(&request, caller);
            let mut cache = self.idempotency.lock().await;
            // ponytail: bounded process-local retry cache; persist it if
            // cross-restart exactly-once execution becomes a measured need.
            if cache.len() >= 1_024 {
                cache.pop_first();
            }
            cache.insert(key, response.clone());
        }
        response
    }

    async fn dispatch_checked(
        &self,
        request: &ApiRequest,
        caller: &Caller,
    ) -> Result<(Option<crate::domain::SessionState>, Value)> {
        self.validate_request(request)?;
        if request.idempotency_key.is_some() {
            let key = idempotency_key(request, caller);
            if let Some(response) = self.idempotency.lock().await.get(&key).cloned() {
                if let Some(error) = response.error {
                    return Err(Error {
                        code: error.code,
                        message: error.message,
                        retryable: error.retryable,
                        details: error.details,
                    });
                }
                return Ok((response.state, response.result.unwrap_or(Value::Null)));
            }
        }

        let effect = effect_for_method(&request.method).ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                format!("unknown canonical method {}", request.method),
            )
        })?;
        let entry = self.entry_for_request(request).await;
        let profile = entry
            .as_ref()
            .map(|entry| entry.handle.profile())
            .unwrap_or(self.config.security.default_profile);
        // 2026-08-28: Selecting a profile must not grant raw authority; the
        // transport has to authenticate and explicitly mark an admin caller.
        if profile == Profile::RawAdmin && !caller.admin {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "raw_admin requires an authenticated administrative caller",
            ));
        }
        profile.authorize(effect)?;

        // 2026-08-28: A continue-and-wait request holds the mutation guard.
        // Keep cancellation and interactive I/O outside it while the target
        // runs.
        let out_of_band = request.method.starts_with("inferior_io.")
            || (request.method == "execution.control"
                && request.parameters.get("action").and_then(Value::as_str) == Some("interrupt"));
        let _mutation_guard = if effect != Effect::Read && !out_of_band {
            match &entry {
                Some(entry) => Some(entry.mutation.lock().await),
                None => None,
            }
        } else {
            None
        };
        if let Some(entry) = &entry {
            let state = entry.handle.state();
            if matches!(state.consistency, crate::domain::Consistency::Lost)
                && !matches!(
                    request.method.as_str(),
                    "session.get" | "session.close" | "artifact.get"
                )
            {
                return Err(Error::new(
                    ErrorCode::ConsistencyLost,
                    "session consistency is lost; only status, evidence, recovery, or close is allowed",
                ));
            }
            if effect != Effect::Read {
                self.require_mutation_preconditions(request, caller, entry, &state)
                    .await?;
            }
        }

        let request_value = serde_json::to_value(request)?;
        self.store.audit(
            &caller.identity,
            entry.as_ref().map(|entry| entry.handle.id()),
            &request.method,
            effect,
            true,
            entry.as_ref().map(|entry| entry.handle.state().revision),
            &request_value,
            "accepted",
        )?;

        let result = self.execute_method(request, caller).await;
        let completed_entry = match (&entry, result.as_ref()) {
            (Some(entry), _) => Some(entry.clone()),
            (None, Ok(result)) if request.method == "session.create" => {
                match result.get("session_id").and_then(Value::as_str) {
                    Some(id) => self.sessions.read().await.get(id).cloned(),
                    None => None,
                }
            }
            _ => None,
        };
        if let Some(entry) = &completed_entry {
            let outcome = if result.is_ok() {
                "completed"
            } else {
                "failed"
            };
            self.store.audit(
                &caller.identity,
                Some(entry.handle.id()),
                &request.method,
                effect,
                result.is_ok(),
                Some(entry.handle.state().revision),
                &request_value,
                outcome,
            )?;
        }
        let result = result?;
        let state = completed_entry.map(|entry| entry.handle.state());
        Ok((state, result))
    }

    fn validate_request(&self, request: &ApiRequest) -> Result<()> {
        if request.api_version != API_VERSION {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "unsupported api_version {}; expected {API_VERSION}",
                    request.api_version
                ),
            ));
        }
        if request.request_id.is_empty() || request.request_id.len() > 128 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "request_id must contain 1 to 128 bytes",
            ));
        }
        if request.method.len() > 128 {
            return Err(Error::new(ErrorCode::InvalidArgument, "method is too long"));
        }
        Ok(())
    }

    async fn require_mutation_preconditions(
        &self,
        request: &ApiRequest,
        caller: &Caller,
        entry: &SessionEntry,
        state: &crate::domain::SessionState,
    ) -> Result<()> {
        if entry.owner != caller.identity {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "the vertical slice has one process-local writer per session",
            ));
        }
        if let Some(expected) = request.expected_revision {
            state.require_revision(expected)?;
        } else if request
            .parameters
            .get("accept_latest_revision")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(Error::new(
                ErrorCode::StaleRevision,
                "mutation requires expected_revision or accept_latest_revision=true",
            ));
        }
        Ok(())
    }

    pub(crate) async fn entry(&self, session_id: &str) -> Result<Arc<SessionEntry>> {
        self.sessions
            .read()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "session not found"))
    }

    pub async fn shutdown(&self) {
        let sessions = std::mem::take(&mut *self.sessions.write().await);
        for entry in sessions.into_values() {
            let _ = entry.handle.close().await;
        }
    }

    async fn entry_for_request(&self, request: &ApiRequest) -> Option<Arc<SessionEntry>> {
        let id = request.session_id.as_deref()?;
        self.sessions.read().await.get(id).cloned()
    }

    fn bound_response(&self, response: &mut ApiResponse) {
        let Ok(serialized) = serde_json::to_vec(response) else {
            return;
        };
        if serialized.len() <= self.config.limits.tool_response_bytes {
            return;
        }
        if let Ok(uri) = self.artifacts.put(&serialized) {
            response.result = Some(serde_json::json!({
                "artifact": uri,
                "size": serialized.len(),
                "message": "response exceeded inline limit"
            }));
            response.artifacts = vec![uri];
            response.truncated = true;
        } else {
            response.result = None;
            response.error = Some(crate::protocol::ApiError {
                code: ErrorCode::OutputLimit,
                message: "response exceeded inline limit and artifact creation failed".into(),
                retryable: false,
                details: None,
            });
        }
    }
}

fn idempotency_key(request: &ApiRequest, caller: &Caller) -> String {
    format!(
        "{}:{}:{}:{}",
        caller.identity,
        request.session_id.as_deref().unwrap_or("global"),
        request.method,
        request.idempotency_key.as_deref().unwrap_or("")
    )
}
