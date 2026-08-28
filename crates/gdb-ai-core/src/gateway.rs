use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::AtomicU64},
};
use tokio::sync::{Mutex, RwLock};

use crate::{
    Error, ErrorCode, Result,
    artifact::ArtifactStore,
    config::Config,
    domain::WriteLease,
    metrics::Metrics,
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
    pub out_of_band_mutation: Mutex<()>,
    pub lease: Mutex<Option<WriteLease>>,
    pub lease_generation: AtomicU64,
}

pub struct Gateway {
    pub(crate) config: Arc<Config>,
    pub(crate) store: Arc<Store>,
    pub(crate) artifacts: ArtifactStore,
    pub(crate) sessions: RwLock<BTreeMap<String, Arc<SessionEntry>>>,
    pub(crate) metrics: Arc<Metrics>,
    idempotency: Mutex<BTreeMap<String, (String, ApiResponse)>>,
    idempotency_locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    rates: Mutex<BTreeMap<String, RateWindow>>,
}

struct RateWindow {
    started: std::time::Instant,
    requests: u64,
}

impl Gateway {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let store = Arc::new(Store::open(&config.persistence.sqlite)?);
        let artifacts = ArtifactStore::new(&config.artifacts.path)?;
        let metrics = Arc::new(Metrics::default());
        Ok(Self {
            config: Arc::new(config),
            store,
            artifacts,
            sessions: RwLock::new(BTreeMap::new()),
            metrics,
            idempotency: Mutex::new(BTreeMap::new()),
            idempotency_locks: Mutex::new(BTreeMap::new()),
            rates: Mutex::new(BTreeMap::new()),
        })
    }

    pub async fn dispatch(&self, request: ApiRequest, caller: &Caller) -> ApiResponse {
        tracing::debug!(
            caller = %caller.identity,
            method = %request.method,
            session_id = request.session_id.as_deref().unwrap_or("global"),
            request_id = %request.request_id,
            "canonical request"
        );
        // 2026-08-28: Caching only completed responses let concurrent retries
        // execute the same mutation twice. Serialize each live idempotency key.
        let retry_key = request
            .idempotency_key
            .as_ref()
            .map(|_| idempotency_key(&request, caller));
        let retry_hash = retry_key
            .as_ref()
            .map(|_| idempotency_fingerprint(&request));
        let retry_lock = if let Some(key) = &retry_key {
            let mut locks = self.idempotency_locks.lock().await;
            Some(
                locks
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(())))
                    .clone(),
            )
        } else {
            None
        };
        let retry_guard = match &retry_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        if let Some(key) = &retry_key {
            let memory = self.idempotency.lock().await.get(key).cloned();
            let cached = match memory {
                Some((stored_hash, response)) if Some(&stored_hash) == retry_hash.as_ref() => {
                    Some(response)
                }
                Some(_) => {
                    let error = Error::new(
                        ErrorCode::Conflict,
                        "idempotency key was already used with different parameters",
                    );
                    let state = self
                        .entry_for_request(&request)
                        .await
                        .map(|entry| entry.handle.state());
                    drop(retry_guard);
                    if retry_lock
                        .as_ref()
                        .is_some_and(|lock| Arc::strong_count(lock) == 2)
                    {
                        self.idempotency_locks.lock().await.remove(key);
                    }
                    return ApiResponse::failure(&request, error, state);
                }
                None => match self
                    .store
                    .get_idempotent_response(key, retry_hash.as_deref().unwrap_or_default())
                {
                    Ok(response) => response,
                    Err(error) => {
                        let state = self
                            .entry_for_request(&request)
                            .await
                            .map(|entry| entry.handle.state());
                        drop(retry_guard);
                        if retry_lock
                            .as_ref()
                            .is_some_and(|lock| Arc::strong_count(lock) == 2)
                        {
                            self.idempotency_locks.lock().await.remove(key);
                        }
                        return ApiResponse::failure(&request, error, state);
                    }
                },
            };
            if let Some(cached) = cached {
                drop(retry_guard);
                if retry_lock
                    .as_ref()
                    .is_some_and(|lock| Arc::strong_count(lock) == 2)
                {
                    self.idempotency_locks.lock().await.remove(key);
                }
                return cached;
            }
        }
        let state = self
            .entry_for_request(&request)
            .await
            .map(|entry| entry.handle.state());
        let result = self.dispatch_checked(&request, caller).await;
        let mut response = match result {
            Ok((state, result)) => ApiResponse::success(&request, state, result),
            Err(error) => {
                // 2026-08-28: Commands can fail after an async stop, GDB exit,
                // or consistency transition. Return the post-failure state,
                // not the snapshot captured before dispatch.
                let state = self
                    .entry_for_request(&request)
                    .await
                    .map(|entry| entry.handle.state())
                    .or(state);
                ApiResponse::failure(&request, error, state)
            }
        };
        self.bound_response(&request, &mut response);

        if request.idempotency_key.is_some() {
            let key = idempotency_key(&request, caller);
            let request_hash = retry_hash.unwrap_or_else(|| idempotency_fingerprint(&request));
            if let Err(error) = self
                .store
                .put_idempotent_response(&key, &request_hash, &response)
            {
                response.warnings.push(crate::protocol::Warning {
                    code: "IDEMPOTENCY_NOT_DURABLE".into(),
                    message: error.to_string(),
                });
            }
            let mut cache = self.idempotency.lock().await;
            if cache.len() >= 1_024 {
                cache.pop_first();
            }
            cache.insert(key, (request_hash, response.clone()));
        }
        drop(retry_guard);
        if let (Some(key), Some(lock)) = (retry_key, retry_lock)
            && Arc::strong_count(&lock) == 2
        {
            self.idempotency_locks.lock().await.remove(&key);
        }
        tracing::debug!(
            method = %request.method,
            revision = response.revision,
            error = ?response.error.as_ref().map(|error| error.code),
            "canonical response"
        );
        response
    }

    async fn dispatch_checked(
        &self,
        request: &ApiRequest,
        caller: &Caller,
    ) -> Result<(Option<crate::domain::SessionState>, Value)> {
        self.validate_request(request)?;
        self.check_rate(&caller.identity).await?;

        let mut effect = effect_for_method(&request.method).ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                format!("unknown canonical method {}", request.method),
            )
        })?;
        if matches!(
            request.method.as_str(),
            "memory.read" | "memory.search" | "memory.compare"
        ) && request.parameters.get("volatile").and_then(Value::as_bool) == Some(true)
        {
            effect = Effect::VolatileTargetRead;
        }
        let entry = self.entry_for_request(request).await;
        if let Some(session_id) = request
            .session_id
            .as_deref()
            .map(crate::domain::SessionId::parse)
            .transpose()?
        {
            let owner = match &entry {
                Some(entry) => Some(entry.owner.clone()),
                None => self.store.session_owner(&session_id)?,
            };
            let known = entry.is_some() || self.store.get_session(&session_id)?.is_some();
            // 2026-08-28: Session IDs were treated as bearer credentials, so
            // another authenticated principal could inspect session state.
            // Enforce ownership once at the gateway for active and durable data.
            if known
                && !caller.admin
                && owner
                    .as_deref()
                    .is_none_or(|owner| !same_principal(owner, &caller.identity))
            {
                self.store.audit(
                    &caller.identity,
                    Some(&session_id),
                    &request.method,
                    effect,
                    false,
                    entry.as_ref().map(|entry| entry.handle.state().revision),
                    &serde_json::to_value(request)?,
                    "denied",
                )?;
                return Err(Error::new(
                    ErrorCode::PolicyDenied,
                    "session belongs to another principal",
                ));
            }
        }
        let profile = entry
            .as_ref()
            .map(|entry| entry.handle.profile())
            .unwrap_or(self.config.security.default_profile);
        // 2026-08-28: Selecting a profile must not grant raw authority; the
        // transport has to authenticate and explicitly mark an admin caller.
        if profile == Profile::RawAdmin && !caller.admin {
            self.store.audit(
                &caller.identity,
                entry.as_ref().map(|entry| entry.handle.id()),
                &request.method,
                effect,
                false,
                entry.as_ref().map(|entry| entry.handle.state().revision),
                &serde_json::to_value(request)?,
                "denied",
            )?;
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "raw_admin requires an authenticated administrative caller",
            ));
        }
        if let Err(error) = profile.authorize_method(&request.method, effect) {
            // 2026-08-28: Policy denials previously returned before audit.
            // Persist the denied decision so rejected mutations remain traceable.
            self.store.audit(
                &caller.identity,
                entry.as_ref().map(|entry| entry.handle.id()),
                &request.method,
                effect,
                false,
                entry.as_ref().map(|entry| entry.handle.state().revision),
                &serde_json::to_value(request)?,
                "denied",
            )?;
            return Err(error);
        }

        // 2026-08-28: A continue-and-wait request holds the mutation guard.
        // Keep shutdown, cancellation, lease renewal, and interactive I/O
        // outside it while the target runs. Their short-operation lock preserves
        // ordering without waiting behind run control. A lease can expire
        // during a long wait.
        let out_of_band = request.method.starts_with("inferior_io.")
            || request.method == "session.close"
            || request.method == "session.acquire_write_lease"
            || (request.method == "execution.control"
                && request.parameters.get("action").and_then(Value::as_str) == Some("interrupt"));
        let _mutation_guard = if effect != Effect::Read {
            match &entry {
                Some(entry) if out_of_band => Some(entry.out_of_band_mutation.lock().await),
                Some(entry) => Some(entry.mutation.lock().await),
                None => None,
            }
        } else {
            None
        };
        if let Some(entry) = &entry {
            let mut state = entry.handle.state();
            // 2026-08-28: A timed-out MI mutation may still complete later.
            // Expose the fence before reconciliation and admit only recovery-safe
            // status, evidence, interrupt, and close requests while it is active.
            if !state.outcome_unknown_tokens.is_empty()
                && !request_allowed_during_unknown_outcome(request)
            {
                return Err(Error::new(
                    ErrorCode::GdbUnresponsive,
                    format!(
                        "MI command outcome is unknown for token(s) {:?}; interrupt or close the session",
                        state.outcome_unknown_tokens
                    ),
                ));
            }
            // 2026-08-28: TAINTED describes an unknowable outer state, but its
            // managed registries still require one bounded reconciliation.
            if state.reconciliation_required {
                self.reconcile_session(entry, true).await?;
                state = entry.handle.state();
            }
            // 2026-08-28: LOST sessions previously blocked transcript access,
            // removing the evidence needed to diagnose and recover the session.
            if matches!(state.consistency, crate::domain::Consistency::Lost)
                && !matches!(
                    request.method.as_str(),
                    "session.get"
                        | "session.transcript"
                        | "session.event"
                        | "session.close"
                        | "session.attempt_recovery"
                        | "artifact.get"
                )
            {
                return Err(Error::new(
                    ErrorCode::ConsistencyLost,
                    "session consistency is lost; only status, evidence, recovery, or close is allowed",
                ));
            }
            if effect != Effect::Read
                && let Err(error) = self
                    .require_mutation_preconditions(request, caller, entry, &state)
                    .await
            {
                // 2026-08-28: Lease and revision rejections previously
                // bypassed audit even though they are policy decisions.
                self.store.audit(
                    &caller.identity,
                    Some(entry.handle.id()),
                    &request.method,
                    effect,
                    false,
                    Some(state.revision),
                    &serde_json::to_value(request)?,
                    "rejected",
                )?;
                return Err(error);
            }
        }

        let request_value = serde_json::to_value(request)?;
        if let Some(entry) = &entry {
            entry.handle.record_api(request_value.clone()).await?;
        }
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
            let audit_result = match &result {
                Ok(result) => serde_json::json!({ "result": result }),
                Err(error) => serde_json::json!({
                    "error": {
                        "code": error.code,
                        "message": error.message,
                        "retryable": error.retryable
                    }
                }),
            };
            self.store
                .audit_result(Some(entry.handle.id()), &request.method, &audit_result)?;
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
        if request.method.is_empty() || request.method.len() > 128 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "method must contain 1 to 128 bytes",
            ));
        }
        if request
            .idempotency_key
            .as_ref()
            .is_some_and(|key| key.is_empty() || key.len() > 256)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "idempotency_key must contain 1 to 256 bytes",
            ));
        }
        if !request.parameters.is_object() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "parameters must be an object",
            ));
        }
        if let Some(session_id) = &request.session_id {
            crate::domain::SessionId::parse(session_id)?;
        }
        if serde_json::to_vec(request)?.len() > 1024 * 1024 {
            return Err(Error::new(ErrorCode::OutputLimit, "request exceeds 1 MiB"));
        }
        Ok(())
    }

    async fn check_rate(&self, identity: &str) -> Result<()> {
        let mut rates = self.rates.lock().await;
        if rates.len() >= 1_024 && !rates.contains_key(identity) {
            rates.pop_first();
        }
        let now = std::time::Instant::now();
        let window = rates.entry(identity.to_owned()).or_insert(RateWindow {
            started: now,
            requests: 0,
        });
        if now.duration_since(window.started) >= std::time::Duration::from_secs(1) {
            window.started = now;
            window.requests = 0;
        }
        window.requests = window.requests.saturating_add(1);
        let limit = self
            .config
            .server
            .requests_per_second
            .max(1)
            .saturating_add(self.config.server.request_burst);
        if window.requests > limit {
            Err(Error::new(ErrorCode::Conflict, "request rate limit exceeded").retryable())
        } else {
            Ok(())
        }
    }

    async fn require_mutation_preconditions(
        &self,
        request: &ApiRequest,
        caller: &Caller,
        entry: &SessionEntry,
        state: &crate::domain::SessionState,
    ) -> Result<()> {
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
        if request.method == "session.acquire_write_lease" {
            return Ok(());
        }
        let lease_id = request
            .parameters
            .get("lease_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::new(ErrorCode::WriteLeaseRequired, "mutation requires lease_id")
            })?;
        let lease = entry.lease.lock().await;
        let lease = lease.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::WriteLeaseRequired,
                "session has no active write lease",
            )
        })?;
        if lease.is_expired(now_unix_ms()) {
            return Err(Error::new(
                ErrorCode::WriteLeaseExpired,
                "write lease has expired",
            ));
        }
        if lease.lease_id.0 != lease_id || lease.owner != caller.identity {
            return Err(Error::new(
                ErrorCode::WriteLeaseRequired,
                "write lease does not belong to this caller",
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

    fn bound_response(&self, request: &ApiRequest, response: &mut ApiResponse) {
        let Ok(serialized) = serde_json::to_vec(response) else {
            return;
        };
        if serialized.len() <= self.config.limits.tool_response_bytes {
            return;
        }
        let session_id = response
            .session_id
            .as_deref()
            .or(request.session_id.as_deref())
            .and_then(|id| crate::domain::SessionId::parse(id).ok());
        if let Ok(uri) = self.put_artifact(session_id.as_ref(), &serialized, "protocol-response") {
            // 2026-08-28: Replacing only result left a large state or error in
            // the envelope, so the supposedly bounded response still overflowed.
            let was_error = response.error.is_some();
            response.state = None;
            response.warnings.clear();
            response.evidence.clear();
            if was_error {
                response.result = None;
                response.error = Some(crate::protocol::ApiError {
                    code: ErrorCode::OutputLimit,
                    message: "error response exceeded inline limit".into(),
                    retryable: false,
                    details: Some(serde_json::json!({
                        "artifact": uri,
                        "size": serialized.len()
                    })),
                });
            } else {
                response.result = Some(serde_json::json!({
                    "artifact": uri,
                    "size": serialized.len(),
                    "message": "response exceeded inline limit"
                }));
                response.error = None;
            }
            response.artifacts = vec![uri];
            response.truncated = true;
            self.metrics.response_truncated();
        } else {
            response.result = None;
            response.state = None;
            response.warnings.clear();
            response.evidence.clear();
            response.error = Some(crate::protocol::ApiError {
                code: ErrorCode::OutputLimit,
                message: "response exceeded inline limit and artifact creation failed".into(),
                retryable: false,
                details: None,
            });
        }
    }

    pub(crate) fn put_artifact(
        &self,
        session_id: Option<&crate::domain::SessionId>,
        bytes: &[u8],
        sensitivity: &str,
    ) -> Result<String> {
        if let Some(session_id) = session_id {
            let used = self.store.artifact_bytes(session_id)?;
            if used.saturating_add(bytes.len()) > self.config.limits.session_artifact_bytes {
                return Err(Error::new(
                    ErrorCode::OutputLimit,
                    "session artifact quota exceeded",
                ));
            }
        }
        let uri = self.artifacts.put(bytes)?;
        self.store
            .register_artifact(&uri, session_id, bytes.len(), sensitivity)?;
        self.metrics.artifact_written(bytes.len());
        Ok(uri)
    }

    pub fn metrics(&self) -> String {
        self.metrics.render()
    }
}

fn request_allowed_during_unknown_outcome(request: &ApiRequest) -> bool {
    matches!(
        request.method.as_str(),
        "session.get" | "session.transcript" | "session.event" | "session.close" | "artifact.get"
    ) || (request.method == "execution.control"
        && request.parameters.get("action").and_then(Value::as_str) == Some("interrupt"))
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

// 2026-08-28: A key without a request fingerprint returned an earlier result
// for different parameters. Exclude transport request IDs so real retries match.
fn idempotency_fingerprint(request: &ApiRequest) -> String {
    let mut canonical = request.clone();
    canonical.request_id.clear();
    canonical.idempotency_key = None;
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn now_unix_ms() -> u64 {
    std::time::SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

pub(crate) fn same_principal(left: &str, right: &str) -> bool {
    fn principal(identity: &str) -> &str {
        identity.split_once("/mcp:").map_or(identity, |part| part.0)
    }
    principal(left) == principal(right)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;
    use crate::config::{ArtifactConfig, PersistenceConfig};

    #[tokio::test]
    async fn rejects_expired_write_lease_without_interrupting_session() {
        if std::process::Command::new("gdb")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let directory = tempdir().unwrap();
        let mut config = Config {
            artifacts: ArtifactConfig {
                path: directory.path().join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: directory.path().join("state.sqlite"),
                sessions: directory.path().join("sessions"),
            },
            ..Config::default()
        };
        config.server.write_lease_ms = 1;
        let gateway = Gateway::new(config).unwrap();
        let caller = Caller::local("lease-test");
        let created = gateway
            .dispatch(
                ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "create".into(),
                    session_id: None,
                    method: "session.create".into(),
                    expected_revision: None,
                    idempotency_key: None,
                    parameters: json!({}),
                },
                &caller,
            )
            .await;
        let session_id = created.session_id.clone().unwrap();
        let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
            .as_str()
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let rejected = gateway
            .dispatch(
                ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "close".into(),
                    session_id: Some(session_id),
                    method: "session.close".into(),
                    expected_revision: created.revision,
                    idempotency_key: None,
                    parameters: json!({"lease_id": lease_id}),
                },
                &caller,
            )
            .await;
        assert_eq!(rejected.error.unwrap().code, ErrorCode::WriteLeaseExpired);
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn concurrent_idempotent_create_runs_once() {
        if std::process::Command::new("gdb")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let directory = tempdir().unwrap();
        let gateway = Gateway::new(Config {
            artifacts: ArtifactConfig {
                path: directory.path().join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: directory.path().join("state.sqlite"),
                sessions: directory.path().join("sessions"),
            },
            ..Config::default()
        })
        .unwrap();
        let caller = Caller::local("idempotency-test");
        let request = ApiRequest {
            api_version: API_VERSION.into(),
            request_id: "create".into(),
            session_id: None,
            method: "session.create".into(),
            expected_revision: None,
            idempotency_key: Some("same-create".into()),
            parameters: json!({}),
        };
        let (first, second) = tokio::join!(
            gateway.dispatch(request.clone(), &caller),
            gateway.dispatch(request, &caller)
        );
        assert_eq!(first.session_id, second.session_id);
        assert_eq!(gateway.sessions.read().await.len(), 1);
        let conflicting = gateway
            .dispatch(
                ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "changed-retry".into(),
                    session_id: None,
                    method: "session.create".into(),
                    expected_revision: Some(99),
                    idempotency_key: Some("same-create".into()),
                    parameters: json!({}),
                },
                &caller,
            )
            .await;
        assert_eq!(conflicting.error.unwrap().code, ErrorCode::Conflict);
        assert_eq!(gateway.sessions.read().await.len(), 1);
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn isolates_active_and_persisted_sessions_by_principal() {
        if std::process::Command::new("gdb")
            .arg("--version")
            .output()
            .is_err()
        {
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
        let gateway = Gateway::new(config.clone()).unwrap();
        let alice = Caller::local("alice");
        let bob = Caller::local("bob");
        let created = gateway
            .dispatch(
                ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "create-owned".into(),
                    session_id: None,
                    method: "session.create".into(),
                    expected_revision: None,
                    idempotency_key: None,
                    parameters: json!({}),
                },
                &alice,
            )
            .await;
        let session_id = created.session_id.clone().unwrap();
        let read = |request_id: &str| ApiRequest {
            api_version: API_VERSION.into(),
            request_id: request_id.into(),
            session_id: Some(session_id.clone()),
            method: "session.get".into(),
            expected_revision: None,
            idempotency_key: None,
            parameters: json!({}),
        };
        assert_eq!(
            gateway
                .dispatch(read("bob-active"), &bob)
                .await
                .error
                .unwrap()
                .code,
            ErrorCode::PolicyDenied
        );
        gateway.shutdown().await;

        let reopened = Gateway::new(config).unwrap();
        assert!(
            reopened
                .dispatch(read("alice-closed"), &alice)
                .await
                .error
                .is_none()
        );
        let transcript = ApiRequest {
            api_version: API_VERSION.into(),
            request_id: "alice-transcript".into(),
            session_id: Some(session_id.clone()),
            method: "session.transcript".into(),
            expected_revision: None,
            idempotency_key: None,
            parameters: json!({"max_bytes": 1024}),
        };
        assert!(reopened.dispatch(transcript, &alice).await.error.is_none());
        assert_eq!(
            reopened
                .dispatch(read("bob-closed"), &bob)
                .await
                .error
                .unwrap()
                .code,
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn bounds_the_complete_response_envelope() {
        let directory = tempdir().unwrap();
        let mut config = Config {
            artifacts: ArtifactConfig {
                path: directory.path().join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: directory.path().join("state.sqlite"),
                sessions: directory.path().join("sessions"),
            },
            ..Config::default()
        };
        config.limits.tool_response_bytes = 1_024;
        let gateway = Gateway::new(config).unwrap();
        let request = ApiRequest {
            api_version: API_VERSION.into(),
            request_id: "bounded".into(),
            session_id: Some("sess_bound".into()),
            method: "session.get".into(),
            expected_revision: None,
            idempotency_key: None,
            parameters: json!({}),
        };
        let mut state =
            crate::domain::SessionState::creating(crate::domain::SessionId("sess_bound".into()));
        state.limitations = vec!["x".repeat(1_024); 8];
        let mut response = ApiResponse::success(&request, Some(state), json!({"x": "y"}));
        gateway.bound_response(&request, &mut response);
        assert!(serde_json::to_vec(&response).unwrap().len() <= 1_024);
        assert!(response.truncated);
        assert_eq!(response.artifacts.len(), 1);
    }
}
