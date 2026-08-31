use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore};

use crate::{
    Error, ErrorCode, Result,
    artifact::ArtifactStore,
    config::Config,
    domain::{Address, SessionState, TargetOrigin, WriteLease},
    metrics::Metrics,
    persistence::{ArtifactLimits, StorageLock, Store, prune_retained_sessions},
    policy::{Effect, Profile, effect_for_method},
    protocol::{API_VERSION, ApiRequest, ApiResponse, Warning},
    session::SessionHandle,
};

mod operation;
mod operations;

use operation::OperationRegistry;
pub use operation::{
    OperationTicket, RequestOperationCancellation, RequestOperationRecord, RequestOperationStatus,
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

struct SessionEntry {
    handle: SessionHandle,
    slot: Mutex<Option<OwnedSemaphorePermit>>,
    owner: String,
    target_state: tokio::sync::RwLock<()>,
    mutation: Mutex<()>,
    out_of_band_mutation: Mutex<()>,
    lease: Mutex<Option<WriteLease>>,
    lease_generation: AtomicU64,
}

pub struct Gateway {
    config: Arc<Config>,
    store: Arc<Store>,
    artifacts: ArtifactStore,
    sessions: RwLock<BTreeMap<String, Arc<SessionEntry>>>,
    metrics: Arc<Metrics>,
    idempotency: Mutex<BTreeMap<String, (String, ApiResponse)>>,
    idempotency_locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    rates: Mutex<BTreeMap<String, RateWindow>>,
    session_creation: RwLock<()>,
    session_slots: Arc<Semaphore>,
    shutting_down: AtomicBool,
    operations: OperationRegistry,
    _storage_lock: StorageLock,
}

struct RateWindow {
    started: std::time::Instant,
    requests: u64,
}

impl Gateway {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let max_sessions = config.server.max_sessions;
        let storage_lock = StorageLock::acquire(config.persistence.sqlite.with_extension("lock"))?;
        let store = Arc::new(Store::open_with_storage(
            &config.persistence.sqlite,
            &config.storage,
        )?);
        let artifacts = ArtifactStore::new(&config.artifacts.path)?;
        artifacts.cleanup_temporary_publications()?;
        let metrics = Arc::new(Metrics::default());
        let operation_limit = config
            .storage
            .max_operations_per_session
            .saturating_mul(config.server.max_sessions.max(1));
        let gateway = Self {
            config: Arc::new(config),
            store,
            artifacts,
            sessions: RwLock::new(BTreeMap::new()),
            metrics,
            idempotency: Mutex::new(BTreeMap::new()),
            idempotency_locks: Mutex::new(BTreeMap::new()),
            rates: Mutex::new(BTreeMap::new()),
            session_creation: RwLock::new(()),
            session_slots: Arc::new(Semaphore::new(max_sessions)),
            shutting_down: AtomicBool::new(false),
            operations: OperationRegistry::new(operation_limit),
            _storage_lock: storage_lock,
        };
        gateway.maintain_storage(&BTreeSet::new())?;
        Ok(gateway)
    }

    pub fn list_session_ids(&self, caller: &Caller) -> Result<Vec<String>> {
        // 2026-08-31: MCP resource discovery loaded and serialized complete
        // session states, so a large breakpoint registry became an artifact
        // and was then reported as an empty resource list. Query IDs directly.
        Ok(self
            .store
            .list_session_id_owners()?
            .into_iter()
            .filter(|(_, owner)| {
                caller.admin
                    || owner
                        .as_deref()
                        .is_some_and(|owner| same_principal(owner, &caller.identity))
            })
            .map(|(id, _)| id)
            .collect())
    }

    pub async fn dispatch(&self, request: ApiRequest, caller: &Caller) -> ApiResponse {
        self.dispatch_inner(request, caller, false).await
    }

    pub(super) async fn dispatch_admitted(
        &self,
        request: ApiRequest,
        caller: &Caller,
    ) -> ApiResponse {
        self.dispatch_inner(request, caller, true).await
    }

    async fn dispatch_inner(
        &self,
        request: ApiRequest,
        caller: &Caller,
        admitted: bool,
    ) -> ApiResponse {
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
                    if let Some(lock) = &retry_lock {
                        self.release_idempotency_lock(key, lock).await;
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
                        if let Some(lock) = &retry_lock {
                            self.release_idempotency_lock(key, lock).await;
                        }
                        return ApiResponse::failure(&request, error, state);
                    }
                },
            };
            if let Some(cached) = cached {
                drop(retry_guard);
                if let Some(lock) = &retry_lock {
                    self.release_idempotency_lock(key, lock).await;
                }
                return cached;
            }
        }
        // 2026-08-30: Successful requests already return their post-operation
        // state. Retain the cheap session entry and clone state only on error
        // instead of copying growing registries before every Agent request.
        let initial_entry = self.entry_for_request(&request).await;
        let result = self.dispatch_checked(&request, caller, admitted).await;
        let mut response = match result {
            Ok((state, result, warnings)) => {
                let mut response = ApiResponse::success(&request, state, result);
                response.warnings.extend(warnings);
                response
            }
            Err(error) => {
                // 2026-08-28: Commands can fail after an async stop, GDB exit,
                // or consistency transition. Return the post-failure state,
                // not the snapshot captured before dispatch.
                let state = self
                    .entry_for_request(&request)
                    .await
                    .map(|entry| entry.handle.state())
                    .or_else(|| initial_entry.map(|entry| entry.handle.state()));
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
        if let (Some(key), Some(lock)) = (retry_key, retry_lock) {
            self.release_idempotency_lock(&key, &lock).await;
        }
        tracing::debug!(
            method = %request.method,
            revision = response.revision,
            error = ?response.error.as_ref().map(|error| error.code),
            "canonical response"
        );
        response
    }

    async fn release_idempotency_lock(&self, key: &str, candidate: &Arc<Mutex<()>>) {
        // 2026-08-30: Checking Arc ownership before locking the registry let
        // a waiter clone the old lock before removal, then a new request create
        // a second lock for the same key. Check identity and ownership atomically.
        let mut locks = self.idempotency_locks.lock().await;
        if locks.get(key).is_some_and(|current| {
            Arc::ptr_eq(current, candidate) && Arc::strong_count(current) == 2
        }) {
            locks.remove(key);
        }
    }

    async fn dispatch_checked(
        &self,
        request: &ApiRequest,
        caller: &Caller,
        admitted: bool,
    ) -> Result<(Option<crate::domain::SessionState>, Value, Vec<Warning>)> {
        // 2026-08-30: Canonical MCP operations are fully validated before
        // admission. Avoid repeating schema and request-size traversal when
        // their Gateway-owned task dispatches the same immutable request.
        if !admitted {
            self.validate_request(request)?;
        }
        self.check_rate(&caller.identity).await?;

        let mut effect = effect_for_method(request.method);
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
                    entry
                        .as_ref()
                        .map(|entry| entry.handle.with_state(|state| state.revision)),
                    &serde_json::to_value(request)?,
                    "denied",
                )?;
                return Err(Error::new(
                    ErrorCode::PolicyDenied,
                    "session belongs to another principal",
                ));
            }
        }
        if let Some(entry) = &entry
            && matches!(
                request.method,
                crate::protocol::CanonicalMethod::MemoryRead
                    | crate::protocol::CanonicalMethod::MemorySearch
                    | crate::protocol::CanonicalMethod::MemoryCompare
            )
        {
            // 2026-08-29: The caller-controlled `volatile` flag previously
            // decided whether a read might mutate a remote device. Classify
            // the target range here and use the flag only as acknowledgement.
            let range_effect = classify_memory_range(&entry.handle.state(), request)?;
            if range_effect != MemoryRangeEffect::Ordinary {
                effect = Effect::VolatileTargetRead;
                let acknowledged = request
                    .parameters
                    .get("acknowledge_target_effects")
                    .or_else(|| request.parameters.get("volatile"))
                    .and_then(Value::as_bool)
                    == Some(true);
                if !acknowledged {
                    self.store.audit(
                        &caller.identity,
                        Some(entry.handle.id()),
                        &request.method,
                        effect,
                        false,
                        Some(entry.handle.with_state(|state| state.revision)),
                        &serde_json::to_value(request)?,
                        "denied",
                    )?;
                    return Err(Error::new(
                        ErrorCode::PolicyDenied,
                        format!(
                            "{} memory range requires acknowledge_target_effects=true",
                            range_effect.as_str()
                        ),
                    ));
                }
            }
        }
        // 2026-08-30: Persisting ordinary observations to two SQLite audit
        // tables added six retention statements to every Agent read. Their
        // evidence remains in the session journal; state-changing and volatile
        // operations retain durable admission and completion audit records.
        let durable_audit = effect != Effect::Read;
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
                entry
                    .as_ref()
                    .map(|entry| entry.handle.with_state(|state| state.revision)),
                &serde_json::to_value(request)?,
                "denied",
            )?;
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "raw_admin requires an authenticated administrative caller",
            ));
        }
        if let Err(error) = profile.authorize_method(request.method, effect) {
            // 2026-08-28: Policy denials previously returned before audit.
            // Persist the denied decision so rejected mutations remain traceable.
            self.store.audit(
                &caller.identity,
                entry.as_ref().map(|entry| entry.handle.id()),
                &request.method,
                effect,
                false,
                entry
                    .as_ref()
                    .map(|entry| entry.handle.with_state(|state| state.revision)),
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
            || request.method == "session.force_abort"
            || request.method == "session.acquire_write_lease"
            || (request.method == "execution.control"
                && request.parameters.get("action").and_then(Value::as_str) == Some("interrupt"));
        // 2026-08-28: Composite reads previously released the actor between MI
        // commands, allowing continue to mix multiple stops in one response.
        // Normal mutations exclude stable observations; control remains preemptive.
        let stable_observation =
            effect == Effect::Read && requires_stable_target(&request.method) && !out_of_band;
        let _target_observation_guard = match &entry {
            Some(entry) if stable_observation => Some(entry.target_state.read().await),
            _ => None,
        };
        let _target_mutation_guard = match &entry {
            Some(entry) if effect != Effect::Read && !out_of_band => {
                Some(entry.target_state.write().await)
            }
            _ => None,
        };
        let _mutation_guard = if effect != Effect::Read {
            match &entry {
                Some(entry) if out_of_band => Some(entry.out_of_band_mutation.lock().await),
                Some(entry) => Some(entry.mutation.lock().await),
                None => None,
            }
        } else {
            None
        };
        // 2026-08-28: Stable reads for an unknown or closed session reached
        // this point without a registry entry and panicked before returning
        // NOT_FOUND. Only capture a baseline when a live entry exists.
        let observation_baseline = match (&entry, stable_observation) {
            (Some(entry), true) => {
                let state = entry.handle.state();
                Some((state.stop_id, state.execution_epoch))
            }
            _ => None,
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
            // 2026-08-29: Automatic reconciliation ran before lease recovery
            // and termination, so an unresponsive backend could prevent the
            // owner from regaining authority or releasing session resources.
            if state.reconciliation_required
                && !matches!(
                    request.method,
                    crate::protocol::CanonicalMethod::SessionClose
                        | crate::protocol::CanonicalMethod::SessionForceAbort
                        | crate::protocol::CanonicalMethod::SessionAcquireWriteLease
                        | crate::protocol::CanonicalMethod::SessionAttemptRecovery
                )
            {
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
                        | "session.force_abort"
                        | "session.acquire_write_lease"
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

        // 2026-08-30: Ordinary reads only need one journal representation.
        // Move it into the worker instead of cloning the complete request;
        // mutations retain one copy for durable audit.
        let mut request_value = (entry.is_some() || durable_audit)
            .then(|| serde_json::to_value(request))
            .transpose()?;
        if let Some(entry) = &entry {
            let journal_request = if durable_audit {
                request_value.as_ref().unwrap().clone()
            } else {
                request_value.take().unwrap()
            };
            entry.handle.record_api(journal_request).await?;
        }
        if durable_audit {
            self.store.audit(
                &caller.identity,
                entry.as_ref().map(|entry| entry.handle.id()),
                &request.method,
                effect,
                true,
                entry
                    .as_ref()
                    .map(|entry| entry.handle.with_state(|state| state.revision)),
                request_value.as_ref().unwrap(),
                "accepted",
            )?;
        }

        let mut result = self.execute_method(request, caller).await;
        if result.is_ok()
            && let (Some(entry), Some((stop_id, execution_epoch))) = (&entry, observation_baseline)
        {
            let current = entry.handle.state();
            if current.stop_id != stop_id || current.execution_epoch != execution_epoch {
                result = Err(Error::new(
                    ErrorCode::StaleContext,
                    "target stop changed during observation",
                ));
            }
        }
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
        let mut warnings = Vec::new();
        if let Some(entry) = &completed_entry
            && durable_audit
        {
            let outcome = if result.is_ok() {
                "completed"
            } else {
                "failed"
            };
            // 2026-08-30: A post-effect audit failure replaced an already
            // executed mutation with INTERNAL, encouraging an unsafe retry.
            // Admission audit remains fail-closed; completion gaps are explicit.
            if let Err(error) = self.store.audit(
                &caller.identity,
                Some(entry.handle.id()),
                &request.method,
                effect,
                result.is_ok(),
                Some(entry.handle.with_state(|state| state.revision)),
                request_value.as_ref().unwrap(),
                outcome,
            ) {
                tracing::error!(%error, method = %request.method, "completion audit failed");
                if result.is_ok() {
                    warnings.push(Warning {
                        code: "AUDIT_COMPLETION_FAILED".into(),
                        message: error.to_string(),
                    });
                }
            }
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
            if let Err(error) =
                self.store
                    .audit_result(Some(entry.handle.id()), &request.method, &audit_result)
            {
                tracing::error!(%error, method = %request.method, "result audit failed");
                if result.is_ok() {
                    warnings.push(Warning {
                        code: "AUDIT_RESULT_FAILED".into(),
                        message: error.to_string(),
                    });
                }
            }
        }
        let result = result?;
        let state = completed_entry.map(|entry| entry.handle.state());
        Ok((state, result, warnings))
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
        // 2026-08-28: Session-scoped methods accepted a missing session ID,
        // allowing later stable-observation setup to dereference no session.
        if request.method.requires_session() && request.session_id.is_none() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "method requires session_id",
            ));
        }
        // 2026-08-28: The envelope schema accepted arbitrary method
        // parameters, so misspelled or wrong-typed mutation fields were
        // silently ignored by handlers that read serde_json::Value directly.
        request.method.validate_parameters(&request.parameters)?;
        if let Some(session_id) = &request.session_id {
            crate::domain::SessionId::parse(session_id)?;
        }
        // 2026-08-30: HTTP, stdio, and Unix reject wire messages above 1 MiB
        // before deserialization. Re-serializing the owned request here
        // doubled work without reducing memory or expanding that boundary.
        Ok(())
    }

    async fn check_rate(&self, identity: &str) -> Result<()> {
        let mut rates = self.rates.lock().await;
        let identity = principal_identity(identity);
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
        // 2026-08-29: Recovery and forced cleanup reused the expiring business
        // lease, leaving an owner unable to govern a LOST session. Ownership
        // is already enforced at the shared Gateway boundary.
        if matches!(
            request.method,
            crate::protocol::CanonicalMethod::SessionForceAbort
                | crate::protocol::CanonicalMethod::SessionAttemptRecovery
        ) {
            return Ok(());
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

    async fn entry(&self, session_id: &str) -> Result<Arc<SessionEntry>> {
        self.sessions
            .read()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "session not found"))
    }

    // 2026-08-31: Actor-scoped close cancellation stopped GDB without
    // releasing its registry entry, lease, or max-session slot. Every path
    // that closes the actor must share the same post-shutdown retirement.
    async fn retire_session(&self, session_id: &str, entry: &Arc<SessionEntry>) -> Option<String> {
        // 2026-08-30: Metadata cleanup failure must not retain a terminated
        // process in the live registry.
        let lease_warning = self
            .store
            .delete_lease(entry.handle.id())
            .err()
            .map(|error| error.to_string());
        let (retired, live_sessions) = {
            let mut sessions = self.sessions.write().await;
            let retired = sessions
                .get(session_id)
                .is_some_and(|current| Arc::ptr_eq(current, entry));
            if retired {
                sessions.remove(session_id);
            }
            (retired, sessions.keys().cloned().collect())
        };
        // 2026-08-31: In-flight requests can retain SessionEntry clones after
        // retirement. Release capacity here instead of waiting for the last
        // unrelated request to drop its Arc.
        if retired {
            entry.slot.lock().await.take();
        }
        if let Err(error) = self.maintain_storage(&live_sessions) {
            tracing::warn!(%error, "closed session retention failed");
        }
        lease_warning
    }

    pub async fn shutdown(&self) {
        // 2026-08-30: Shutdown could drain an empty registry while an in-flight
        // create later inserted a live GDB. Close admission first, then share
        // the creation gate so every previously admitted session is drained.
        self.shutting_down.store(true, Ordering::Release);
        let _creation = self.session_creation.write().await;
        let sessions = std::mem::take(&mut *self.sessions.write().await);
        for entry in sessions.into_values() {
            let _ = entry.handle.close().await;
        }
    }

    fn maintain_storage(&self, live_sessions: &BTreeSet<String>) -> Result<()> {
        // 2026-08-29: Per-session journal limits did not bound the number of
        // retained session directories after daemon restarts. Apply the same
        // age/count policy at startup and normal lifecycle boundaries.
        let (sessions, _) = prune_retained_sessions(
            &self.store,
            &self.artifacts,
            &self.config.persistence.sessions,
            now_unix_ms().min(i64::MAX as u64) as i64,
            self.config.storage.closed_session_retention_ms,
            self.config.storage.max_closed_sessions,
            live_sessions,
        )?;
        if sessions > 0 {
            self.store.checkpoint_wal()?;
        }
        self.refresh_artifact_storage_metric();
        Ok(())
    }

    fn refresh_artifact_storage_metric(&self) {
        // 2026-08-29: Quotas failed safely but operators could not observe the
        // managed store approaching its hard cap. Metrics must not change the
        // result of an otherwise successful storage operation.
        if let Ok(stored) = self.store.total_artifact_bytes() {
            self.metrics
                .artifact_storage(stored, self.config.limits.total_artifact_bytes);
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
            response.continuation = None;
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
            // 2026-08-30: Artifact publication failure retained the original
            // artifact list, so the fallback envelope could still exceed the
            // configured response bound and did not disclose truncation.
            response.result = None;
            response.state = None;
            response.warnings.clear();
            response.evidence.clear();
            response.continuation = None;
            response.artifacts.clear();
            response.truncated = true;
            response.error = Some(crate::protocol::ApiError {
                code: ErrorCode::OutputLimit,
                message: "response exceeded inline limit and artifact creation failed".into(),
                retryable: false,
                details: None,
            });
        }
    }

    fn put_artifact(
        &self,
        session_id: Option<&crate::domain::SessionId>,
        bytes: &[u8],
        sensitivity: &str,
    ) -> Result<String> {
        let uri = self.store.put_artifact(
            &self.artifacts,
            bytes,
            session_id,
            sensitivity,
            ArtifactLimits {
                session_bytes: self.config.limits.session_artifact_bytes,
                owner_bytes: self.config.limits.owner_artifact_bytes,
                total_bytes: self.config.limits.total_artifact_bytes,
            },
        )?;
        self.metrics.artifact_written(bytes.len());
        self.refresh_artifact_storage_metric();
        Ok(uri)
    }

    pub fn metrics(&self) -> String {
        let (verification_hits, verification_misses) = self.artifacts.verification_counts();
        format!(
            "{}gdbai_artifact_verification_cache_hits_total {verification_hits}\n\
             gdbai_artifact_verification_cache_misses_total {verification_misses}\n",
            self.metrics.render()
        )
    }
}

fn request_allowed_during_unknown_outcome(request: &ApiRequest) -> bool {
    matches!(
        request.method.as_str(),
        "session.get"
            | "session.transcript"
            | "session.event"
            | "session.close"
            | "session.force_abort"
            | "session.acquire_write_lease"
            | "session.attempt_recovery"
            | "artifact.get"
    ) || (request.method == "execution.control"
        && request.parameters.get("action").and_then(Value::as_str) == Some("interrupt"))
}

fn requires_stable_target(method: &str) -> bool {
    matches!(
        method,
        "inspection.get"
            | "inspection.snapshot"
            | "inspection.batch"
            | "value.evaluate"
            | "value.create"
            | "value.children"
            | "value.update"
            | "memory.read"
            | "memory.search"
            | "memory.compare"
            | "register.read"
            | "disassembly.read"
            | "agent.hypothesis_check"
            | "kernel.inspect"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryRangeEffect {
    Ordinary,
    Volatile,
    Unknown,
}

impl MemoryRangeEffect {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Volatile => "volatile",
            Self::Unknown => "unknown-effect",
        }
    }
}

fn classify_memory_range(state: &SessionState, request: &ApiRequest) -> Result<MemoryRangeEffect> {
    let address_field = if request.method == crate::protocol::CanonicalMethod::MemorySearch {
        "start"
    } else {
        "address"
    };
    let address =
        Address::parse(request.parameters[address_field].as_str().ok_or_else(|| {
            Error::new(ErrorCode::InvalidArgument, "memory address is required")
        })?)?;
    let start = u64::from_str_radix(&address.as_str()[2..], 16)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid memory address"))?;
    let length = request.parameters["length"]
        .as_u64()
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "memory length is required"))?;
    // 2026-08-30: Range policy used an unrepresentable exclusive end at the
    // final address and rejected a valid one-byte read before MI validation.
    let last = start
        .checked_add(length.saturating_sub(1))
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "memory range overflows"))?;

    match state.target_origin {
        TargetOrigin::Core => Ok(MemoryRangeEffect::Ordinary),
        TargetOrigin::Remote | TargetOrigin::Unknown => Ok(MemoryRangeEffect::Unknown),
        TargetOrigin::Local | TargetOrigin::Attach => {
            let Some(pid) = state.inferiors.values().find_map(|inferior| inferior.pid) else {
                return Ok(MemoryRangeEffect::Unknown);
            };
            let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
                return Ok(MemoryRangeEffect::Unknown);
            };
            Ok(classify_linux_maps(&maps, start, last))
        }
    }
}

fn classify_linux_maps(maps: &str, start: u64, last: u64) -> MemoryRangeEffect {
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some((map_start, map_end)) = fields.next().and_then(|range| range.split_once('-'))
        else {
            continue;
        };
        let (Ok(map_start), Ok(map_end)) = (
            u64::from_str_radix(map_start, 16),
            u64::from_str_radix(map_end, 16),
        ) else {
            continue;
        };
        if start < map_start || last >= map_end {
            continue;
        }
        let path = fields.nth(4).unwrap_or_default();
        return if path.starts_with("/dev/") {
            MemoryRangeEffect::Volatile
        } else {
            MemoryRangeEffect::Ordinary
        };
    }
    MemoryRangeEffect::Unknown
}

fn idempotency_key(request: &ApiRequest, caller: &Caller) -> String {
    format!(
        "{}:{}:{}:{}",
        principal_identity(&caller.identity),
        request.session_id.as_deref().unwrap_or("global"),
        request.method,
        request.idempotency_key.as_deref().unwrap_or("")
    )
}

#[derive(Serialize)]
struct FingerprintRequest<'a> {
    api_version: &'a str,
    request_id: &'static str,
    session_id: &'a Option<String>,
    method: crate::protocol::CanonicalMethod,
    expected_revision: Option<u64>,
    idempotency_key: Option<&'static str>,
    parameters: &'a Value,
}

// 2026-08-28: A key without a request fingerprint returned an earlier result
// for different parameters. Exclude transport request IDs so real retries match.
fn idempotency_fingerprint(request: &ApiRequest) -> String {
    // 2026-08-30: Cloning the request copied its complete caller-controlled
    // parameter tree. A borrowed view preserves the existing canonical JSON
    // field order and fingerprint while replacing only the excluded fields.
    let canonical = FingerprintRequest {
        api_version: &request.api_version,
        request_id: "",
        session_id: &request.session_id,
        method: request.method,
        expected_revision: request.expected_revision,
        idempotency_key: None,
        parameters: &request.parameters,
    };
    let mut digest = Sha256::new();
    serde_json::to_writer(&mut digest, &canonical).unwrap_or_default();
    format!("{:x}", digest.finalize())
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn same_principal(left: &str, right: &str) -> bool {
    principal_identity(left) == principal_identity(right)
}

fn principal_identity(identity: &str) -> &str {
    // 2026-08-30: MCP clientInfo.name is caller-controlled presentation data.
    // Treating it as authority let one principal reset limits and idempotency.
    identity.split_once("/mcp:").map_or(identity, |part| part.0)
}

#[cfg(test)]
mod tests;
