use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock, watch};

use super::{Caller, Gateway, RequestMode, now_unix_ms, same_principal};
use crate::{
    Error, ErrorCode, Result,
    domain::OperationId,
    policy::{Effect, effect_for_method},
    protocol::{ApiRequest, ApiResponse, CanonicalMethod},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestOperationStatus {
    Accepted,
    Running,
    CancelRequested,
    Succeeded,
    Failed,
    OutcomeUnknown,
    Aborted,
}

impl RequestOperationStatus {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::OutcomeUnknown | Self::Aborted
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RequestOperationRecord {
    pub operation_id: OperationId,
    pub session_id: Option<String>,
    pub method: CanonicalMethod,
    pub effect: Effect,
    pub status: RequestOperationStatus,
    pub admitted_revision: Option<u64>,
    pub admitted_execution_epoch: Option<u64>,
    pub waiter_deadline_unix_ms: Option<u64>,
    pub cancellation: RequestOperationCancellation,
    pub waiter_detached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ApiResponse>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OperationTicket {
    pub operation_id: OperationId,
    pub status: RequestOperationStatus,
    pub waitable: bool,
    pub cancellation: RequestOperationCancellation,
    pub waiter_deadline_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestOperationCancellation {
    WaiterOnly,
    ActorScoped,
}

struct OperationEntry {
    owner: String,
    state: watch::Sender<RequestOperationRecord>,
    transition: Mutex<()>,
    cancelled: Arc<AtomicBool>,
    cancellation_applied: AtomicBool,
}

pub(super) struct OperationRegistry {
    entries: RwLock<BTreeMap<String, Arc<OperationEntry>>>,
    maximum: usize,
}

impl OperationRegistry {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            maximum: maximum.max(1),
        }
    }

    async fn insert(
        &self,
        owner: String,
        record: RequestOperationRecord,
    ) -> Result<Arc<OperationEntry>> {
        let mut entries = self.entries.write().await;
        if entries.len() >= self.maximum
            && let Some(completed) = entries
                .iter()
                .find_map(|(id, entry)| entry.state.borrow().status.terminal().then(|| id.clone()))
        {
            entries.remove(&completed);
        }
        if entries.len() >= self.maximum {
            return Err(
                Error::new(ErrorCode::Conflict, "canonical operation registry is full").retryable(),
            );
        }
        let id = record.operation_id.0.clone();
        let (state, _) = watch::channel(record);
        let entry = Arc::new(OperationEntry {
            owner,
            state,
            transition: Mutex::new(()),
            cancelled: Arc::new(AtomicBool::new(false)),
            cancellation_applied: AtomicBool::new(false),
        });
        entries.insert(id, entry.clone());
        Ok(entry)
    }

    async fn entry(&self, operation_id: &str, caller: &Caller) -> Result<Arc<OperationEntry>> {
        let entry = self
            .entries
            .read()
            .await
            .get(operation_id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "operation not found"))?;
        if caller.admin || same_principal(&entry.owner, &caller.identity) {
            Ok(entry)
        } else {
            Err(Error::new(ErrorCode::NotFound, "operation not found"))
        }
    }

    async fn remove_delivered(&self, operation_id: &str, caller: &Caller) -> bool {
        let mut entries = self.entries.write().await;
        let removable = entries.get(operation_id).is_some_and(|entry| {
            (caller.admin || same_principal(&entry.owner, &caller.identity))
                && entry.state.borrow().status.terminal()
                && !entry.state.borrow().waiter_detached
        });
        if removable {
            entries.remove(operation_id);
        }
        removable
    }
}

impl Gateway {
    pub async fn admit_operation(
        self: &Arc<Self>,
        request: ApiRequest,
        caller: Caller,
        waiter_timeout: Option<Duration>,
    ) -> Result<OperationTicket> {
        self.admit_operation_with_mode(request, caller, waiter_timeout, RequestMode::Canonical)
            .await
    }

    pub async fn admit_operation_with_mode(
        self: &Arc<Self>,
        request: ApiRequest,
        caller: Caller,
        waiter_timeout: Option<Duration>,
        mode: RequestMode,
    ) -> Result<OperationTicket> {
        self.validate_request(&request)?;
        let coordination = self.entry_for_request(&request).await.map(|entry| {
            entry
                .handle
                .with_state(|state| (state.revision, state.execution_epoch))
        });
        let operation_id = OperationId::new();
        let waiter_deadline_unix_ms = waiter_timeout.map(|timeout| {
            now_unix_ms().saturating_add(timeout.as_millis().min(u64::MAX as u128) as u64)
        });
        let cancellation = cancellation_for_request(&request);
        let record = RequestOperationRecord {
            operation_id: operation_id.clone(),
            session_id: request.session_id.clone(),
            method: request.method,
            effect: effect_for_method(request.method),
            status: RequestOperationStatus::Accepted,
            admitted_revision: coordination.map(|(revision, _)| revision),
            admitted_execution_epoch: coordination.map(|(_, epoch)| epoch),
            waiter_deadline_unix_ms,
            cancellation,
            waiter_detached: false,
            result: None,
        };
        let entry = self
            .operations
            .insert(caller.identity.clone(), record)
            .await?;
        let ticket = OperationTicket {
            operation_id: operation_id.clone(),
            status: RequestOperationStatus::Accepted,
            waitable: true,
            cancellation,
            waiter_deadline_unix_ms,
        };

        let gateway = self.clone();
        // 2026-08-30: Operation task failure only needs response identity.
        // Do not clone a caller-controlled parameters tree of up to 1 MiB on
        // every successful request for this exceptional path.
        let failure_request = ApiRequest {
            api_version: request.api_version.clone(),
            request_id: request.request_id.clone(),
            session_id: request.session_id.clone(),
            method: request.method,
            expected_revision: None,
            idempotency_key: None,
            parameters: Value::Null,
        };
        let active_operation =
            crate::session::ActiveOperation::new(operation_id, entry.cancelled.clone());
        tokio::spawn(async move {
            {
                // 2026-08-29: Cancellation could win immediately after
                // admission and then be overwritten by an unconditional
                // RUNNING transition. Serialize both state transitions.
                let _transition = entry.transition.lock().await;
                entry.state.send_modify(|record| {
                    if record.status == RequestOperationStatus::Accepted {
                        record.status = RequestOperationStatus::Running;
                    }
                });
            }
            let dispatch = tokio::spawn(crate::session::scope_operation(
                active_operation,
                async move { gateway.dispatch_admitted(request, &caller, mode).await },
            ));
            let response = match dispatch.await {
                Ok(response) => response,
                Err(error) => ApiResponse::failure(
                    &failure_request,
                    Error::new(
                        ErrorCode::Internal,
                        format!("operation task failed: {error}"),
                    ),
                    None,
                ),
            };
            let status = operation_status(&response);
            let _transition = entry.transition.lock().await;
            entry.state.send_modify(|record| {
                // 2026-08-30: A cancellation could lose the race with normal
                // completion yet overwrite a successful result as ABORTED.
                // Only an actor-applied or cooperatively observed cancel wins.
                let cooperatively_cancelled = response
                    .error
                    .as_ref()
                    .is_some_and(|error| error.code == ErrorCode::Cancelled);
                record.status = completed_status(
                    status,
                    record.status,
                    entry.cancellation_applied.load(Ordering::Acquire),
                    cooperatively_cancelled,
                );
                record.result = Some(response);
            });
        });
        Ok(ticket)
    }

    pub async fn wait_operation(
        &self,
        operation_id: &str,
        caller: &Caller,
    ) -> Result<RequestOperationRecord> {
        let entry = self.operations.entry(operation_id, caller).await?;
        let mut state = entry.state.subscribe();
        loop {
            let record = state.borrow().clone();
            if record.status.terminal() {
                return Ok(record);
            }
            state
                .changed()
                .await
                .map_err(|_| Error::new(ErrorCode::Internal, "operation status channel closed"))?;
        }
    }

    pub async fn detach_operation_waiter(
        &self,
        operation_id: &str,
        caller: &Caller,
    ) -> Result<RequestOperationRecord> {
        let entry = self.operations.entry(operation_id, caller).await?;
        // 2026-08-29: HTTP deadline previously dropped the target JoinHandle,
        // making later side effects untraceable. Detach only the waiter while
        // the Gateway-owned operation continues to a recorded outcome.
        entry
            .state
            .send_modify(|record| record.waiter_detached = true);
        Ok(entry.state.borrow().clone())
    }

    pub async fn release_delivered_operation(&self, operation_id: &str, caller: &Caller) {
        // 2026-08-30: Successful MCP calls never expose their internal
        // operation ID. Drop the terminal response after delivery instead of
        // retaining thousands of unreachable, potentially large responses.
        self.operations.remove_delivered(operation_id, caller).await;
    }

    pub(super) async fn cancel_request_operation(
        &self,
        operation_id: &str,
        caller: &Caller,
        mode: crate::session::OperationCancelMode,
    ) -> Result<RequestOperationRecord> {
        let entry = self.operations.entry(operation_id, caller).await?;
        let _transition = entry.transition.lock().await;
        let session_id = {
            let record = entry.state.borrow().clone();
            if record.status.terminal() {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "operation already completed",
                ));
            }
            if record.cancellation != RequestOperationCancellation::ActorScoped {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "operation supports waiter detachment only",
                ));
            }
            entry.cancelled.store(true, Ordering::Release);
            entry
                .state
                .send_modify(|record| record.status = RequestOperationStatus::CancelRequested);
            record.session_id.ok_or_else(|| {
                Error::new(ErrorCode::InvalidState, "operation has no target session")
            })?
        };
        let session = self.entry(&session_id).await?;
        let operation_id = OperationId::parse(operation_id)?;
        match session.handle.cancel_operation(operation_id, mode).await {
            Ok(()) => {
                entry.cancellation_applied.store(true, Ordering::Release);
                if mode == crate::session::OperationCancelMode::CloseSession
                    && let Some(error) = self.retire_session(&session_id, &session).await
                {
                    tracing::warn!(%error, "cancelled session lease cleanup failed");
                }
            }
            // A queued operation observes the shared cancellation flag before
            // it sends MI; no active resume exists for the actor to interrupt.
            Err(error) if error.code == ErrorCode::Conflict => {}
            Err(error) => return Err(error),
        }
        Ok(entry.state.borrow().clone())
    }

    pub(super) async fn operation_get(
        &self,
        request: &ApiRequest,
        caller: &Caller,
    ) -> Result<Value> {
        let operation_id = request.parameters["operation_id"]
            .as_str()
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "operation_id is required"))?;
        let entry = self.operations.entry(operation_id, caller).await?;
        Ok(json!({ "operation": entry.state.borrow().clone() }))
    }

    pub(super) async fn operation_cancel(
        &self,
        request: &ApiRequest,
        caller: &Caller,
    ) -> Result<Value> {
        let operation_id = request.parameters["operation_id"]
            .as_str()
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "operation_id is required"))?;
        let mode = match request.parameters["mode"].as_str() {
            Some("interrupt_target") => crate::session::OperationCancelMode::InterruptTarget,
            Some("close_session") => crate::session::OperationCancelMode::CloseSession,
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "unsupported operation cancellation mode",
                ));
            }
        };
        let record = self
            .cancel_request_operation(operation_id, caller, mode)
            .await?;
        Ok(json!({ "operation": record }))
    }
}

fn completed_status(
    outcome: RequestOperationStatus,
    current: RequestOperationStatus,
    cancellation_applied: bool,
    cooperatively_cancelled: bool,
) -> RequestOperationStatus {
    if outcome == RequestOperationStatus::OutcomeUnknown {
        RequestOperationStatus::OutcomeUnknown
    } else if current == RequestOperationStatus::CancelRequested
        && (cancellation_applied || cooperatively_cancelled)
    {
        RequestOperationStatus::Aborted
    } else {
        outcome
    }
}

fn operation_status(response: &ApiResponse) -> RequestOperationStatus {
    // 2026-08-30: Unknown tokens belong to the session, not necessarily this
    // operation. Require this timeout's token to remain unresolved so later
    // reads and unrelated timeouts retain their own completion status.
    let unknown_token = response
        .error
        .as_ref()
        .filter(|error| error.code == ErrorCode::Timeout)
        .and_then(|error| error.details.as_ref())
        .filter(|details| details["outcome_unknown"].as_bool() == Some(true))
        .and_then(|details| details["token"].as_u64());
    if unknown_token.is_some_and(|token| {
        response
            .state
            .as_ref()
            .is_some_and(|state| state.outcome_unknown_tokens.contains(&token))
    }) {
        RequestOperationStatus::OutcomeUnknown
    } else if response.error.is_some() {
        RequestOperationStatus::Failed
    } else {
        RequestOperationStatus::Succeeded
    }
}

fn cancellation_for_request(request: &ApiRequest) -> RequestOperationCancellation {
    let resumes = request.method == CanonicalMethod::ExecutionControl
        && request.parameters["action"].as_str() != Some("interrupt");
    if resumes
        || matches!(
            request.method,
            CanonicalMethod::TargetLaunch
                | CanonicalMethod::TargetRestart
                | CanonicalMethod::AgentProbe
                | CanonicalMethod::AgentExperiment
        )
    {
        RequestOperationCancellation::ActorScoped
    } else {
        RequestOperationCancellation::WaiterOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, domain::SessionId, protocol::API_VERSION};
    use tempfile::tempdir;

    fn config() -> Config {
        let directory = tempdir().unwrap().keep();
        let mut config = Config::default();
        config.persistence.sqlite = directory.join("state.sqlite");
        config.persistence.sessions = directory.join("sessions");
        config.artifacts.path = directory.join("artifacts");
        config
    }

    #[tokio::test]
    async fn detached_waiter_keeps_operation_result_queryable() {
        let gateway = Arc::new(Gateway::new(config()).unwrap());
        let caller = Caller::local("operation-test");
        let ticket = gateway
            .admit_operation(
                ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "list".into(),
                    session_id: None,
                    method: CanonicalMethod::SessionList,
                    expected_revision: None,
                    idempotency_key: None,
                    parameters: json!({}),
                },
                caller.clone(),
                Some(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        gateway
            .detach_operation_waiter(&ticket.operation_id.0, &caller)
            .await
            .unwrap();
        let record = gateway
            .wait_operation(&ticket.operation_id.0, &caller)
            .await
            .unwrap();
        assert_eq!(record.status, RequestOperationStatus::Succeeded);
        assert!(record.waiter_detached);
        assert!(record.result.unwrap().error.is_none());
        gateway
            .release_delivered_operation(&ticket.operation_id.0, &caller)
            .await;
        assert_eq!(
            gateway
                .cancel_request_operation(
                    &ticket.operation_id.0,
                    &caller,
                    crate::session::OperationCancelMode::InterruptTarget,
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
    }

    #[tokio::test]
    async fn delivered_operation_releases_its_retained_response() {
        let gateway = Arc::new(Gateway::new(config()).unwrap());
        let caller = Caller::local("operation-test");
        let ticket = gateway
            .admit_operation(
                ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "list".into(),
                    session_id: None,
                    method: CanonicalMethod::SessionList,
                    expected_revision: None,
                    idempotency_key: None,
                    parameters: json!({}),
                },
                caller.clone(),
                None,
            )
            .await
            .unwrap();
        gateway
            .wait_operation(&ticket.operation_id.0, &caller)
            .await
            .unwrap();
        gateway
            .release_delivered_operation(&ticket.operation_id.0, &caller)
            .await;

        let error = match gateway
            .operations
            .entry(&ticket.operation_id.0, &caller)
            .await
        {
            Ok(_) => panic!("delivered operation remained in the registry"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::NotFound);
    }

    #[test]
    fn only_resuming_requests_are_actor_cancellable() {
        let mut request = ApiRequest {
            api_version: API_VERSION.into(),
            request_id: "resume".into(),
            session_id: Some(SessionId::new().0),
            method: CanonicalMethod::ExecutionControl,
            expected_revision: None,
            idempotency_key: None,
            parameters: json!({"action": "continue"}),
        };
        assert_eq!(
            cancellation_for_request(&request),
            RequestOperationCancellation::ActorScoped
        );
        request.parameters = json!({"action": "interrupt"});
        assert_eq!(
            cancellation_for_request(&request),
            RequestOperationCancellation::WaiterOnly
        );
    }

    #[test]
    fn cancellation_that_loses_completion_race_preserves_outcome() {
        assert_eq!(
            completed_status(
                RequestOperationStatus::Succeeded,
                RequestOperationStatus::CancelRequested,
                false,
                false,
            ),
            RequestOperationStatus::Succeeded
        );
        assert_eq!(
            completed_status(
                RequestOperationStatus::Succeeded,
                RequestOperationStatus::CancelRequested,
                true,
                false,
            ),
            RequestOperationStatus::Aborted
        );
        assert_eq!(
            completed_status(
                RequestOperationStatus::Failed,
                RequestOperationStatus::CancelRequested,
                false,
                true,
            ),
            RequestOperationStatus::Aborted
        );
        assert_eq!(
            completed_status(
                RequestOperationStatus::OutcomeUnknown,
                RequestOperationStatus::CancelRequested,
                true,
                false,
            ),
            RequestOperationStatus::OutcomeUnknown
        );
    }

    #[test]
    fn operation_status_ignores_unknown_tokens_owned_by_other_operations() {
        let request = ApiRequest {
            api_version: API_VERSION.into(),
            request_id: "status".into(),
            session_id: Some(SessionId::new().0),
            method: CanonicalMethod::SessionGet,
            expected_revision: None,
            idempotency_key: None,
            parameters: json!({}),
        };
        let mut state = crate::domain::SessionState::creating(SessionId::new());
        state.outcome_unknown_tokens.insert(7);

        assert_eq!(
            operation_status(&ApiResponse::success(
                &request,
                Some(state.clone()),
                json!({})
            )),
            RequestOperationStatus::Succeeded
        );
        assert_eq!(
            operation_status(&ApiResponse::failure(
                &request,
                Error::new(ErrorCode::InvalidState, "not ready"),
                Some(state.clone()),
            )),
            RequestOperationStatus::Failed
        );
        assert_eq!(
            operation_status(&ApiResponse::failure(
                &request,
                Error::new(ErrorCode::Timeout, "wait timed out"),
                Some(state.clone()),
            )),
            RequestOperationStatus::Failed
        );
        assert_eq!(
            operation_status(&ApiResponse::failure(
                &request,
                Error::new(ErrorCode::Timeout, "command timed out").with_details(json!({
                    "outcome_unknown": true,
                    "token": 7,
                })),
                Some(state),
            )),
            RequestOperationStatus::OutcomeUnknown
        );
    }
}
