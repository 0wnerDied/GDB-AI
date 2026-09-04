use serde::Deserialize;
use serde_json::{Value, json};
use ulid::Ulid;

use super::{
    context::{context_options, require_stopped_context},
    evaluation::{safe_evaluate_command, validate_expression, validate_expression_text},
    mi::result_text,
    request::{bounded_limit, parameters, required_session, string},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{DomainEvent, ValueBinding, ValueId},
    gateway::{Gateway, SessionEntry},
    protocol::ApiRequest,
    session::CommandReply,
};

async fn evaluate_expression(
    entry: &SessionEntry,
    request: &ApiRequest,
    state: &crate::domain::SessionState,
    expression: &str,
    side_effects: bool,
) -> Result<CommandReply> {
    let command = context_options(
        MiCommand::new("-data-evaluate-expression")?.string(expression),
        &request.parameters,
        state,
    )?;
    if !side_effects {
        return safe_evaluate_command(&entry.handle, command).await;
    }
    entry
        .handle
        .transaction(
            vec![
                MiCommand::new("-gdb-set")?
                    .bare("may-call-functions")?
                    .bare("on")?,
            ],
            command,
            vec![
                MiCommand::new("-gdb-set")?
                    .bare("may-call-functions")?
                    .bare("off")?,
            ],
        )
        .await
}

async fn current_value_binding(
    entry: &SessionEntry,
    request: &ApiRequest,
    state: &crate::domain::SessionState,
) -> Result<ValueBinding> {
    require_stopped_context(&request.parameters, state)?;
    let binding = entry
        .handle
        .value_binding(string(&request.parameters, "value_id")?)
        .await?;
    state.require_stop(&binding.stop_id)?;
    Ok(binding)
}

impl Gateway {
    pub(super) async fn value_evaluate(&self, request: &ApiRequest) -> Result<Value> {
        #[derive(Deserialize)]
        struct Parameters {
            expression: Option<String>,
            expressions: Option<Vec<String>>,
            side_effects: Option<String>,
        }

        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let parameters: Parameters = parameters(request)?;
        let batch = parameters.expressions.is_some();
        let expressions = parameters
            .expression
            .into_iter()
            .chain(parameters.expressions.unwrap_or_default())
            .collect::<Vec<_>>();
        if expressions.is_empty() || expressions.len() > 16 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "evaluation accepts 1 to 16 expressions",
            ));
        }
        let side_effects = parameters.side_effects.as_deref().unwrap_or("deny");
        let replies = if side_effects == "allow" {
            let mut replies = Vec::with_capacity(expressions.len());
            for expression in &expressions {
                validate_expression_text(expression)?;
                replies.push(evaluate_expression(&entry, request, &state, expression, true).await?);
            }
            replies
        } else {
            for expression in &expressions {
                validate_expression(expression)?;
            }
            // 2026-09-05: Exploit traces evaluated related runtime addresses
            // in separate Agent turns even though they belonged to one stop.
            // Keep the complete ordered batch behind one stop/command fence.
            entry
                .handle
                .stable_observation(
                    &state,
                    Box::pin(async {
                        let mut replies = Vec::with_capacity(expressions.len());
                        for expression in &expressions {
                            replies.push(
                                evaluate_expression(&entry, request, &state, expression, false)
                                    .await?,
                            );
                        }
                        Ok(replies)
                    }),
                )
                .await?
        };
        let effect = if side_effects == "allow" {
            "allowed"
        } else {
            "denied"
        };
        if batch {
            let results = expressions
                .iter()
                .zip(&replies)
                .map(|(expression, reply)| {
                    json!({
                        "expression": expression,
                        "value": result_text(&reply.record, "value")
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!({
                "stop_id": state.stop_id,
                "results": results,
                "commands": replies,
                "side_effects": effect
            }))
        } else {
            let reply = replies.into_iter().next().unwrap();
            Ok(json!({
                "stop_id": state.stop_id,
                "value": result_text(&reply.record, "value"),
                "command": reply,
                "side_effects": effect
            }))
        }
    }

    pub(super) async fn value_create(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let expression = string(&request.parameters, "expression")?;
        validate_expression(&expression)?;
        let stop_id = state.stop_id.clone().unwrap();
        let value_id = ValueId::for_stop(&stop_id);
        let backend_name = format!("gdbai_{}", Ulid::new());
        let command = context_options(MiCommand::new("-var-create")?, &request.parameters, &state)?
            .bare(&backend_name)?
            .bare("*")?
            .string(&expression);
        let reply = safe_evaluate_command(&entry.handle, command).await?;
        let binding = ValueBinding {
            value_id: value_id.clone(),
            backend_name: backend_name.clone(),
            stop_id: stop_id.clone(),
            expression: expression.clone(),
        };
        if let Err(error) = entry.handle.register_value(binding).await {
            let _ = entry
                .handle
                .command(MiCommand::new("-var-delete")?.bare(backend_name)?)
                .await;
            return Err(error);
        }
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "value_created".into(),
            })
            .await?;
        Ok(json!({
            "value_id": value_id,
            "stop_id": stop_id,
            "expression": expression,
            "value": result_text(&reply.record, "value"),
            "type": result_text(&reply.record, "type"),
            "children_count": result_text(&reply.record, "numchild")
                .and_then(|value| value.parse::<u64>().ok()),
            "has_children": result_text(&reply.record, "numchild")
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|count| count > 0),
            "command": reply
        }))
    }

    pub(super) async fn value_children(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        let binding = current_value_binding(&entry, request, &state).await?;
        let offset = request
            .parameters
            .get("offset")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let limit = bounded_limit(&request.parameters, 100, self.config.limits.value_children)?;
        let end = offset.saturating_add(limit);
        let reply = entry
            .handle
            .command(
                MiCommand::new("-var-list-children")?
                    .bare("--simple-values")?
                    .bare(&binding.backend_name)?
                    .bare(offset.to_string())?
                    .bare(end.to_string())?,
            )
            .await?;
        let has_more = result_text(&reply.record, "has_more") == Some("1".into());
        Ok(json!({
            "value_id": binding.value_id,
            "stop_id": binding.stop_id,
            "offset": offset,
            "limit": limit,
            "result": reply,
            "continuation": has_more.then(|| format!("{}:{}", binding.value_id, end))
        }))
    }

    pub(super) async fn value_update(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        let binding = current_value_binding(&entry, request, &state).await?;
        let reply = entry
            .handle
            .command(
                MiCommand::new("-var-update")?
                    .bare("--simple-values")?
                    .bare(&binding.backend_name)?,
            )
            .await?;
        Ok(json!({
            "value_id": binding.value_id,
            "stop_id": binding.stop_id,
            "result": reply
        }))
    }

    pub(super) async fn value_release(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        let binding = current_value_binding(&entry, request, &state).await?;
        let reply = entry
            .handle
            .command(MiCommand::new("-var-delete")?.bare(&binding.backend_name)?)
            .await?;
        entry
            .handle
            .remove_value(binding.value_id.0.clone())
            .await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "value_released".into(),
            })
            .await?;
        Ok(json!({ "released": binding.value_id, "command": reply }))
    }
}
