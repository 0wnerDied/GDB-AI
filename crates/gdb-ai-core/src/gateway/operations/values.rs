use gdb_ai_mi::{MiRecord, MiResult};
use serde::Deserialize;
use serde_json::{Value, json};
use ulid::Ulid;

use super::{
    context::{context_options, observation_context, require_stopped_context},
    encoding::byte_content,
    evaluation::{safe_evaluate_command, validate_expression, validate_expression_text},
    mi::{aggregate_items, result_text},
    request::{bounded_limit, parameters, required_session, string},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{DomainEvent, ValueBinding, ValueId},
    gateway::{Gateway, SessionEntry},
    protocol::{ApiRequest, ValueChange, ValueChild, ValueStatus},
    session::CommandReply,
};

pub(super) fn result_value(results: &[MiResult], name: &str) -> Option<Value> {
    // 2026-09-08: Root evaluate/create used lossy UTF-8 while children kept
    // exact MI bytes. Every value entrance now shares this representation.
    let bytes = MiResult::find(results, name)?.as_bytes()?.to_vec();
    match String::from_utf8(bytes) {
        Ok(text) => Some(Value::String(text)),
        Err(error) => Some(Value::Object(byte_content(error.into_bytes()))),
    }
}

fn result_bool(results: &[MiResult], name: &str) -> Option<bool> {
    match MiResult::find_str(results, name)? {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

fn result_count(results: &[MiResult], name: &str) -> Option<u64> {
    MiResult::find_str(results, name)?.parse().ok()
}

pub(super) fn value_status(fields: &[MiResult]) -> ValueStatus {
    // 2026-09-08: `--simple-values` omits aggregate values, while GDB prints
    // unavailable leaves as sentinels. Being in scope alone does not prove
    // that a value was captured; only claim availability from value evidence.
    match MiResult::find_str(fields, "in_scope") {
        Some("0" | "false") => ValueStatus::Unavailable,
        Some("invalid") => ValueStatus::Invalid,
        Some("1" | "true") | None => {
            match MiResult::find(fields, "value").and_then(|value| value.as_bytes()) {
                Some(b"<optimized out>" | b"<unavailable>") => ValueStatus::Unavailable,
                Some(_) => ValueStatus::Available,
                None => ValueStatus::NotCollected,
            }
        }
        Some(_) => ValueStatus::Unknown,
    }
}

fn value_child(fields: &[MiResult]) -> Option<ValueChild> {
    let path = MiResult::find_str(fields, "name")?.to_owned();
    let children_count = result_count(fields, "numchild");
    Some(ValueChild {
        path,
        name: MiResult::find_str(fields, "exp").map(str::to_owned),
        status: value_status(fields),
        type_name: result_value(fields, "type"),
        value: result_value(fields, "value"),
        children_count,
        has_children: children_count.map(|count| count > 0),
        dynamic: result_bool(fields, "dynamic"),
        display_hint: MiResult::find_str(fields, "displayhint").map(str::to_owned),
        has_more: result_bool(fields, "has_more"),
    })
}

fn value_children(record: &MiRecord) -> Vec<ValueChild> {
    let Some(children) = MiResult::find(record.results(), "children") else {
        return Vec::new();
    };
    aggregate_items(children, "child")
        .into_iter()
        .filter_map(value_child)
        .collect()
}

fn value_changes(record: &MiRecord, binding: &ValueBinding) -> Vec<ValueChange> {
    let Some(changes) = MiResult::find(record.results(), "changelist") else {
        return Vec::new();
    };
    aggregate_items(changes, "change")
        .into_iter()
        .filter_map(|fields| {
            let path = MiResult::find_str(fields, "name")?.to_owned();
            let children_count = result_count(fields, "new_num_children")
                .or_else(|| result_count(fields, "numchild"));
            // 2026-09-08: Dynamic varobj additions exist only here, so dropping
            // them before MCP removes the raw MI reply loses observable state.
            let new_children = MiResult::find(fields, "new_children")
                .map(|children| {
                    aggregate_items(children, "child")
                        .into_iter()
                        .filter_map(value_child)
                        .collect()
                })
                .unwrap_or_default();
            Some(ValueChange {
                value_id: (path == binding.backend_name).then(|| binding.value_id.clone()),
                path,
                status: value_status(fields),
                type_name: result_value(fields, "new_type")
                    .or_else(|| result_value(fields, "type")),
                value: result_value(fields, "value"),
                type_changed: result_bool(fields, "type_changed"),
                children_count,
                has_children: children_count.map(|count| count > 0),
                dynamic: result_bool(fields, "dynamic"),
                display_hint: MiResult::find_str(fields, "displayhint").map(str::to_owned),
                has_more: result_bool(fields, "has_more"),
                new_children,
            })
        })
        .collect()
}

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
    // 2026-09-08: Handles omitted their creation selection, so child/update
    // reads accepted contradictory selectors. Keep GDB's bound selection and
    // semantic attribution together; an existing handle cannot be retargeted.
    for (field, bound) in [
        (
            "inferior_id",
            binding.inferior_id.as_ref().map(|id| id.0.as_str()),
        ),
        (
            "thread_id",
            binding.thread_id.as_ref().map(|id| id.0.as_str()),
        ),
        (
            "frame_id",
            binding.frame_id.as_ref().map(|id| id.0.as_str()),
        ),
    ] {
        if let Some(requested) = request.parameters.get(field).and_then(Value::as_str)
            && Some(requested) != bound
        {
            return Err(Error::new(
                ErrorCode::StaleContext,
                "value handle belongs to another selection",
            ));
        }
    }
    if let Some(level) = request
        .parameters
        .get("frame_level")
        .and_then(Value::as_u64)
        && binding
            .frame_id
            .as_ref()
            .and_then(|frame| frame.0.rsplit_once('_'))
            .and_then(|(_, level)| level.parse::<u64>().ok())
            != Some(level)
    {
        return Err(Error::new(
            ErrorCode::StaleContext,
            "value handle belongs to another frame",
        ));
    }
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
                        "value": result_value(reply.record.results(), "value")
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
                "value": result_value(reply.record.results(), "value"),
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
        let context = observation_context(&request.parameters, &state)?;
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
            inferior_id: context
                .as_ref()
                .and_then(|context| context.inferior_id.clone()),
            thread_id: context
                .as_ref()
                .and_then(|context| context.thread_id.clone()),
            frame_id: context
                .as_ref()
                .and_then(|context| context.frame_id.clone()),
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
            "value": result_value(reply.record.results(), "value"),
            "type": result_value(reply.record.results(), "type"),
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
        // 2026-09-08: Returning only CommandReply forced Agent clients to
        // understand GDB/MI child tuples. Keep it for v1 canonical clients,
        // while exposing the same bytes as first-class value semantics.
        let children = value_children(&reply.record);
        let children_count = result_count(reply.record.results(), "numchild");
        Ok(json!({
            "value_id": binding.value_id,
            "stop_id": binding.stop_id,
            "offset": offset,
            "limit": limit,
            "children": children,
            "children_count": children_count,
            "has_more": has_more,
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
        // 2026-09-08: Value updates exposed only the transport record, so an
        // unavailable or type-changing value was indistinguishable without
        // MI knowledge. Preserve those states in the semantic change list.
        let changes = value_changes(&reply.record, &binding);
        Ok(json!({
            "value_id": binding.value_id,
            "stop_id": binding.stop_id,
            "changes": changes,
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

#[cfg(test)]
mod tests {
    use gdb_ai_mi::{MiLimits, parse_record};

    use super::*;
    use crate::domain::StopId;

    #[test]
    fn value_object_records_have_lossless_semantic_children_and_changes() {
        let children_record = parse_record(
            br#"1^done,numchild="3",children=[child={name="var1.a",exp="a",numchild="0",type="int",value="7",dynamic="0"},child={name="var1.bytes",exp="bytes",numchild="1",type="char [1]",value="\377",dynamic="1",displayhint="array"},child={name="var1.aggregate",exp="aggregate",numchild="2",type="struct pair",in_scope="true"}],has_more="1""#,
            MiLimits::default(),
        )
        .unwrap();
        let children = value_children(&children_record);

        assert_eq!(children.len(), 3);
        assert_eq!(children[0].name.as_deref(), Some("a"));
        assert_eq!(children[0].value, Some(json!("7")));
        assert_eq!(children[1].status, ValueStatus::Available);
        assert_eq!(children[1].has_children, Some(true));
        assert_eq!(
            children[1].value,
            Some(json!({"encoding": "binary", "data_base64": "/w=="}))
        );
        assert_eq!(children[2].status, ValueStatus::NotCollected);
        assert_eq!(children[2].value, None);

        let binding = ValueBinding {
            value_id: ValueId("vstop_test_value".into()),
            backend_name: "var1".into(),
            stop_id: StopId("stop_test".into()),
            expression: "value".into(),
            inferior_id: None,
            thread_id: None,
            frame_id: None,
        };
        let update_record = parse_record(
            br#"2^done,changelist=[{name="var1",value="8",in_scope="true",type_changed="true",new_type="long",new_num_children="1",dynamic="1",displayhint="array",has_more="1",new_children=[{name="var1.new",exp="new",numchild="0",type="int",value="<optimized out>",in_scope="true"}]},{name="var1.a",in_scope="false",type_changed="false"}]"#,
            MiLimits::default(),
        )
        .unwrap();
        let changes = value_changes(&update_record, &binding);

        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].value_id.as_ref(), Some(&binding.value_id));
        assert_eq!(changes[0].status, ValueStatus::Available);
        assert_eq!(changes[0].type_name, Some(json!("long")));
        assert_eq!(changes[0].children_count, Some(1));
        assert_eq!(changes[0].has_more, Some(true));
        assert_eq!(changes[0].new_children.len(), 1);
        assert_eq!(changes[0].new_children[0].status, ValueStatus::Unavailable);
        assert_eq!(
            changes[0].new_children[0].value,
            Some(json!("<optimized out>"))
        );
        assert_eq!(changes[1].status, ValueStatus::Unavailable);
    }
}
