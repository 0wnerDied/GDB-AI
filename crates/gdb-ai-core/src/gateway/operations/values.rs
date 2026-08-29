use super::*;

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
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let expression = string(&request.parameters, "expression")?;
        validate_expression(&expression)?;
        if request
            .parameters
            .get("side_effects")
            .and_then(Value::as_str)
            .unwrap_or("deny")
            != "deny"
        {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "the vertical slice only supports side_effects=deny",
            ));
        }
        let evaluate = context_options(
            MiCommand::new("-data-evaluate-expression")?.string(expression),
            &request.parameters,
            &state,
        )?;
        let reply = safe_evaluate_command(&entry.handle, evaluate).await?;
        Ok(json!({
            "stop_id": state.stop_id,
            "value": result_text(&reply.record, "value"),
            "command": reply,
            "side_effects": "denied"
        }))
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
