use std::collections::BTreeSet;

use serde_json::Value;

use super::{encoding::parse_address, evaluation::validate_expression};
use crate::{
    Error, ErrorCode, Result,
    domain::StopId,
    protocol::{ApiRequest, CanonicalMethod},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ObservationKind {
    Inspection,
    Evaluate,
    Memory,
    Disassembly,
    Diff,
}

#[derive(Clone, Debug)]
pub(super) struct ObservationRequest {
    name: String,
    kind: ObservationKind,
    parameters: Value,
    cache_key: String,
    cacheable: bool,
}

impl ObservationRequest {
    pub(super) fn parse(
        item: &Value,
        stop_id: &StopId,
        memory_budget: &mut usize,
        expression_budget: &mut usize,
        maximum_memory_bytes: usize,
        defaults: &Value,
    ) -> Result<Self> {
        let mut parameters = item.clone();
        let object = parameters.as_object_mut().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "observation request must be an object",
            )
        })?;
        const SELECTION: [&str; 4] = ["inferior_id", "thread_id", "frame_id", "frame_level"];
        // 2026-09-08: Composite reads discarded their parent's explicit
        // selection. An item inherits that selection unless it supplies its
        // own; a new thread must not inherit a frame from the old thread.
        if !SELECTION.iter().any(|field| object.contains_key(*field)) {
            for field in SELECTION {
                if let Some(value) = defaults.get(field) {
                    object.insert(field.into(), value.clone());
                }
            }
        }
        let view = object
            .get("view")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "view is required"))?
            .to_owned();
        let name = object
            .remove("name")
            .and_then(|name| name.as_str().map(str::to_owned))
            .unwrap_or_else(|| view.clone());
        if name.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "observation name must not be empty",
            ));
        }
        let kind = match view.as_str() {
            "evaluate" => ObservationKind::Evaluate,
            "memory" => ObservationKind::Memory,
            "disassembly" => ObservationKind::Disassembly,
            "diff" => ObservationKind::Diff,
            _ => ObservationKind::Inspection,
        };
        if kind != ObservationKind::Diff {
            object.insert("stop_id".into(), Value::String(stop_id.0.clone()));
        }
        let method = match kind {
            ObservationKind::Inspection => CanonicalMethod::InspectionGet,
            ObservationKind::Evaluate => CanonicalMethod::ValueEvaluate,
            ObservationKind::Memory => CanonicalMethod::MemoryRead,
            ObservationKind::Disassembly => CanonicalMethod::DisassemblyRead,
            ObservationKind::Diff => CanonicalMethod::InspectionDiff,
        };
        if kind != ObservationKind::Inspection {
            parameters.as_object_mut().unwrap().remove("view");
        }
        method.validate_parameters(&parameters)?;

        match kind {
            ObservationKind::Evaluate => {
                let expressions = parameters
                    .get("expressions")
                    .and_then(Value::as_array)
                    .map_or(1, Vec::len);
                if expressions == 0 || expressions > 16 {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "evaluation accepts 1 to 16 expressions",
                    ));
                }
                *expression_budget =
                    expression_budget.checked_add(expressions).ok_or_else(|| {
                        Error::new(ErrorCode::InvalidArgument, "expression budget overflow")
                    })?;
                if *expression_budget > 16 {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "one observation turn accepts at most 16 expressions",
                    ));
                }
                if let Some(expression) = parameters.get("expression").and_then(Value::as_str) {
                    validate_expression(expression)?;
                }
                if let Some(expressions) = parameters.get("expressions").and_then(Value::as_array) {
                    for expression in expressions.iter().filter_map(Value::as_str) {
                        validate_expression(expression)?;
                    }
                }
            }
            ObservationKind::Memory => {
                let length = parameters["length"].as_u64().unwrap();
                let length = usize::try_from(length).map_err(|_| {
                    Error::new(ErrorCode::InvalidArgument, "memory length is too large")
                })?;
                if length == 0 || length > maximum_memory_bytes {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("memory length must be between 1 and {maximum_memory_bytes}"),
                    ));
                }
                *memory_budget = memory_budget.checked_add(length).ok_or_else(|| {
                    Error::new(ErrorCode::InvalidArgument, "memory budget overflow")
                })?;
                if *memory_budget > maximum_memory_bytes {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "one observation turn accepts at most {maximum_memory_bytes} memory bytes"
                        ),
                    ));
                }
                if let Some(address) = parameters.get("address").and_then(Value::as_str) {
                    crate::domain::Address::parse(address)?;
                }
                if let Some(expression) =
                    parameters.get("address_expression").and_then(Value::as_str)
                {
                    validate_expression(expression)?;
                }
            }
            ObservationKind::Disassembly => {
                if let Some(expression) = parameters
                    .pointer("/around/expression")
                    .and_then(Value::as_str)
                {
                    validate_expression(expression)?;
                }
                if let Some(range) = parameters.get("range") {
                    let start = parse_address(range["start"].as_str().unwrap())?;
                    let end = parse_address(range["end"].as_str().unwrap())?;
                    if end <= start || end - start > 64 * 1024 {
                        return Err(Error::new(
                            ErrorCode::InvalidArgument,
                            "disassembly range must be positive and at most 64 KiB",
                        ));
                    }
                }
            }
            ObservationKind::Inspection | ObservationKind::Diff => {}
        }

        let cache_key = format!(
            "{}:{}",
            method.as_str(),
            serde_json::to_string(&parameters)?
        );
        // 2026-09-08: Full target state was cached on stop/epoch alone even
        // though output and snapshot events can advance it within that fence.
        // Cache only bounded metadata or register reads proven stable here.
        let cacheable = crate::gateway::shareable_view(&parameters);
        Ok(Self {
            name,
            kind,
            parameters,
            cache_key,
            cacheable,
        })
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn kind(&self) -> ObservationKind {
        self.kind
    }

    pub(super) fn cache_key(&self) -> Option<&str> {
        self.cacheable.then_some(&self.cache_key)
    }

    pub(super) fn finalize_result(&self, result: &mut Value) {
        let Some(result) = result.as_object_mut() else {
            return;
        };
        if self.kind == ObservationKind::Evaluate {
            if let Some(expression) = self.parameters.get("expression") {
                result.insert("expression".into(), expression.clone());
            }
        }

        let selection: serde_json::Map<_, _> =
            ["inferior_id", "thread_id", "frame_id", "frame_level"]
                .into_iter()
                .filter_map(|field| {
                    self.parameters
                        .get(field)
                        .cloned()
                        .map(|value| (field.into(), value))
                })
                .collect();
        // 2026-09-08: The shared context describes the default stopped frame,
        // but explicit item selectors can override it. Preserve only that
        // override so historical readers can attribute the returned value.
        if !selection.is_empty() {
            result.insert("selection".into(), Value::Object(selection));
        }
    }

    pub(super) fn is_partial_result(&self, result: &Value) -> bool {
        result.get("partial").and_then(Value::as_bool) == Some(true)
            // 2026-09-08: Source excerpts use `partial` for deliberate
            // pagination, not a failed capture.
            && self.parameters.get("view").and_then(Value::as_str) != Some("source")
    }

    pub(super) fn subrequest(&self, parent: &ApiRequest) -> ApiRequest {
        let method = match self.kind {
            ObservationKind::Inspection => CanonicalMethod::InspectionGet,
            ObservationKind::Evaluate => CanonicalMethod::ValueEvaluate,
            ObservationKind::Memory => CanonicalMethod::MemoryRead,
            ObservationKind::Disassembly => CanonicalMethod::DisassemblyRead,
            ObservationKind::Diff => CanonicalMethod::InspectionDiff,
        };
        ApiRequest {
            api_version: parent.api_version.clone(),
            request_id: format!("{}:{}", parent.request_id, self.name),
            session_id: parent.session_id.clone(),
            method,
            expected_revision: None,
            idempotency_key: None,
            parameters: self.parameters.clone(),
        }
    }
}

pub(super) fn parse_observation_requests(
    value: &Value,
    stop_id: &StopId,
    maximum_memory_bytes: usize,
    defaults: &Value,
) -> Result<Vec<ObservationRequest>> {
    let items = value.as_array().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "observation requests are required",
        )
    })?;
    if items.is_empty() || items.len() > 16 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "observation accepts 1 to 16 reads",
        ));
    }
    let mut names = BTreeSet::new();
    let mut memory_budget = 0;
    let mut expression_budget = 0;
    let mut requests = Vec::with_capacity(items.len());
    for item in items {
        let request = ObservationRequest::parse(
            item,
            stop_id,
            &mut memory_budget,
            &mut expression_budget,
            maximum_memory_bytes,
            defaults,
        )?;
        if !names.insert(request.name.clone()) {
            return Err(Error::new(
                ErrorCode::Conflict,
                "observation request names must be unique",
            ));
        }
        requests.push(request);
    }
    Ok(requests)
}

pub(super) fn validate_observation_requests(
    value: &Value,
    maximum_memory_bytes: usize,
) -> Result<()> {
    parse_observation_requests(
        value,
        &StopId("observation-validation".into()),
        maximum_memory_bytes,
        &Value::Null,
    )
    .map(|_| ())
}

pub(super) fn snapshot_requests(parameters: &Value, profile: &str, frames: usize) -> Value {
    let mut requests = Vec::new();
    if profile != "custom" {
        requests.push(serde_json::json!({"view": "stack", "limit": frames}));
        if profile != "minimal" {
            requests.push(serde_json::json!({"view": "locals"}));
            if profile != "brief" {
                requests.push(serde_json::json!({"view": "arguments", "limit": frames}));
            }
            let mut registers = serde_json::json!({"view": "registers", "profile": profile});
            if let Some(roles) = parameters.get("roles") {
                registers["roles"] = roles.clone();
            }
            requests.push(registers);
            let mut disassembly = serde_json::json!({"view": "disassembly"});
            for field in ["around", "range", "include_bytes", "include_source"] {
                if let Some(value) = parameters.get(field) {
                    disassembly[field] = value.clone();
                }
            }
            if profile == "brief" {
                let object = disassembly.as_object_mut().unwrap();
                if !object.contains_key("around") && !object.contains_key("range") {
                    object.insert("around".into(), serde_json::json!({"expression": "$pc", "before_instructions": 4, "after_instructions": 7}));
                }
                object.entry("include_source").or_insert(Value::Bool(false));
            }
            requests.push(disassembly);
        }
        requests.push(serde_json::json!({"view": "tracked"}));
        for request in &mut requests {
            request["name"] =
                Value::String(format!("@snapshot.{}", request["view"].as_str().unwrap()));
        }
    }
    if let Some(inspect) = parameters.get("inspect").and_then(Value::as_array) {
        requests.extend(inspect.iter().cloned());
    }
    Value::Array(requests)
}

pub(super) fn independent_failure(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::InvalidArgument
            | ErrorCode::NotFound
            | ErrorCode::CapabilityMissing
            | ErrorCode::Unsupported
            | ErrorCode::PolicyDenied
            | ErrorCode::OutputLimit
            | ErrorCode::PartialRead
            | ErrorCode::GdbError
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_whole_turn_budgets_before_capture() {
        let stop_id = StopId("s1".into());
        let error = parse_observation_requests(
            &json!([
                {"name": "first", "view": "memory", "address": "0x1000", "length": 5},
                {"name": "second", "view": "memory", "address": "0x2000", "length": 4}
            ]),
            &stop_id,
            8,
            &Value::Null,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn new_reads_use_existing_canonical_contracts() {
        let stop_id = StopId("s1".into());
        for request in [
            json!({"view": "evaluate", "expression": "value"}),
            json!({"view": "memory", "address_expression": "&value", "length": 4}),
            json!({"view": "disassembly", "around": {"expression": "$pc"}}),
        ] {
            ObservationRequest::parse(&request, &stop_id, &mut 0, &mut 0, 16, &Value::Null)
                .unwrap();
        }
        let defaults = json!({"thread_id": "thread_a", "frame_level": 2});
        let inherited = ObservationRequest::parse(
            &json!({"view": "locals"}),
            &stop_id,
            &mut 0,
            &mut 0,
            16,
            &defaults,
        )
        .unwrap();
        assert_eq!(inherited.parameters["thread_id"], "thread_a");
        assert_eq!(inherited.parameters["frame_level"], 2);
        let replaced = ObservationRequest::parse(
            &json!({"view": "locals", "thread_id": "thread_b"}),
            &stop_id,
            &mut 0,
            &mut 0,
            16,
            &defaults,
        )
        .unwrap();
        assert_eq!(replaced.parameters["thread_id"], "thread_b");
        assert!(replaced.parameters.get("frame_level").is_none());
    }
}
