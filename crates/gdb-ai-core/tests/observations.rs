use std::{process::Command, sync::Arc};

use gdb_ai_core::{
    ErrorCode,
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
};
use serde_json::json;
use tempfile::tempdir;
use tokio::task::JoinSet;

mod support;

use support::{request, successful};

fn metric_value(metrics: &str, name: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| {
            let (metric, value) = line.split_once(' ')?;
            (metric == name).then(|| value.parse().unwrap())
        })
        .unwrap()
}

#[tokio::test]
async fn unifies_bounded_turn_batch_and_snapshot_observations() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let source = directory.path().join("observations.c");
    let executable = directory.path().join("observations");
    std::fs::write(
        &source,
        "#include <stdio.h>\nvolatile int observed = 7;\nint main(void) {\n  observed += 1;\n  observed += 2;\n  puts(\"observations done\");\n  return observed != 10;\n}\n",
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-g", "-O0", "-fno-omit-frame-pointer"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );

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
    config.security.workspace_roots = vec![directory.path().to_owned()];
    config.limits.inline_memory_bytes = 8;
    config.limits.memory_read_bytes = 8;
    if let Some(path) = std::env::var_os("GDB_AI_GDB_PATH") {
        config.gdb.path = path.into();
    }
    let gateway = Arc::new(Gateway::new(config).unwrap());
    let caller = Caller::local("observation-test/mcp:writer");

    let created = successful(
        gateway
            .dispatch(
                request("create", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let session_id = created.result.as_ref().unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let before_launch = metric_value(&gateway.metrics(), "gdbai_commands_total");
    for (inspect, until) in [
        (json!([{"view": "stack"}]), "accepted"),
        (
            json!([
                {"name": "a", "view": "memory", "address": "0x1000", "length": 5},
                {"name": "b", "view": "memory", "address": "0x2000", "length": 4}
            ]),
            "snapshot",
        ),
    ] {
        let rejected = gateway
            .dispatch(
                request(
                    "invalid-launch-inspection",
                    Some(&session_id),
                    "target.launch",
                    created.revision,
                    json!({
                        "program": executable, "lease_id": lease_id,
                        "wait": {"until": until}, "inspect": inspect
                    }),
                ),
                &caller,
            )
            .await;
        assert_eq!(rejected.error.unwrap().code, ErrorCode::InvalidArgument);
        assert_eq!(
            metric_value(&gateway.metrics(), "gdbai_commands_total"),
            before_launch
        );
    }
    let launched = successful(
        gateway
            .dispatch(
                request(
                    "launch",
                    Some(&session_id),
                    "target.launch",
                    created.revision,
                    json!({
                        "program": executable,
                        "cwd": directory.path(),
                        "lease_id": lease_id,
                        "stop": "main",
                        "wait": {"until": "snapshot", "timeout_ms": 5000},
                        "inspect": [
                            {"view": "stack", "limit": 1},
                            {"name": "missing", "view": "evaluate", "expression": "missing_symbol"}
                        ]
                    }),
                ),
                &caller,
            )
            .await,
    );
    let first_stop = launched
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    assert!(!launched.semantics.as_ref().unwrap().complete);
    let launch_result = launched.result.as_ref().unwrap();
    assert_eq!(launch_result["observation_context"]["stop_id"], first_stop);
    assert_eq!(
        launch_result["observations"]["stack"]["frames"][0]["function"],
        "main"
    );
    assert_eq!(
        launch_result["observation_failures"]["missing"]["code"],
        "GDB_ERROR"
    );
    assert!(launch_result["command"]["record"].is_object());
    assert!(launch_result["capabilities"].is_object());
    let tracked = successful(
        gateway
            .dispatch(
                request(
                    "track-observed",
                    Some(&session_id),
                    "tracking.add_expression",
                    launched.revision,
                    json!({"lease_id": lease_id, "expression": "observed"}),
                ),
                &caller,
            )
            .await,
    );
    let tracked = successful(
        gateway
            .dispatch(
                request(
                    "track-missing",
                    Some(&session_id),
                    "tracking.add_expression",
                    tracked.revision,
                    json!({"lease_id": lease_id, "expression": "missing_tracked_symbol"}),
                ),
                &caller,
            )
            .await,
    );

    // 2026-09-08: A malformed aggregate plan used to be discovered only
    // after run control. The target must remain at the original stop.
    let oversized = gateway
        .dispatch(
            request(
                "oversized-turn",
                Some(&session_id),
                "execution.control",
                tracked.revision,
                json!({
                    "action": "next",
                    "lease_id": lease_id,
                    "stop_id": first_stop,
                    "wait": {"until": "snapshot", "timeout_ms": 5000},
                    "inspect": [
                        {"name": "left", "view": "memory", "address": "0x1000", "length": 5},
                        {"name": "right", "view": "memory", "address": "0x2000", "length": 4}
                    ]
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(oversized.error.unwrap().code, ErrorCode::InvalidArgument);
    assert_eq!(oversized.state.unwrap().stop_id.unwrap().0, first_stop);

    let stepped = successful(
        gateway
            .dispatch(
                request(
                    "step-and-observe",
                    Some(&session_id),
                    "execution.control",
                    tracked.revision,
                    json!({
                        "action": "next",
                        "lease_id": lease_id,
                        "stop_id": first_stop,
                        "wait": {"until": "snapshot", "timeout_ms": 5000},
                        "inspect": [
                            {"name": "value", "view": "evaluate", "expression": "observed", "frame_level": 0},
                            {"name": "missing", "view": "evaluate", "expression": "missing_symbol"},
                            {"view": "registers", "roles": ["pc", "sp"]}
                        ]
                    }),
                ),
                &caller,
            )
            .await,
    );
    let second_stop = stepped
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let stepped_result = stepped.result.as_ref().unwrap();
    assert_eq!(
        stepped_result["observation_context"]["stop_id"],
        second_stop
    );
    assert_eq!(stepped_result["observation_complete"], false);
    let stepped_observation_id = stepped_result["observation_context"]["observation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(stepped_result["observations"]["value"]["value"].is_string());
    assert_eq!(
        stepped_result["observations"]["value"]["expression"],
        "observed"
    );
    assert_eq!(
        stepped_result["observations"]["value"]["selection"]["frame_level"],
        0
    );
    assert!(
        stepped_result["observations"]["value"]
            .get("command")
            .is_none()
    );
    assert!(stepped_result["observations"]["registers"].is_object());
    assert_eq!(
        stepped_result["observation_failures"]["missing"]["code"],
        "GDB_ERROR"
    );
    assert!(
        stepped_result["observation_evidence"]
            .as_array()
            .is_some_and(|items| items.len() >= 2)
    );
    let shared_step = successful(
        gateway
            .dispatch(
                request(
                    "shared-step",
                    Some(&session_id),
                    "inspection.snapshot_get",
                    None,
                    json!({"snapshot_id": &stepped_observation_id}),
                ),
                &Caller::local("observation-test/mcp:step-observer"),
            )
            .await,
    );
    assert_eq!(
        shared_step.result.as_ref().unwrap()["context"]["observation_id"],
        stepped_observation_id
    );
    assert_eq!(
        shared_step.result.as_ref().unwrap()["failures"]["missing"]["code"],
        "GDB_ERROR"
    );

    let unchanged_request = request(
        "unchanged-facts",
        Some(&session_id),
        "inspection.batch",
        None,
        json!({
            "stop_id": second_stop,
            "requests": [{"view": "stack", "limit": 1}, {"view": "locals"}]
        }),
    );
    let before = successful(gateway.dispatch(unchanged_request.clone(), &caller).await);
    let after = successful(gateway.dispatch(unchanged_request, &caller).await);
    assert!(!before.evidence.is_empty());
    assert_ne!(before.evidence, after.evidence);
    let unchanged = successful(
        gateway
            .dispatch(
                request(
                    "unchanged-diff",
                    Some(&session_id),
                    "inspection.diff",
                    None,
                    json!({
                        "before_snapshot_id": before.result.unwrap()["observation_id"],
                        "after_snapshot_id": after.result.unwrap()["observation_id"]
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(unchanged.result.unwrap()["changes"], json!({}));

    for agent in [false, true] {
        let crash_request = request(
            "crash-context",
            Some(&session_id),
            "inspection.get",
            None,
            json!({"view": "crash", "stop_id": second_stop, "profile": "minimal"}),
        );
        let crash = successful(if agent {
            gateway.dispatch_agent(crash_request, &caller).await
        } else {
            gateway.dispatch(crash_request, &caller).await
        });
        let semantics = crash.semantics.as_ref().unwrap();
        let capture = crash.result.as_ref().unwrap();
        if agent {
            assert!(capture.get("observation_context").is_none());
            assert!(capture.get("evidence").is_none());
        } else {
            assert_eq!(json!(semantics.context), capture["observation_context"]);
            assert_eq!(json!(crash.evidence), capture["evidence"]);
        }
        assert!(!semantics.complete);
        assert!(!crash.warnings.is_empty());
        assert!(!crash.evidence.is_empty());
        let retained = successful(
            gateway
                .dispatch_agent(
                    request(
                        "shared-crash",
                        Some(&session_id),
                        "inspection.snapshot_get",
                        None,
                        json!({"snapshot_id": capture["observation_id"]}),
                    ),
                    &Caller::local("observation-test/mcp:crash-observer"),
                )
                .await,
        );
        assert_eq!(
            retained.semantics.as_ref().unwrap().context,
            semantics.context
        );
        assert_eq!(retained.evidence, crash.evidence);
        assert_eq!(retained.result.as_ref().unwrap()["stack"], capture["stack"]);
    }

    let tracked_capture = successful(
        gateway
            .dispatch(
                request(
                    "tracked-capture",
                    Some(&session_id),
                    "inspection.batch",
                    None,
                    json!({
                        "stop_id": second_stop,
                        "requests": [{"view": "tracked"}]
                    }),
                ),
                &caller,
            )
            .await,
    )
    .result
    .unwrap();
    assert_eq!(tracked_capture["complete"], false);
    assert!(
        tracked_capture["failures"]
            .as_object()
            .is_some_and(|items| items.is_empty())
    );
    assert_eq!(tracked_capture["results"]["tracked"]["partial"], true);
    assert_eq!(
        tracked_capture["results"]["tracked"]["warnings"][0]["code"],
        "TRACKED_EXPRESSION_UNAVAILABLE"
    );
    assert!(
        tracked_capture["results"]["tracked"]["tracked"]
            .as_object()
            .is_some_and(|items| items.len() == 1)
    );
    assert!(tracked_capture["results"]["tracked"]["changes"].is_object());
    assert!(
        tracked_capture["evidence"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    let separate_before = metric_value(&gateway.metrics(), "gdbai_commands_total");
    let separate_a = successful(
        gateway
            .dispatch(
                request(
                    "separate-registers-a",
                    Some(&session_id),
                    "inspection.get",
                    None,
                    json!({"view": "registers", "stop_id": second_stop, "roles": ["pc", "sp"]}),
                ),
                &caller,
            )
            .await,
    )
    .result
    .unwrap();
    let separate_b = successful(
        gateway
            .dispatch(
                request(
                    "separate-registers-b",
                    Some(&session_id),
                    "inspection.get",
                    None,
                    json!({"view": "registers", "stop_id": second_stop, "roles": ["pc", "sp"]}),
                ),
                &caller,
            )
            .await,
    )
    .result
    .unwrap();
    let separate_commands =
        metric_value(&gateway.metrics(), "gdbai_commands_total") - separate_before;
    assert_eq!(separate_a["roles"], separate_b["roles"]);
    assert_eq!(
        separate_commands, 2,
        "separate requests share one register capture"
    );

    let batch_before = metric_value(&gateway.metrics(), "gdbai_commands_total");
    let deduplicated = successful(
        gateway
            .dispatch(
                request(
                    "deduplicated-registers",
                    Some(&session_id),
                    "inspection.batch",
                    None,
                    json!({
                        "stop_id": second_stop,
                        "requests": [
                            {"name": "a", "view": "registers", "roles": ["pc", "sp"]},
                            {"name": "b", "view": "registers", "roles": ["pc", "sp"]}
                        ]
                    }),
                ),
                &caller,
            )
            .await,
    )
    .result
    .unwrap();
    let batch_commands = metric_value(&gateway.metrics(), "gdbai_commands_total") - batch_before;
    assert_eq!(deduplicated["results"]["a"], deduplicated["results"]["b"]);
    assert_eq!(deduplicated["results"]["a"]["roles"], separate_a["roles"]);
    assert_eq!(batch_commands, separate_commands);
    eprintln!(
        "register reads used {separate_commands} separate MI commands and {batch_commands} batched MI commands"
    );

    for concurrency in [1, 4, 8] {
        let commands_before = metric_value(&gateway.metrics(), "gdbai_commands_total");
        let mut observers = JoinSet::new();
        for observer in 0..concurrency {
            let gateway = gateway.clone();
            let session_id = session_id.clone();
            let stop_id = second_stop.clone();
            observers.spawn(async move {
                gateway
                    .dispatch(
                        request(
                            format!("coalesced-{concurrency}-{observer}"),
                            Some(&session_id),
                            "inspection.batch",
                            None,
                            json!({
                                "stop_id": stop_id,
                                "requests": [{"name": format!("registers-{concurrency}"), "view": "registers", "roles": ["pc", "sp"]}]
                            }),
                        ),
                        &Caller::local(format!("observation-test/mcp:observer-{observer}")),
                    )
                    .await
            });
        }
        let mut observation_id = None;
        while let Some(response) = observers.join_next().await {
            let result = successful(response.unwrap()).result.unwrap();
            let id = result["observation_id"].clone();
            assert_eq!(observation_id.get_or_insert(id.clone()), &id);
            assert_eq!(
                result["results"][format!("registers-{concurrency}")]["roles"],
                separate_a["roles"]
            );
        }
        let commands = metric_value(&gateway.metrics(), "gdbai_commands_total") - commands_before;
        assert_eq!(commands, 2, "all observers must share one backend capture");
        eprintln!("qualified read coalescing: observers={concurrency}, mi_commands={commands}");
    }

    let batch = successful(
        gateway
            .dispatch(
                request(
                    "batch",
                    Some(&session_id),
                    "inspection.batch",
                    None,
                    json!({
                        "stop_id": second_stop,
                        "requests": [
                            {"name": "registers_a", "view": "registers", "roles": ["pc", "sp"]},
                            {"name": "registers_b", "view": "registers", "roles": ["pc", "sp"]},
                            {"name": "memory", "view": "memory", "address_expression": "&observed", "length": 4},
                            {"name": "evaluate", "view": "evaluate", "expression": "observed"},
                            {"name": "code", "view": "disassembly", "around": {"expression": "$pc", "before_instructions": 1, "after_instructions": 1}},
                            {"name": "source", "view": "source", "path": source, "line": 3, "before_lines": 1, "after_lines": 1}
                        ]
                    }),
                ),
                &caller,
            )
            .await,
    );
    let batch = batch.result.unwrap();
    assert_eq!(batch["complete"], true);
    assert_eq!(batch["partial"], false);
    assert_eq!(batch["observation_context"]["stop_id"], second_stop);
    assert_eq!(batch["results"]["memory"]["read_length"], 4);
    assert!(batch["results"]["evaluate"]["value"].is_string());
    assert!(batch["results"]["evaluate"].get("command").is_none());
    assert!(batch["results"]["code"]["instructions"].is_array());
    assert_eq!(
        batch["results"]["source"]["lines"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        batch["results"]["registers_a"],
        batch["results"]["registers_b"]
    );
    assert!(
        batch["evidence"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    let batch_id = batch["observation_id"].as_str().unwrap().to_owned();
    assert_eq!(batch["observation_context"]["observation_id"], batch_id);
    let diff = successful(
        gateway
            .dispatch(
                request(
                    "observation-diff",
                    Some(&session_id),
                    "inspection.batch",
                    None,
                    json!({
                        "stop_id": second_stop,
                        "requests": [{
                            "view": "diff",
                            "before_snapshot_id": stepped_observation_id,
                            "after_snapshot_id": batch_id
                        }]
                    }),
                ),
                &caller,
            )
            .await,
    )
    .result
    .unwrap();
    assert_eq!(diff["results"]["diff"]["historical"], true);
    assert_eq!(
        diff["results"]["diff"]["before_snapshot_id"],
        stepped_observation_id
    );
    assert_eq!(diff["results"]["diff"]["after_snapshot_id"], batch_id);
    assert!(diff["results"]["diff"]["changes"]["results"].is_object());
    let shared_batch = successful(
        gateway
            .dispatch(
                request(
                    "shared-batch",
                    Some(&session_id),
                    "inspection.snapshot_get",
                    None,
                    json!({"snapshot_id": batch_id}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(
        shared_batch.result.as_ref().unwrap()["results"]["evaluate"],
        batch["results"]["evaluate"]
    );
    for concurrency in [1, 4, 8] {
        let commands_before = metric_value(&gateway.metrics(), "gdbai_commands_total");
        let mut observers = JoinSet::new();
        for observer in 0..concurrency {
            let gateway = gateway.clone();
            let session_id = session_id.clone();
            let batch_id = batch_id.clone();
            observers.spawn(async move {
                gateway
                    .dispatch(
                        request(
                            format!("shared-{concurrency}-{observer}"),
                            Some(&session_id),
                            "inspection.snapshot_get",
                            None,
                            json!({"snapshot_id": batch_id}),
                        ),
                        &Caller::local(format!("observation-test/mcp:observer-{observer}")),
                    )
                    .await
            });
        }
        let mut retrieved = 0;
        while let Some(response) = observers.join_next().await {
            let response = successful(response.unwrap());
            let observation = response.result.unwrap();
            assert_eq!(observation["observation_id"], batch_id);
            assert_eq!(observation["results"], batch["results"]);
            retrieved += 1;
        }
        let commands_after = metric_value(&gateway.metrics(), "gdbai_commands_total");
        assert_eq!(retrieved, concurrency);
        assert_eq!(commands_after, commands_before);
        eprintln!(
            "immutable observation reuse: observers={concurrency}, extra_mi_commands={}",
            commands_after - commands_before
        );
    }
    let denied = gateway
        .dispatch(
            request(
                "denied-observer",
                Some(&session_id),
                "inspection.snapshot_get",
                None,
                json!({"snapshot_id": batch_id}),
            ),
            &Caller::local("other-principal/mcp:observer"),
        )
        .await;
    assert_eq!(denied.error.unwrap().code, ErrorCode::PolicyDenied);

    let partial = successful(gateway.dispatch_agent(request(
        "partial-expression-list", Some(&session_id), "value.evaluate", None,
        json!({"stop_id": second_stop, "expressions": ["observed", "missing_symbol", "observed + 1"]})
    ), &caller).await);
    assert!(!partial.semantics.unwrap().complete);
    let partial = partial.result.unwrap();
    assert_eq!(partial["results"][0]["status"], "available");
    assert_eq!(partial["results"][1]["status"], "failed");
    assert_eq!(partial["results"][2]["status"], "available");
    assert!(partial["failures"]["1"]["details"].get("record").is_none());
    assert!(partial.get("commands").is_none());

    let custom_before = metric_value(&gateway.metrics(), "gdbai_commands_total");
    let custom = successful(gateway.dispatch_agent(request(
        "custom-snapshot", Some(&session_id), "inspection.snapshot", None,
        json!({"stop_id": second_stop, "inspect": [{"view": "registers", "roles": ["pc"]}]})
    ), &caller).await).result.unwrap();
    assert_eq!(custom["profile"], "custom");
    assert_eq!(custom["availability"]["stack"], "not_collected");
    assert_eq!(custom["availability"]["tracked"], "not_collected");
    assert_eq!(custom["observation_availability"]["registers"], "captured");
    assert_eq!(
        metric_value(&gateway.metrics(), "gdbai_commands_total") - custom_before,
        2
    );

    let snapshot_response = successful(
        gateway
            .dispatch(
                request(
                    "snapshot",
                    Some(&session_id),
                    "inspection.snapshot",
                    None,
                    json!({
                        "profile": "minimal",
                        "stop_id": second_stop,
                        "inspect": [
                            {"name": "value", "view": "evaluate", "expression": "observed"},
                            {"name": "memory", "view": "memory", "address_expression": "&observed", "length": 4}
                        ]
                    }),
                ),
                &caller,
            )
            .await,
    );
    let snapshot_revision = snapshot_response.revision;
    let snapshot = snapshot_response.result.unwrap();
    assert_eq!(snapshot["observation_id"], snapshot["snapshot_id"]);
    assert!(snapshot["observations"]["value"]["value"].is_string());
    assert_eq!(snapshot["observations"]["memory"]["read_length"], 4);
    let snapshot_id = snapshot["snapshot_id"].as_str().unwrap().to_owned();
    assert_eq!(
        snapshot["observation_context"]["observation_id"],
        snapshot_id
    );
    let historical = successful(
        gateway
            .dispatch(
                request(
                    "historical",
                    Some(&session_id),
                    "inspection.snapshot_get",
                    None,
                    json!({"snapshot_id": snapshot_id}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(historical.result.as_ref().unwrap()["historical"], true);
    assert_eq!(
        historical.result.as_ref().unwrap()["observation_id"],
        snapshot["observation_id"]
    );

    let register_request = request(
        "before-same-stop-write",
        Some(&session_id),
        "register.read",
        None,
        json!({"stop_id": second_stop, "roles": ["pc"]}),
    );
    let before_write = successful(gateway.dispatch(register_request.clone(), &caller).await);
    let denied = gateway
        .dispatch(
            register_request.clone(),
            &Caller::local("other-principal/mcp:reader"),
        )
        .await;
    assert_eq!(denied.error.unwrap().code, ErrorCode::PolicyDenied);

    let register_write = successful(gateway.dispatch(request(
        "same-stop-register-assignment", Some(&session_id), "value.evaluate", before_write.revision,
        json!({"lease_id": lease_id, "stop_id": second_stop, "expression": "$pc = $pc", "side_effects": "allow"})
    ), &caller).await);
    assert_eq!(
        register_write.revision, before_write.revision,
        "register assignment emits no revision event"
    );
    let after_write_commands = metric_value(&gateway.metrics(), "gdbai_commands_total");
    let after_write = successful(gateway.dispatch(register_request, &caller).await);
    assert_eq!(
        metric_value(&gateway.metrics(), "gdbai_commands_total") - after_write_commands,
        2,
        "same-stop writes invalidate even when revision is unchanged"
    );
    assert_eq!(
        after_write.result.unwrap()["roles"],
        before_write.result.unwrap()["roles"]
    );

    let written = successful(
        gateway
            .dispatch(
                request(
                    "same-stop-write",
                    Some(&session_id),
                    "value.evaluate",
                    snapshot_revision,
                    json!({
                        "lease_id": lease_id,
                        "stop_id": second_stop,
                        "expression": "observed = 42",
                        "side_effects": "allow"
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(
        written.state.as_ref().unwrap().stop_id.as_ref().unwrap().0,
        second_stop
    );
    for view in ["memory", "evaluate"] {
        let uncached_before = metric_value(&gateway.metrics(), "gdbai_commands_total");
        for repeat in 0..2 {
            let item = if view == "memory" {
                json!({"view": view, "address_expression": "&observed", "length": 4})
            } else {
                json!({"view": view, "expression": "observed"})
            };
            successful(
                gateway
                    .dispatch(
                        request(
                            format!("uncached-{view}-{repeat}"),
                            Some(&session_id),
                            "inspection.batch",
                            None,
                            json!({"stop_id": second_stop, "requests": [item]}),
                        ),
                        &caller,
                    )
                    .await,
            );
        }
        assert!(
            metric_value(&gateway.metrics(), "gdbai_commands_total") - uncached_before >= 2,
            "potentially volatile reads must be sampled for each request"
        );
    }
    let refreshed = successful(
        gateway
            .dispatch(
                request(
                    "fresh-same-stop",
                    Some(&session_id),
                    "inspection.batch",
                    None,
                    json!({
                        "stop_id": second_stop,
                        "requests": [{"view": "evaluate", "expression": "observed"}]
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(refreshed.revision, written.revision);
    let refreshed = refreshed.result.unwrap();
    assert_ne!(refreshed["observation_id"], batch_id);
    assert_eq!(refreshed["results"]["evaluate"]["value"], "42");
    let original = successful(
        gateway
            .dispatch(
                request(
                    "unchanged-same-stop",
                    Some(&session_id),
                    "inspection.snapshot_get",
                    None,
                    json!({"snapshot_id": batch_id}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(
        original.result.as_ref().unwrap()["results"],
        batch["results"]
    );
    assert_eq!(original.result.as_ref().unwrap()["historical"], true);

    let next_controller = Caller::local("observation-test/mcp:next-controller");
    let denied_handoff = gateway
        .dispatch(
            request(
                "cross-principal-handoff",
                Some(&session_id),
                "session.handoff",
                written.revision,
                json!({
                    "lease_id": lease_id,
                    "to": "other-principal/mcp:controller"
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(denied_handoff.error.unwrap().code, ErrorCode::PolicyDenied);
    let handoff = successful(
        gateway
            .dispatch(
                request(
                    "handoff",
                    Some(&session_id),
                    "session.handoff",
                    written.revision,
                    json!({"lease_id": lease_id, "to": &next_controller.identity}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(
        handoff.result.as_ref().unwrap()["controller"],
        next_controller.identity
    );
    let former_controller = gateway
        .dispatch(
            request(
                "former-controller",
                Some(&session_id),
                "session.handoff",
                handoff.revision,
                json!({
                    "lease_id": lease_id,
                    "to": "observation-test/mcp:third-controller"
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        former_controller.error.unwrap().code,
        ErrorCode::WriteLeaseRequired
    );
    let exited = successful(
        gateway
            .dispatch_agent(
                request(
                    "exit-before-inspection",
                    Some(&session_id),
                    "execution.control",
                    None,
                    json!({"action": "continue", "wait": {"until": "settled", "timeout_ms": 5000},
            "inspect": [{"view": "evaluate", "expression": "observed"}]}),
                ),
                &next_controller,
            )
            .await,
    );
    assert!(!exited.semantics.as_ref().unwrap().complete);
    assert_eq!(exited.result.as_ref().unwrap()["settled_by"], "exited");
    assert_eq!(
        exited.result.as_ref().unwrap()["observation_status"],
        "not_collected"
    );
    let before_restart = metric_value(&gateway.metrics(), "gdbai_commands_total");
    let rejected = gateway
        .dispatch_agent(
            request(
                "invalid-restart-inspection",
                Some(&session_id),
                "target.restart",
                None,
                json!({"wait": {"until": "running"}, "inspect": [{"view": "stack"}]}),
            ),
            &next_controller,
        )
        .await;
    assert_eq!(rejected.error.unwrap().code, ErrorCode::InvalidArgument);
    assert_eq!(
        metric_value(&gateway.metrics(), "gdbai_commands_total"),
        before_restart
    );
    let restarted = successful(
        gateway
            .dispatch_agent(
                request(
                    "restart-and-inspect",
                    Some(&session_id),
                    "target.restart",
                    None,
                    json!({"stop": "main", "inspect": [{"view": "stack", "limit": 1}]}),
                ),
                &next_controller,
            )
            .await,
    );
    let restart_context = restarted
        .semantics
        .as_ref()
        .unwrap()
        .context
        .as_ref()
        .unwrap();
    assert!(restarted.semantics.as_ref().unwrap().complete);
    assert_ne!(restart_context.stop_id.0, second_stop);
    let restart_result = restarted.result.as_ref().unwrap();
    assert!(restart_result.get("observation_context").is_none());
    assert_eq!(restart_result["stop_id"], restart_context.stop_id.0);
    assert_eq!(
        restart_result["observations"]["stack"]["frames"][0]["function"],
        "main"
    );
    assert!(restart_result.get("command").is_none());
    assert!(restart_result.get("capabilities").is_none());
    let rerun = successful(
        gateway
            .dispatch_agent(
                request(
                    "restart-to-exit",
                    Some(&session_id),
                    "target.restart",
                    None,
                    json!({"stop": "none", "inspect": [{"view": "stack"}]}),
                ),
                &next_controller,
            )
            .await,
    );
    assert!(!rerun.semantics.as_ref().unwrap().complete);
    assert_eq!(
        rerun.result.as_ref().unwrap()["observation_status"],
        "not_collected"
    );
    assert!(
        rerun.result.as_ref().unwrap()["output"]["text"]
            .as_str()
            .unwrap()
            .contains("observations done")
    );
    successful(
        gateway
            .dispatch_agent(
                request("close", Some(&session_id), "session.close", None, json!({})),
                &next_controller,
            )
            .await,
    );
    let retained_batch = successful(
        gateway
            .dispatch(
                request(
                    "retained-batch",
                    Some(&session_id),
                    "inspection.snapshot_get",
                    None,
                    json!({"snapshot_id": batch_id}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(
        retained_batch.result.as_ref().unwrap()["results"]["evaluate"],
        batch["results"]["evaluate"]
    );
    let retained_diff = successful(
        gateway
            .dispatch(
                request(
                    "retained-diff",
                    Some(&session_id),
                    "inspection.diff",
                    None,
                    json!({
                        "before_snapshot_id": stepped_observation_id,
                        "after_snapshot_id": batch_id
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(retained_diff.result.as_ref().unwrap()["historical"], true);
    assert_eq!(
        retained_diff.result.as_ref().unwrap()["before_snapshot_id"],
        stepped_observation_id
    );
}
