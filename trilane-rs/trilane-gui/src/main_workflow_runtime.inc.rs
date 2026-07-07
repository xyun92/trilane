fn audit_mode_user_input(audit_mode: &AuditMode, text: &str) -> String {
    let access = match audit_mode {
        AuditMode::Safe => {
            "ACCESS_MODE% SAFE\n\
             ACCESS_RULES% Keep the same S0-S5 audit depth, but treat filesystem writes, service starts, container operations, network-impacting actions, and privileged commands as approval-bound. If approval is denied, continue with source analysis and clearly record the blocked evidence."
        }
        AuditMode::Lab => {
            "ACCESS_MODE% LAB\n\
             ACCESS_RULES% Authorized local lab mode. You may use full local filesystem and command execution access for the stated target, including starting services or containers when needed. Keep actions scoped to the user-provided objective."
        }
    };
    let control = format!(
        "AUDIT_MODE% {}\n\
         {access}\n\
         MODE_RULES% Run the TriLane source-aware audit with backend workflow control.\n\
         - S1 is a fast security indexer, not a deep audit. Emit compact SURFACE%/OBLIGATION% ledgers plus tightly bounded READ_TARGET% tasks for S2.\n\
         - S1 marker fields must be clean: category is one taxonomy token; use target/source/path/sink/debt/reason for details.\n\
         - S2 is backend-scheduled. Do not spawn subagents yourself. The five core lanes emit CLAIM% candidates only; quick_hits_engine is optional residual recovery.\n\
         - S3 receives a RUNBOOK_CONTEXT% merge packet, canonicalizes CLAIM% families, and plans verification. S3 must run before S4.\n\
         - S4 owns probes, controls, verification, rejection, and evidence-backed skips.\n\
         - S5 owns final PoC packaging. Do not call the audit complete or publish final PoCs until S5 emits canonical POC% entries.\n\
         - Use generic CVE-prior families as a coverage checklist, not as target-specific answers.",
        audit_mode.as_marker()
    );
    format!("{control}\n\nUSER_OBJECTIVE%\n{text}")
}

async fn submit_agent_turn(
    client: &mut InProcessAppServerClient,
    request_counter: &mut i64,
    thread_id: &str,
    text: String,
) -> Result<TurnStartResponse, String> {
    *request_counter += 1;
    client
        .request_typed::<TurnStartResponse>(ClientRequest::TurnStart {
            request_id: RequestId::Integer(*request_counter),
            params: TurnStartParams {
                thread_id: thread_id.to_string(),
                input: vec![UserInput::Text {
                    text,
                    text_elements: vec![],
                }],
                ..Default::default()
            },
        })
        .await
        .map_err(|e| e.to_string())
}

async fn runbook_snapshot(app: &AppHandle) -> RunbookState {
    let state = app.state::<AppState>();
    current_runbook_snapshot(&state).await
}

async fn start_workflow_phase(app: &AppHandle, prompt: &WorkflowPrompt) {
    app.state::<AppState>()
        .transcript_log
        .lock()
        .await
        .record_stage_start(&prompt.stage_id, &prompt.prompt);
    let summary = if prompt.is_repair {
        format!("{} repair gate", prompt.title)
    } else {
        prompt.title.clone()
    };
    mutate_runbook(app, |runbook| {
        runbook.record_workflow_phase(&prompt.stage_id, &summary);
    })
    .await;
    append_and_emit_system_message(
        app,
        format!(
            "SYS% workflow phase start\nWORKFLOW% phase={} stage={} repair={}\n{}",
            prompt.phase_id, prompt.stage_id, prompt.is_repair, prompt.title
        ),
    )
    .await;
}

async fn record_workflow_phase_deferred(
    app: &AppHandle,
    phase_id: &str,
    stage_id: &str,
    title: &str,
    reason: &str,
) {
    let marker = format!(
        "RUNBOOK% S4 Fuzz: deferred {title}; preserving claims for S5 downgrade/adjudication\n\
         S4_SKIP% id={phase_id} reason={reason}"
    );
    mutate_runbook(app, |runbook| {
        runbook.record_agent_message(&marker);
    })
    .await;
    append_and_emit_system_message(
        app,
        format!(
            "SYS% workflow phase deferred\nWORKFLOW% deferred phase={phase_id} stage={stage_id} reason=\"{reason}\""
        ),
    )
    .await;
}

async fn advance_workflow_after_lane_batch(
    context: WorkflowAdvanceContext<'_>,
    completed_phase_id: String,
    status: &str,
) {
    let WorkflowAdvanceContext {
        client,
        request_counter,
        app,
        runtime_config,
        root_thread_id,
        active_workflow,
        active_lane_batch,
    } = context;
    *active_lane_batch = None;
    append_and_emit_system_message(
        app,
        format!("SYS% workflow lane batch joined; phase={completed_phase_id}"),
    )
    .await;
    let workflow_action = if let Some(workflow) = active_workflow.as_mut() {
        let snapshot = runbook_snapshot(app).await;
        record_stage_snapshot(app, &snapshot, status).await;
        Some(workflow.after_turn_completed(&snapshot))
    } else {
        None
    };

    if let Some(action) = workflow_action {
        match action {
            WorkflowAction::Submit(prompt) => {
                start_workflow_phase(app, &prompt).await;
                match submit_agent_turn(client, request_counter, root_thread_id, prompt.prompt)
                    .await
                {
                    Ok(_resp) => {
                        info!("Workflow phase turn started after lane batch");
                    }
                    Err(e) => {
                        let message = format!("Workflow turn start failed: {e}");
                        *active_workflow = None;
                        update_runbook_error(app, &message).await;
                        append_and_emit_system_message(app, message.clone()).await;
                        set_turn_in_progress(app, false).await;
                    }
                }
            }
            WorkflowAction::SpawnLanes(next_batch) => {
                match start_workflow_lane_batch(
                    client,
                    request_counter,
                    app,
                    runtime_config,
                    &next_batch,
                )
                .await
                {
                    Ok(batch_runtime) => {
                        *active_lane_batch = Some(batch_runtime);
                    }
                    Err(e) => {
                        let message = format!("Workflow lane start failed: {e}");
                        *active_workflow = None;
                        update_runbook_error(app, &message).await;
                        append_and_emit_system_message(app, message.clone()).await;
                        set_turn_in_progress(app, false).await;
                    }
                }
            }
            WorkflowAction::Complete => {
                *active_workflow = None;
                set_turn_in_progress(app, false).await;
                let runbook = update_runbook_completed(app).await;
                append_turn_completed_message(app, status, &runbook).await;
            }
            WorkflowAction::DeferPhase {
                phase_id,
                stage_id,
                title,
                reason,
                next,
            } => {
                record_workflow_phase_deferred(app, &phase_id, &stage_id, &title, &reason).await;
                match *next {
                    WorkflowAction::Submit(prompt) => {
                        start_workflow_phase(app, &prompt).await;
                        match submit_agent_turn(
                            client,
                            request_counter,
                            root_thread_id,
                            prompt.prompt,
                        )
                        .await
                        {
                            Ok(_resp) => {
                                info!("Workflow phase turn started after deferred phase");
                            }
                            Err(e) => {
                                let message = format!("Workflow turn start failed: {e}");
                                *active_workflow = None;
                                update_runbook_error(app, &message).await;
                                append_and_emit_system_message(app, message.clone()).await;
                                set_turn_in_progress(app, false).await;
                            }
                        }
                    }
                    WorkflowAction::SpawnLanes(next_batch) => {
                        match start_workflow_lane_batch(
                            client,
                            request_counter,
                            app,
                            runtime_config,
                            &next_batch,
                        )
                        .await
                        {
                            Ok(batch_runtime) => {
                                *active_lane_batch = Some(batch_runtime);
                            }
                            Err(e) => {
                                let message = format!("Workflow lane start failed: {e}");
                                *active_workflow = None;
                                update_runbook_error(app, &message).await;
                                append_and_emit_system_message(app, message.clone()).await;
                                set_turn_in_progress(app, false).await;
                            }
                        }
                    }
                    WorkflowAction::Complete => {
                        *active_workflow = None;
                        set_turn_in_progress(app, false).await;
                        let runbook = update_runbook_completed(app).await;
                        append_turn_completed_message(app, status, &runbook).await;
                    }
                    WorkflowAction::Blocked(message) => {
                        *active_workflow = None;
                        update_runbook_error(app, &message).await;
                        append_and_emit_system_message(app, message).await;
                        set_turn_in_progress(app, false).await;
                    }
                    WorkflowAction::DeferPhase { .. } => {
                        let message = "Nested workflow deferral is not supported".to_string();
                        *active_workflow = None;
                        update_runbook_error(app, &message).await;
                        append_and_emit_system_message(app, message).await;
                        set_turn_in_progress(app, false).await;
                    }
                }
            }
            WorkflowAction::Blocked(message) => {
                *active_workflow = None;
                update_runbook_error(app, &message).await;
                append_and_emit_system_message(app, message).await;
                set_turn_in_progress(app, false).await;
            }
        }
    }
}

async fn start_workflow_lane_batch(
    client: &InProcessAppServerClient,
    request_counter: &mut i64,
    app: &AppHandle,
    runtime_config: &AgentRuntimeConfig,
    batch: &WorkflowLaneBatch,
) -> Result<ActiveLaneBatch, String> {
    if batch.lanes.is_empty() {
        return Err("workflow lane batch is empty".to_string());
    }

    let summary = if batch.is_repair {
        format!("{} repair gate", batch.title)
    } else {
        batch.title.clone()
    };
    app.state::<AppState>()
        .transcript_log
        .lock()
        .await
        .record_stage_start(&batch.stage_id, &lane_batch_prompt_text(batch));
    mutate_runbook(app, |runbook| {
        runbook.record_workflow_phase(&batch.stage_id, &summary);
    })
    .await;
    append_and_emit_system_message(
        app,
        format!(
            "SYS% workflow lane batch start\nWORKFLOW% phase={} stage={} repair={} concurrency={} attempts={} lanes={}",
            batch.phase_id,
            batch.stage_id,
            batch.is_repair,
            workflow_lane_concurrency().min(batch.lanes.len()),
            WORKFLOW_LANE_MAX_ATTEMPTS,
            batch
                .lanes
                .iter()
                .map(|lane| lane.lane_id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
    )
    .await;

    let mut runtime =
        ActiveLaneBatch::new(batch, workflow_lane_concurrency().min(batch.lanes.len()));
    for lane in &runtime.lanes {
        record_workflow_lane_status(
            app,
            WorkflowLaneStatus {
                stage_id: &runtime.stage_id,
                lane_id: &lane.lane_id,
                status: "queued",
                claim_count: None,
                candidate_count: None,
                thread_id: None,
                summary: &lane.title,
            },
        )
        .await;
    }

    let started =
        start_ready_workflow_lanes(client, request_counter, app, runtime_config, &mut runtime)
            .await?;
    if started == 0 && runtime.all_complete() {
        return Err("no workflow lane turns started".to_string());
    }

    Ok(runtime)
}

async fn start_ready_workflow_lanes(
    client: &InProcessAppServerClient,
    request_counter: &mut i64,
    app: &AppHandle,
    runtime_config: &AgentRuntimeConfig,
    batch: &mut ActiveLaneBatch,
) -> Result<usize, String> {
    let mut started = 0usize;
    while batch.running_count() < batch.max_concurrency {
        let Some(index) = batch.next_ready_lane_index(Instant::now()) else {
            break;
        };

        batch.lanes[index].mark_starting();
        let lane_id = batch.lanes[index].lane_id.clone();
        let attempt = batch.lanes[index].attempts;
        let summary = format!("starting attempt {attempt}/{WORKFLOW_LANE_MAX_ATTEMPTS}");
        record_workflow_lane_status(
            app,
            WorkflowLaneStatus {
                stage_id: &batch.stage_id,
                lane_id: &lane_id,
                status: "running",
                claim_count: None,
                candidate_count: None,
                thread_id: None,
                summary: &summary,
            },
        )
        .await;

        *request_counter += 1;
        let thread_response = client
            .request_typed::<ThreadStartResponse>(ClientRequest::ThreadStart {
                request_id: RequestId::Integer(*request_counter),
                params: ThreadStartParams {
                    cwd: Some(runtime_config.cwd.clone()),
                    model: runtime_config.model.clone(),
                    ephemeral: Some(true),
                    config: runtime_config.thread_config_overrides.clone(),
                    base_instructions: Some(runtime_config.base_instructions.clone()),
                    ..Default::default()
                },
            })
            .await;

        let thread_id = match thread_response {
            Ok(response) => response.thread.id,
            Err(e) => {
                mark_workflow_lane_start_error(
                    app,
                    batch,
                    index,
                    &format!("thread start failed: {e}"),
                )
                .await;
                continue;
            }
        };

        batch.lanes[index].thread_id = thread_id.clone();
        let summary = format!("thread started; attempt {attempt}/{WORKFLOW_LANE_MAX_ATTEMPTS}");
        record_workflow_lane_status(
            app,
            WorkflowLaneStatus {
                stage_id: &batch.stage_id,
                lane_id: &lane_id,
                status: "running",
                claim_count: None,
                candidate_count: None,
                thread_id: Some(&thread_id),
                summary: &summary,
            },
        )
        .await;

        *request_counter += 1;
        let prompt = batch.lanes[index].prompt.clone();
        match client
            .request_typed::<TurnStartResponse>(ClientRequest::TurnStart {
                request_id: RequestId::Integer(*request_counter),
                params: TurnStartParams {
                    thread_id: thread_id.clone(),
                    input: vec![UserInput::Text {
                        text: prompt,
                        text_elements: vec![],
                    }],
                    ..Default::default()
                },
            })
            .await
        {
            Ok(response) => {
                started += 1;
                batch.lanes[index].turn_id = Some(response.turn.id);
            }
            Err(e) => {
                mark_workflow_lane_start_error(
                    app,
                    batch,
                    index,
                    &format!("turn start failed: {e}"),
                )
                .await;
            }
        }
    }

    Ok(started)
}

async fn mark_workflow_lane_start_error(
    app: &AppHandle,
    batch: &mut ActiveLaneBatch,
    index: usize,
    error: &str,
) {
    let lane_id = batch.lanes[index].lane_id.clone();
    let thread_id = batch.lanes[index].thread_id.clone();
    let attempt = batch.lanes[index].attempts;
    let (status, summary) = if is_retryable_lane_error(error) && batch.can_retry(index) {
        let delay = batch.retry_lane(index, error);
        ("retrying", retry_status_summary(error, attempt, delay))
    } else {
        batch.finish_lane(index, /*failed*/ true);
        (
            "failed",
            format!(
                "lane start failed after attempt {attempt}/{WORKFLOW_LANE_MAX_ATTEMPTS}: {}",
                truncate_for_status(error, 220)
            ),
        )
    };
    let thread_id = if thread_id.is_empty() {
        None
    } else {
        Some(thread_id.as_str())
    };
    record_workflow_lane_status(
        app,
        WorkflowLaneStatus {
            stage_id: &batch.stage_id,
            lane_id: &lane_id,
            status,
            claim_count: Some(0),
            candidate_count: Some(0),
            thread_id,
            summary: &summary,
        },
    )
    .await;
    append_and_emit_system_message(app, format!("SYS% lane {lane_id} {status}; {summary}")).await;
}

async fn recover_idle_workflow_lanes(app: &AppHandle, batch: &mut ActiveLaneBatch) {
    let timeout = workflow_lane_idle_timeout();
    let idle_indices = batch.idle_running_lane_indices(Instant::now(), timeout);
    for index in idle_indices {
        if !matches!(
            batch.lanes.get(index).map(|lane| lane.status),
            Some(ActiveLaneStatus::Running)
        ) {
            continue;
        }
        let stage_id = batch.stage_id.clone();
        let lane_id = batch.lanes[index].lane_id.clone();
        let thread_id = batch.lanes[index].thread_id.clone();
        let attempt = batch.lanes[index].attempts;
        batch.finish_lane(index, /*failed*/ false);
        let lane_status = "done";
        let lane_detail = format!(
            "lane idle timeout after {}s without completion event; joined scheduler-owned lane after attempt={attempt}/{WORKFLOW_LANE_MAX_ATTEMPTS}",
            timeout.as_secs()
        );
        let thread_id = if thread_id.is_empty() {
            None
        } else {
            Some(thread_id.as_str())
        };
        record_workflow_lane_status(
            app,
            WorkflowLaneStatus {
                stage_id: &stage_id,
                lane_id: &lane_id,
                status: lane_status,
                claim_count: None,
                candidate_count: None,
                thread_id,
                summary: &lane_detail,
            },
        )
        .await;
        append_and_emit_system_message(
            app,
            format!("SYS% lane {lane_id} {lane_status}; {lane_detail}"),
        )
        .await;
    }
}

struct WorkflowLaneStatus<'a> {
    stage_id: &'a str,
    lane_id: &'a str,
    status: &'a str,
    claim_count: Option<usize>,
    candidate_count: Option<usize>,
    thread_id: Option<&'a str>,
    summary: &'a str,
}

async fn record_workflow_lane_status(
    app: &AppHandle,
    status: WorkflowLaneStatus<'_>,
) {
    mutate_runbook(app, |runbook| {
        runbook.record_subagent_lane(RunbookLaneUpdate {
            stage: status.stage_id,
            lane_id: status.lane_id,
            status: status.status,
            claim_count: status.claim_count,
            candidate_count: status.candidate_count,
            thread_id: status.thread_id,
            summary: status.summary,
        });
    })
    .await;
}

async fn append_chat_message(app: &AppHandle, role: &str, content: String) {
    let state = app.state::<AppState>();
    let timestamp = chrono::Utc::now().to_rfc3339();
    state.messages.lock().await.push(ChatMessage {
        role: role.to_string(),
        content: content.clone(),
        timestamp: timestamp.clone(),
    });
    let stage_hint = state.runbook.lock().await.current_stage.clone();
    state
        .transcript_log
        .lock()
        .await
        .record_message(&timestamp, role, &stage_hint, &content);
}

async fn append_and_emit_system_message(app: &AppHandle, content: String) {
    append_chat_message(app, "system", content.clone()).await;
    emit_fe(app, FrontendEvent::SystemMessage { content });
}

async fn set_turn_in_progress(app: &AppHandle, in_progress: bool) {
    let state = app.state::<AppState>();
    *state.turn_in_progress.lock().await = in_progress;
}

async fn update_runbook_turn_started(app: &AppHandle, turn_id: String) {
    mutate_runbook(app, |runbook| {
        runbook.set_turn_id(turn_id.clone());
    })
    .await;
    let state = app.state::<AppState>();
    state.transcript_log.lock().await.set_turn_id(&turn_id);
}

async fn update_runbook_completed(app: &AppHandle) -> RunbookState {
    mutate_runbook(app, |runbook| {
        runbook.complete();
    })
    .await
}

async fn append_turn_completed_message(app: &AppHandle, status: &str, runbook: &RunbookState) {
    let incomplete = runbook.status == runbook::RunbookStatus::Error;
    let mut lines = if incomplete {
        vec![format!("SYS% turn incomplete; status={status}")]
    } else {
        vec![format!("SYS% turn completed; status={status}")]
    };
    lines.push(format!(
        "RUNBOOK% final findings={}",
        runbook.final_findings.len()
    ));
    if incomplete {
        lines.push(
            "RUNBOOK% blocked before final PoC bundle; check Scan watchdog evidence".to_string(),
        );
    } else if !runbook.final_findings.is_empty() {
        lines.push("POC_BUNDLE% final PoC bundle is ready in Findings".to_string());
    } else {
        lines.push("REPORT% no final findings were produced".to_string());
    }
    append_chat_message(app, "system", lines.join("\n")).await;
    app.state::<AppState>()
        .transcript_log
        .lock()
        .await
        .finish_turn(status, runbook);
}

async fn record_stage_snapshot(app: &AppHandle, runbook: &RunbookState, status: &str) {
    app.state::<AppState>()
        .transcript_log
        .lock()
        .await
        .record_stage_snapshot(&runbook.current_stage, status, runbook);
}

async fn update_runbook_error(app: &AppHandle, message: &str) {
    mutate_runbook(app, |runbook| {
        runbook.fail(message);
    })
    .await;
}

fn lane_batch_prompt_text(batch: &WorkflowLaneBatch) -> String {
    batch
        .lanes
        .iter()
        .map(|lane| {
            format!(
                "## {}\n\nLANE% {}\n\n{}",
                lane.title, lane.lane_id, lane.prompt
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n---\n\n")
}
