async fn agent_event_loop(
    mut client: InProcessAppServerClient,
    mut cmd_rx: mpsc::Receiver<AgentCommand>,
    app: AppHandle,
    thread_id: String,
    runtime_config: AgentRuntimeConfig,
) {
    let mut request_counter: i64 = 100;
    let mut active_workflow: Option<TriLaneWorkflow> = None;
    let mut active_lane_batch: Option<ActiveLaneBatch> = None;

    loop {
        tokio::select! {
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    AgentCommand::SendMessage { text, audit_mode } => {
                        warn!("GUI send_message received text_len={}", text.len());
                        active_lane_batch = None;
                        let mut workflow = TriLaneWorkflow::new(text.clone());
                        let snapshot = runbook_snapshot(&app).await;
                        let agent_input = match workflow.begin(&snapshot) {
                            WorkflowAction::Submit(prompt) => {
                                start_workflow_phase(&app, &prompt).await;
                                active_workflow = Some(workflow);
                                prompt.prompt
                            }
                            WorkflowAction::SpawnLanes(batch) => {
                                active_workflow = Some(workflow);
                                match start_workflow_lane_batch(
                                    &client,
                                    &mut request_counter,
                                    &app,
                                    &runtime_config,
                                    &batch,
                                )
                                .await
                                {
                                    Ok(batch_runtime) => {
                                        active_lane_batch = Some(batch_runtime);
                                        continue;
                                    }
                                    Err(e) => {
                                        active_workflow = None;
                                        let message = format!("Workflow lane start failed: {e}");
                                        update_runbook_error(&app, &message).await;
                                        append_and_emit_system_message(&app, message.clone()).await;
                                        set_turn_in_progress(&app, false).await;
                                        continue;
                                    }
                                }
                            }
                            WorkflowAction::Complete => audit_mode_user_input(&audit_mode, &text),
                            WorkflowAction::Blocked(message) => {
                                append_and_emit_system_message(&app, message.clone()).await;
                                update_runbook_error(&app, &message).await;
                                set_turn_in_progress(&app, false).await;
                                continue;
                            }
                        };
                        match submit_agent_turn(&mut client, &mut request_counter, &thread_id, agent_input).await {
                            Ok(_resp) => { info!("Turn started"); }
                            Err(e) => {
                                active_workflow = None;
                                set_turn_in_progress(&app, false).await;
                                emit_fe(&app, FrontendEvent::Error { message: format!("Turn start failed: {e}") });
                            }
                        }
                    }
                    AgentCommand::Approve {
                        request_id,
                        decision,
                    } => {
                        info!("Approval command received: {request_id} -> {decision}");
                    }
                    AgentCommand::Shutdown => {
                        info!("Shutting down agent");
                        let _ = client.shutdown().await;
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(WORKFLOW_LANE_RETRY_TICK), if active_lane_batch.is_some() => {
                if let Some(batch) = active_lane_batch.as_mut() {
                    let start_result = start_ready_workflow_lanes(
                        &client,
                        &mut request_counter,
                        &app,
                        &runtime_config,
                        batch,
                    )
                    .await;
                    if let Err(e) = start_result
                {
                    let message = format!("Workflow lane scheduler failed: {e}");
                    active_workflow = None;
                    update_runbook_error(&app, &message).await;
                    append_and_emit_system_message(&app, message).await;
                    set_turn_in_progress(&app, false).await;
                    continue;
                    }
                }

                let lane_batch_complete = active_lane_batch
                    .as_ref()
                    .is_some_and(ActiveLaneBatch::all_complete);
                let completed_phase_id = active_lane_batch
                    .as_ref()
                    .map(|batch| batch.phase_id.clone())
                    .unwrap_or_default();
                if lane_batch_complete {
                    advance_workflow_after_lane_batch(
                        WorkflowAdvanceContext {
                            client: &mut client,
                            request_counter: &mut request_counter,
                            app: &app,
                            runtime_config: &runtime_config,
                            root_thread_id: &thread_id,
                            active_workflow: &mut active_workflow,
                            active_lane_batch: &mut active_lane_batch,
                        },
                        completed_phase_id,
                        "LaneBatchCompleted",
                    )
                    .await;
                }
            }
            event = client.next_event() => {
                match event {
                    Some(ServerEvent::ServerNotification(notification)) => {
                        match notification {
                            ServerNotification::AgentMessageDelta(delta) => {
                                update_runbook_from_agent_delta(
                                    &app,
                                    &delta.item_id,
                                    &delta.delta,
                                )
                                .await;
                                emit_fe(&app, FrontendEvent::AgentMessageDelta {
                                    thread_id: delta.thread_id,
                                    turn_id: delta.turn_id,
                                    item_id: delta.item_id,
                                    delta: delta.delta,
                                });
                            }
                            ServerNotification::CommandExecutionOutputDelta(delta) => {
                                emit_fe(&app, FrontendEvent::CommandOutputDelta {
                                    thread_id: delta.thread_id,
                                    turn_id: delta.turn_id,
                                    item_id: delta.item_id,
                                    delta: delta.delta,
                                });
                            }
                            ServerNotification::ItemCompleted(item) => {
                                let (item_type, role, text) =
                                    frontend_item_completed_payload(&item.item);
                                flush_pending_runbook_markers(&app).await;
                                if let (Some(role), Some(text)) = (&role, &text) {
                                    append_chat_message(&app, role, text.clone()).await;
                                }
                                update_runbook_from_item(&app, &item.item, &text).await;
                                emit_fe(&app, FrontendEvent::ItemCompleted {
                                    thread_id: item.thread_id,
                                    turn_id: item.turn_id,
                                    item_id: format!("{:?}", item.item),
                                    item_type,
                                    role,
                                    text,
                                });
                            }
                            ServerNotification::TurnCompleted(turn) => {
                                flush_pending_runbook_markers(&app).await;
                                clear_agent_delta_buffers(&app).await;
                                warn!(
                                    "ServerNotification::TurnCompleted status={:?} has_error={}",
                                    turn.turn.status,
                                    turn.turn.error.is_some()
                                );
                                let turn_error =
                                    turn.turn.error.as_ref().map(|error| error.message.clone());
                                let status = format!("{:?}", turn.turn.status);

                                let lane_completion = if let Some(batch) =
                                    active_lane_batch.as_mut()
                                {
                                    if let Some(index) = batch.lane_index_by_thread(&turn.thread_id)
                                    {
                                        let stage_id = batch.stage_id.clone();
                                        let lane_id = batch.lanes[index].lane_id.clone();
                                        let attempt = batch.lanes[index].attempts;
                                        let retryable_error = turn_error
                                            .as_deref()
                                            .is_some_and(is_retryable_lane_error);
                                        let should_retry = turn_error.as_deref().is_some()
                                            && retryable_error
                                            && batch.can_retry(index);
                                        let (lane_status, lane_detail) = if should_retry {
                                            if let Some(error) = turn_error.as_deref() {
                                                let delay = batch.retry_lane(index, error);
                                                (
                                                    "retrying",
                                                    retry_status_summary(error, attempt, delay),
                                                )
                                            } else {
                                                ("failed", "missing retryable lane error".to_string())
                                            }
                                        } else {
                                            batch.finish_lane(index, turn_error.is_some());
                                            (
                                                if turn_error.is_some() {
                                                    "failed"
                                                } else {
                                                    "done"
                                                },
                                                turn_error
                                                    .as_deref()
                                                    .unwrap_or("lane turn completed")
                                                    .to_string(),
                                            )
                                        };
                                        Some((
                                            stage_id,
                                            lane_id,
                                            lane_status.to_string(),
                                            lane_detail,
                                        ))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                if let Some((stage_id, lane_id, lane_status, lane_detail)) =
                                    lane_completion
                                {
                                    record_workflow_lane_status(
                                        &app,
                                        &stage_id,
                                        &lane_id,
                                        &lane_status,
                                        None,
                                        None,
                                        Some(&turn.thread_id),
                                        &lane_detail,
                                    )
                                    .await;
                                    append_and_emit_system_message(
                                        &app,
                                        format!(
                                            "SYS% lane {lane_id} {lane_status}; status={status}"
                                        ),
                                    )
                                    .await;
                                    emit_fe(&app, FrontendEvent::TurnCompleted {
                                        thread_id: turn.thread_id.clone(),
                                        turn_id: turn.turn.id.clone(),
                                        status: format!("LaneCompleted:{lane_id}:{status}"),
                                    });

                                    if let Some(batch) = active_lane_batch.as_mut() {
                                        let start_result = start_ready_workflow_lanes(
                                            &client,
                                            &mut request_counter,
                                            &app,
                                            &runtime_config,
                                            batch,
                                        )
                                        .await;
                                        if let Err(e) = start_result
                                    {
                                        let message =
                                            format!("Workflow lane scheduler failed: {e}");
                                        active_workflow = None;
                                        update_runbook_error(&app, &message).await;
                                        append_and_emit_system_message(&app, message).await;
                                        set_turn_in_progress(&app, false).await;
                                        continue;
                                        }
                                    }

                                    let lane_batch_complete = active_lane_batch
                                        .as_ref()
                                        .is_some_and(ActiveLaneBatch::all_complete);
                                    let completed_phase_id = active_lane_batch
                                        .as_ref()
                                        .map(|batch| batch.phase_id.clone())
                                        .unwrap_or_default();
                                    if lane_batch_complete {
                                        advance_workflow_after_lane_batch(
                                            WorkflowAdvanceContext {
                                                client: &mut client,
                                                request_counter: &mut request_counter,
                                                app: &app,
                                                runtime_config: &runtime_config,
                                                root_thread_id: &thread_id,
                                                active_workflow: &mut active_workflow,
                                                active_lane_batch: &mut active_lane_batch,
                                            },
                                            completed_phase_id,
                                            &status,
                                        )
                                        .await;
                                    }
                                    continue;
                                }

                                if let Some(message) = turn_error {
                                    append_chat_message(&app, "system", message.clone()).await;
                                    update_runbook_error(&app, &message).await;
                                    emit_fe(
                                        &app,
                                        FrontendEvent::Error {
                                            message: message.clone(),
                                        },
                                    );
                                    active_workflow = None;
                                    set_turn_in_progress(&app, false).await;
                                    let runbook = update_runbook_completed(&app).await;
                                    append_turn_completed_message(&app, &status, &runbook).await;
                                    emit_fe(&app, FrontendEvent::TurnCompleted {
                                        thread_id: turn.thread_id,
                                        turn_id: turn.turn.id.clone(),
                                        status: format!("Failed: {message}"),
                                    });
                                    continue;
                                }

                                let workflow_action = if let Some(workflow) = active_workflow.as_mut() {
                                    let snapshot = runbook_snapshot(&app).await;
                                    Some(workflow.after_turn_completed(&snapshot))
                                } else {
                                    None
                                };

                                if let Some(action) = workflow_action {
                                    match action {
                                        WorkflowAction::Submit(prompt) => {
                                            start_workflow_phase(&app, &prompt).await;
                                            emit_fe(&app, FrontendEvent::TurnCompleted {
                                                thread_id: turn.thread_id.clone(),
                                                turn_id: turn.turn.id.clone(),
                                                status: format!("PhaseCompleted:{status}"),
                                            });
                                            match submit_agent_turn(
                                                &mut client,
                                                &mut request_counter,
                                                &thread_id,
                                                prompt.prompt,
                                            )
                                            .await
                                            {
                                                Ok(_resp) => {
                                                    info!("Workflow phase turn started");
                                                }
                                                Err(e) => {
                                                    let message = format!("Workflow turn start failed: {e}");
                                                    active_workflow = None;
                                                    update_runbook_error(&app, &message).await;
                                                    append_and_emit_system_message(&app, message.clone()).await;
                                                    set_turn_in_progress(&app, false).await;
                                                }
                                            }
                                            continue;
                                        }
                                        WorkflowAction::SpawnLanes(batch) => {
                                            match start_workflow_lane_batch(
                                                &client,
                                                &mut request_counter,
                                                &app,
                                                &runtime_config,
                                                &batch,
                                            )
                                            .await
                                            {
                                                Ok(batch_runtime) => {
                                                    active_lane_batch = Some(batch_runtime);
                                                }
                                                Err(e) => {
                                                    let message = format!(
                                                        "Workflow lane start failed: {e}"
                                                    );
                                                    active_workflow = None;
                                                    update_runbook_error(&app, &message).await;
                                                    append_and_emit_system_message(
                                                        &app,
                                                        message.clone(),
                                                    )
                                                    .await;
                                                    set_turn_in_progress(&app, false).await;
                                                }
                                            }
                                            continue;
                                        }
                                        WorkflowAction::Complete => {
                                            active_workflow = None;
                                        }
                                        WorkflowAction::Blocked(message) => {
                                            active_workflow = None;
                                            update_runbook_error(&app, &message).await;
                                            append_and_emit_system_message(&app, message).await;
                                        }
                                    }
                                }

                                set_turn_in_progress(&app, false).await;
                                let runbook = update_runbook_completed(&app).await;
                                append_turn_completed_message(&app, &status, &runbook).await;
                                emit_fe(&app, FrontendEvent::TurnCompleted {
                                    thread_id: turn.thread_id,
                                    turn_id: turn.turn.id.clone(),
                                    status,
                                });
                            }
                            ServerNotification::TurnStarted(turn) => {
                                flush_pending_runbook_markers(&app).await;
                                clear_agent_delta_buffers(&app).await;
                                warn!("ServerNotification::TurnStarted turn_id={}", turn.turn.id);
                                let lane_started =
                                    active_lane_batch.as_mut().and_then(|batch| {
                                        let stage_id = batch.stage_id.clone();
                                        batch
                                            .mark_turn_started(
                                                &turn.thread_id,
                                                turn.turn.id.clone(),
                                            )
                                            .map(|lane_id| (stage_id, lane_id))
                                    });
                                if let Some((stage_id, lane_id)) = lane_started {
                                    record_workflow_lane_status(
                                        &app,
                                        &stage_id,
                                        &lane_id,
                                        "running",
                                        None,
                                        None,
                                        Some(&turn.thread_id),
                                        "lane turn started",
                                    )
                                    .await;
                                    emit_fe(&app, FrontendEvent::TurnStarted {
                                        thread_id: turn.thread_id.clone(),
                                        turn_id: turn.turn.id.clone(),
                                    });
                                    continue;
                                }
                                update_runbook_turn_started(&app, turn.turn.id.clone()).await;
                                emit_fe(&app, FrontendEvent::TurnStarted {
                                    thread_id: turn.thread_id.clone(),
                                    turn_id: turn.turn.id.clone(),
                                });
                            }
                            ServerNotification::Error(error) => {
                                warn!(
                                    "ServerNotification::Error message={}",
                                    error.error.message
                                );
                                if active_lane_batch.is_some() {
                                    append_and_emit_system_message(
                                        &app,
                                        format!(
                                            "SYS% transient lane provider error; waiting for lane completion/retry\n{}",
                                            error.error.message
                                        ),
                                    )
                                    .await;
                                    continue;
                                }
                                active_workflow = None;
                                append_chat_message(&app, "system", error.error.message.clone())
                                    .await;
                                update_runbook_error(&app, &error.error.message).await;
                                emit_fe(
                                    &app,
                                    FrontendEvent::Error {
                                        message: error.error.message,
                                    },
                                );
                                set_turn_in_progress(&app, false).await;
                            }
                            _ => {}
                        }
                    }
                    Some(ServerEvent::ServerRequest(request)) => {
                        match &request {
                            ServerRequest::CommandExecutionRequestApproval { request_id, params } => {
                                let decision = if runtime_config.audit_mode.grants_full_access() {
                                    "accept"
                                } else {
                                    "decline"
                                };
                                emit_fe(&app, FrontendEvent::ApprovalRequired {
                                    request_id: format!("{request_id:?}"),
                                    approval_type: "command".to_string(),
                                    command: params.command.clone(),
                                    cwd: params.cwd.as_ref().map(|p| p.to_string_lossy().to_string()),
                                    reason: params.reason.clone(),
                                });
                                if decision == "decline" {
                                    append_and_emit_system_message(
                                        &app,
                                        format!(
                                            "SYS% safe mode declined approval request for command: {}",
                                            params.command.clone().unwrap_or_default()
                                        ),
                                    )
                                    .await;
                                }
                                let _ = client.resolve_server_request(
                                    request_id.clone(),
                                    serde_json::json!({ "decision": decision }),
                                ).await;
                            }
                            ServerRequest::FileChangeRequestApproval { request_id, params } => {
                                let decision = if runtime_config.audit_mode.grants_full_access() {
                                    "accept"
                                } else {
                                    "decline"
                                };
                                emit_fe(&app, FrontendEvent::ApprovalRequired {
                                    request_id: format!("{request_id:?}"),
                                    approval_type: "file_change".to_string(),
                                    command: None,
                                    cwd: params.grant_root.as_ref().map(|p| p.to_string_lossy().to_string()),
                                    reason: params.reason.clone(),
                                });
                                if decision == "decline" {
                                    append_and_emit_system_message(
                                        &app,
                                        "SYS% safe mode declined approval request for file changes"
                                            .to_string(),
                                    )
                                    .await;
                                }
                                let _ = client.resolve_server_request(
                                    request_id.clone(),
                                    serde_json::json!({ "decision": decision }),
                                ).await;
                            }
                            _ => {
                                let _ = client.reject_server_request(
                                    request.id().clone(),
                                    codex_app_server_protocol::JSONRPCErrorError {
                                        code: -32601,
                                        message: "unsupported".to_string(),
                                        data: None,
                                    },
                                ).await;
                            }
                        }
                    }
                    Some(ServerEvent::Lagged { skipped }) => {
                        warn!("Event stream lagged, {skipped} events dropped");
                        emit_fe(&app, FrontendEvent::Lagged { skipped });
                    }
                    None => {
                        info!("Event stream closed");
                        break;
                    }
                }
            }
        }
    }
    info!("Agent event loop exited");
}
