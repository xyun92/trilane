// ── Types exposed to frontend ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub location: String,
    pub code_path: String,
    pub description: String,
    pub payload: String,
    pub cwe: String,
    pub confidence: String,
    pub evidence_state: String,
    pub duplicate_count: usize,
    pub original_id: String,
    pub candidate_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub stage: String,
    pub stage_name: String,
    pub progress: f32,
    pub message: String,
    pub findings_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FrontendEvent {
    AgentMessageDelta {
        thread_id: String,
        turn_id: String,
        item_id: String,
        delta: String,
    },
    CommandOutputDelta {
        thread_id: String,
        turn_id: String,
        item_id: String,
        delta: String,
    },
    ItemCompleted {
        thread_id: String,
        turn_id: String,
        item_id: String,
        item_type: String,
        role: Option<String>,
        text: Option<String>,
    },
    TurnCompleted {
        thread_id: String,
        turn_id: String,
        status: String,
    },
    TurnStarted {
        thread_id: String,
        turn_id: String,
    },
    SystemMessage {
        content: String,
    },
    ApprovalRequired {
        request_id: String,
        approval_type: String,
        command: Option<String>,
        cwd: Option<String>,
        reason: Option<String>,
    },
    Error {
        message: String,
    },
    Lagged {
        skipped: usize,
    },
    RunbookUpdated {
        state: Box<RunbookState>,
    },
}

// ── Application state ────────────────────────────────────────────────────

#[derive(Default)]
struct PendingRunbookMarkers {
    lines: Vec<String>,
    queued_at: Option<Instant>,
}

struct AppState {
    arg0_paths: Arg0DispatchPaths,
    msg_tx: Mutex<Option<mpsc::Sender<AgentCommand>>>,
    thread_id: Mutex<Option<String>>,
    turn_in_progress: Mutex<bool>,
    messages: Mutex<Vec<ChatMessage>>,
    runbook: Mutex<RunbookState>,
    agent_delta_marker_buffers: Mutex<HashMap<String, String>>,
    pending_runbook_markers: Mutex<PendingRunbookMarkers>,
    state_store: TriLaneStateStore,
    transcript_log: Mutex<TranscriptArchive>,
}

#[derive(Clone)]
struct AgentRuntimeConfig {
    model: Option<String>,
    cwd: String,
    base_instructions: String,
    thread_config_overrides: Option<HashMap<String, serde_json::Value>>,
    audit_mode: AuditMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveLaneStatus {
    Queued,
    Running,
    Done,
    Failed,
}

struct ActiveLane {
    lane_id: String,
    title: String,
    prompt: String,
    thread_id: String,
    turn_id: Option<String>,
    status: ActiveLaneStatus,
    attempts: u8,
    retry_ready_at: Option<Instant>,
    last_error: Option<String>,
}

struct ActiveLaneBatch {
    phase_id: String,
    stage_id: String,
    max_concurrency: usize,
    lanes: Vec<ActiveLane>,
}

struct WorkflowAdvanceContext<'a> {
    client: &'a mut InProcessAppServerClient,
    request_counter: &'a mut i64,
    app: &'a AppHandle,
    runtime_config: &'a AgentRuntimeConfig,
    root_thread_id: &'a str,
    active_workflow: &'a mut Option<TriLaneWorkflow>,
    active_lane_batch: &'a mut Option<ActiveLaneBatch>,
}

impl ActiveLaneBatch {
    fn new(batch: &WorkflowLaneBatch, max_concurrency: usize) -> Self {
        Self {
            phase_id: batch.phase_id.clone(),
            stage_id: batch.stage_id.clone(),
            max_concurrency: max_concurrency.max(1),
            lanes: batch.lanes.iter().map(ActiveLane::queued).collect(),
        }
    }

    fn mark_turn_started(&mut self, thread_id: &str, turn_id: String) -> Option<String> {
        let lane = self
            .lanes
            .iter_mut()
            .find(|lane| lane.thread_id == thread_id && lane.status == ActiveLaneStatus::Running)?;
        lane.turn_id = Some(turn_id);
        Some(lane.lane_id.clone())
    }

    fn lane_index_by_thread(&self, thread_id: &str) -> Option<usize> {
        self.lanes.iter().position(|lane| {
            lane.thread_id == thread_id && lane.status == ActiveLaneStatus::Running
        })
    }

    fn finish_lane(&mut self, index: usize, failed: bool) {
        if let Some(lane) = self.lanes.get_mut(index) {
            lane.status = if failed {
                ActiveLaneStatus::Failed
            } else {
                ActiveLaneStatus::Done
            };
            lane.retry_ready_at = None;
        }
    }

    fn retry_lane(&mut self, index: usize, error: &str) -> Duration {
        let delay = workflow_lane_retry_delay(self.lanes[index].attempts);
        let lane = &mut self.lanes[index];
        lane.status = ActiveLaneStatus::Queued;
        lane.thread_id.clear();
        lane.turn_id = None;
        lane.retry_ready_at = Some(Instant::now() + delay);
        lane.last_error = Some(error.to_string());
        delay
    }

    fn running_count(&self) -> usize {
        self.lanes
            .iter()
            .filter(|lane| lane.status == ActiveLaneStatus::Running)
            .count()
    }

    fn next_ready_lane_index(&self, now: Instant) -> Option<usize> {
        self.lanes.iter().position(|lane| {
            lane.status == ActiveLaneStatus::Queued
                && lane.retry_ready_at.is_none_or(|ready_at| ready_at <= now)
        })
    }

    fn can_retry(&self, index: usize) -> bool {
        self.lanes
            .get(index)
            .is_some_and(|lane| lane.attempts < WORKFLOW_LANE_MAX_ATTEMPTS)
    }

    fn all_complete(&self) -> bool {
        self.lanes.iter().all(|lane| {
            matches!(
                lane.status,
                ActiveLaneStatus::Done | ActiveLaneStatus::Failed
            )
        })
    }
}

impl ActiveLane {
    fn queued(spec: &WorkflowLaneSpec) -> Self {
        Self {
            lane_id: spec.lane_id.clone(),
            title: spec.title.clone(),
            prompt: spec.prompt.clone(),
            thread_id: String::new(),
            turn_id: None,
            status: ActiveLaneStatus::Queued,
            attempts: 0,
            retry_ready_at: None,
            last_error: None,
        }
    }

    fn mark_starting(&mut self) {
        self.status = ActiveLaneStatus::Running;
        self.attempts = self.attempts.saturating_add(1);
        self.thread_id.clear();
        self.turn_id = None;
        self.retry_ready_at = None;
        self.last_error = None;
    }
}
