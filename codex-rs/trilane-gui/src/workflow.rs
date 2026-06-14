use crate::runbook::CandidateStatus;
use crate::runbook::RunbookState;

const MAX_REPAIRS_PER_PHASE: usize = 1;

include!("workflow_core.inc.rs");
include!("workflow_prompts.inc.rs");
include!("workflow_phases.inc.rs");

#[cfg(test)]
mod tests {
    use super::TriLaneWorkflow;
    use super::WorkflowAction;
    use crate::runbook::AuditMode;
    use crate::runbook::RunbookState;

    include!("workflow_tests.inc.rs");
}
