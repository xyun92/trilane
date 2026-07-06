include!("runbook_types.inc.rs");
include!("runbook_lifecycle.inc.rs");
include!("runbook_findings.inc.rs");
include!("runbook_claims_impl.inc.rs");
include!("runbook_attack_graph.inc.rs");
include!("runbook_gates.inc.rs");
include!("runbook_progress.inc.rs");
include!("runbook_helpers.inc.rs");

#[cfg(test)]
mod tests {
    use super::scan_progress_from_runbook;
    use super::AuditMode;
    use super::RunbookLaneUpdate;
    use super::RunbookState;
    use super::RunbookStatus;
    use super::StageStatus;

    include!("runbook_tests.inc.rs");
    include!("runbook_state_sync_tests.inc.rs");
}
