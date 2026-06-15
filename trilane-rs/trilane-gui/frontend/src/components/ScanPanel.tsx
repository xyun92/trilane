import AsmGraph from "./AsmGraph";

interface ScanProgress {
  stage: string;
  stage_name: string;
  progress: number;
  message: string;
  findings_count: number;
}

interface RunbookStage {
  id: string;
  code: string;
  name: string;
  label: string;
  status: "pending" | "active" | "done" | "blocked";
  summary: string;
  evidence_count: number;
  candidate_count: number;
  findings_count: number;
  updated_at: string;
}

interface RunbookCoverage {
  id: string;
  category: string;
  label: string;
  mapped_count: number;
  total_hint: number | null;
  status: "pending" | "mapped" | "partial";
  updated_at: string;
}

interface RunbookCandidate {
  id: string;
  stage: string;
  category: string;
  title: string;
  target: string;
  status:
    | "candidate"
    | "probed"
    | "needs_verify"
    | "rejected"
    | "duplicate"
    | "out_of_scope"
    | "confirmed";
  severity: string | null;
  evidence_count: number;
  verification_count: number;
  source_confirmed: boolean;
  updated_at: string;
}

interface RunbookSurface {
  id: string;
  stage: string;
  kind: string;
  category: string;
  label: string;
  target: string;
  signal_count: number;
  updated_at: string;
}

interface RunbookClaim {
  id: string;
  fingerprint: string;
  stage: string;
  category: string;
  title: string;
  target: string;
  status:
    | "seed"
    | "anchored"
    | "armed"
    | "running"
    | "corroborated"
    | "verified"
    | "weaponized"
    | "publishable"
    | "blocked"
    | "discarded"
    | "merged";
  evidence_level:
    | "signal"
    | "source_backed"
    | "runtime_signal"
    | "reproducible"
    | "impact_proven"
    | "control_passed";
  severity: string | null;
  code_path: string;
  root_cause: string;
  precondition: string;
  impact: string;
  payload: string;
  positive_evidence: string;
  negative_evidence: string;
  merged_into: string | null;
  signal_count: number;
  probe_count: number;
  verification_count: number;
  updated_at: string;
}

interface RunbookClaimSummary {
  surfaces: number;
  raw_signals: number;
  root_claims: number;
  publishable: number;
  verified: number;
  blocked: number;
  discarded: number;
  merged: number;
  coverage_debt: number;
  evidence_ladder_complete: number;
}

interface RunbookEvidence {
  id: string;
  stage: string;
  kind: string;
  title: string;
  detail: string;
  timestamp: string;
}

interface RunbookFinding {
  id: string;
  stage: string;
  candidate_id: string | null;
  severity: string;
  title: string;
  code_path: string;
  confidence: string;
  evidence_state: string;
  detail: string;
  timestamp: string;
}

interface RunbookAttackAtom {
  id: string;
  stage: string;
  lane_id: string;
  kind: string;
  category: string;
  target: string;
  label: string;
  claim_id: string | null;
  bridge_keys: string[];
  evidence: string;
  confidence: string;
}

interface RunbookChainCandidate {
  id: string;
  stage: string;
  title: string;
  status: string;
  impact: string;
  atom_ids: string[];
  bridge_keys: string[];
  verify_plan: string;
  score: number;
}

interface RunbookStats {
  coverage_mapped: number;
  coverage_total: number;
  coverage_debt: number;
  surfaces: number;
  surface_covered: number;
  domain_queues: number;
  domain_queues_closed: number;
  hypothesis_count: number;
  hypothesis_floor: number;
  hypothesis_debt: number;
  candidates: number;
  root_claims: number;
  probed: number;
  rejected: number;
  merged_claims: number;
  blocked_claims: number;
  discarded_claims: number;
  needs_verify: number;
  confirmed: number;
  publishable_claims: number;
  source_confirmed: number;
  evidence_signals: number;
}

interface RunbookState {
  status: "idle" | "running" | "completed" | "error";
  audit_mode: "safe" | "lab";
  objective: string;
  current_stage: string;
  turn_id: string | null;
  stages: RunbookStage[];
  coverage: RunbookCoverage[];
  surfaces: RunbookSurface[];
  candidates: RunbookCandidate[];
  claims: RunbookClaim[];
  attack_atoms: RunbookAttackAtom[];
  chain_candidates: RunbookChainCandidate[];
  evidence: RunbookEvidence[];
  findings: RunbookFinding[];
  claim_summary: RunbookClaimSummary;
  stats: RunbookStats;
  last_updated: string;
}

interface Props {
  runbook: RunbookState | null;
  progress: ScanProgress | null;
  auditMode: "safe" | "lab";
}

const FALLBACK_STAGES: RunbookStage[] = [
  { id: "stage0", code: "S0", name: "Gate", label: "", status: "pending", summary: "waiting for agent objective", evidence_count: 0, candidate_count: 0, findings_count: 0, updated_at: "" },
  { id: "stage1", code: "S1", name: "Recon", label: "", status: "pending", summary: "waiting for source/sink map", evidence_count: 0, candidate_count: 0, findings_count: 0, updated_at: "" },
  { id: "stage2", code: "S2", name: "Audit", label: "", status: "pending", summary: "waiting for exploitability evidence", evidence_count: 0, candidate_count: 0, findings_count: 0, updated_at: "" },
  { id: "stage3", code: "S3", name: "FoA", label: "", status: "pending", summary: "waiting for summary", evidence_count: 0, candidate_count: 0, findings_count: 0, updated_at: "" },
  { id: "stage4", code: "S4", name: "Fuzz", label: "", status: "pending", summary: "future fuzzy lane", evidence_count: 0, candidate_count: 0, findings_count: 0, updated_at: "" },
  { id: "stage5", code: "S5", name: "Verify", label: "", status: "pending", summary: "future isolation lane", evidence_count: 0, candidate_count: 0, findings_count: 0, updated_at: "" },
];

const DEFAULT_STATS: RunbookStats = {
  coverage_mapped: 0,
  coverage_total: 15,
  coverage_debt: 0,
  surfaces: 0,
  surface_covered: 0,
  domain_queues: 0,
  domain_queues_closed: 0,
  hypothesis_count: 0,
  hypothesis_floor: 0,
  hypothesis_debt: 0,
  candidates: 0,
  root_claims: 0,
  probed: 0,
  rejected: 0,
  merged_claims: 0,
  blocked_claims: 0,
  discarded_claims: 0,
  needs_verify: 0,
  confirmed: 0,
  publishable_claims: 0,
  source_confirmed: 0,
  evidence_signals: 0,
};

const TRILANE_COVERAGE: RunbookCoverage[] = [
  ["auth", "Authentication bypass"],
  ["authz", "Authorization and IDOR"],
  ["session", "Session/token lifecycle"],
  ["injection", "SQL/NoSQL/template/command injection"],
  ["xss", "Reflected/stored/DOM XSS"],
  ["cors_headers_tls", "CORS, browser trust, and header posture"],
  ["ssrf_redirect", "SSRF and open redirect"],
  ["file_upload_xxe", "Upload parsers and XXE"],
  ["traversal_lfi", "Path traversal and local file read"],
  ["state_invariant_abuse", "State-machine and invariant abuse"],
  ["anti_automation_bypass", "Anti-automation and recovery-control bypass"],
  ["rate_limit", "Rate limiting and brute force"],
  ["secrets_config", "Secrets, keys, and config exposure"],
  ["observability_leak", "Metrics, logs, docs, and diagnostics exposure"],
  ["crypto", "Crypto and password storage"],
].map(([category, label]) => ({
  id: `coverage-${category}`,
  category,
  label,
  mapped_count: 0,
  total_hint: null,
  status: "pending" as const,
  updated_at: "",
}));

export default function ScanPanel({ runbook, progress, auditMode }: Props) {
  const stages = runbook?.stages ?? FALLBACK_STAGES;
  const currentStageIdx = stages.findIndex((stage) => stage.id === (runbook?.current_stage ?? ""));
  const latestEvidence = runbook?.evidence.slice(-8).reverse() ?? [];
  const latestFindings = runbook?.findings.slice(-6).reverse() ?? [];
  const latestCandidates = runbook?.candidates.slice(-8).reverse() ?? [];
  const latestClaims = runbook?.claims.slice(-8).reverse() ?? [];
  const latestSurfaces = runbook?.surfaces.slice(-6).reverse() ?? [];
  const latestAtoms = runbook?.attack_atoms?.slice(-6).reverse() ?? [];
  const latestChains = runbook?.chain_candidates?.slice(0, 6) ?? [];
  const previewCoverage = TRILANE_COVERAGE;
  const coverage = runbook && runbook.status !== "idle" ? runbook.coverage : previewCoverage;
  const stats = runbook && runbook.status !== "idle"
    ? runbook.stats
    : { ...DEFAULT_STATS, coverage_total: previewCoverage.length };
  const status = runbook?.status ?? "idle";
  const displayMode = runbook && runbook.status !== "idle" ? runbook.audit_mode : auditMode;

  return (
    <div className="scan-panel">
      <div className="scan-topline">
        <div>
          <span className="eyebrow">SCAN/RUNBOOK</span>
          <h2>SOP 4.0 projection</h2>
        </div>
        <div className={`scan-state ${status === "running" ? "active" : ""}`}>
          {status.toUpperCase()}
        </div>
      </div>

      <div className="runbook-brief">
        <div>
          <span>OBJECTIVE</span>
          <strong>{runbook?.objective || "No active agent objective. Describe the target in AGENT."}</strong>
        </div>
        <div>
          <span>TURN</span>
          <strong>{runbook?.turn_id || "standby"}</strong>
        </div>
        <div>
          <span>CONFIRMED</span>
          <strong>{stats.confirmed}</strong>
        </div>
        <div>
          <span>CANDIDATES</span>
          <strong>{stats.candidates}</strong>
        </div>
        <div>
          <span>HYPOTHESES</span>
          <strong>{stats.hypothesis_floor > 0 ? `${stats.hypothesis_count}/${stats.hypothesis_floor}` : stats.hypothesis_count}</strong>
        </div>
        <div>
          <span>SURFACES</span>
          <strong>{stats.surface_covered}/{stats.surfaces}</strong>
        </div>
        <div>
          <span>MODE</span>
          <strong>{displayMode.toUpperCase()}</strong>
        </div>
      </div>

      <div className="ledger-stats">
        <div><span>COVERAGE</span><strong>{stats.coverage_mapped}/{stats.coverage_total}</strong></div>
        <div><span>DOMAINS</span><strong>{stats.domain_queues_closed}/{stats.domain_queues}</strong></div>
        <div><span>DEBT</span><strong>{stats.coverage_debt}</strong></div>
        <div><span>H-DEBT</span><strong>{stats.hypothesis_debt}</strong></div>
        <div><span>ROOT CLAIMS</span><strong>{stats.root_claims}</strong></div>
        <div><span>PROBED</span><strong>{stats.probed}</strong></div>
        <div><span>REJECTED</span><strong>{stats.rejected}</strong></div>
        <div><span>MERGED</span><strong>{stats.merged_claims}</strong></div>
        <div><span>BLOCKED</span><strong>{stats.blocked_claims}</strong></div>
        <div><span>NEEDS VERIFY</span><strong>{stats.needs_verify}</strong></div>
        <div><span>PUBLISHABLE</span><strong>{stats.publishable_claims}</strong></div>
        <div><span>ATOMS</span><strong>{runbook?.attack_atoms?.length ?? 0}</strong></div>
        <div><span>CHAINS</span><strong>{runbook?.chain_candidates?.length ?? 0}</strong></div>
        <div><span>SIGNALS</span><strong>{stats.evidence_signals}</strong></div>
      </div>

      <div className="scan-note">
        SCAN is now a surface-driven ASG/ASM ledger. Inventory surfaces, derive domain queues, close debt, then publish adjudicated findings.
      </div>

      <div className="ascii-pipeline">
        {stages.map((stage, idx) => (
          <span
            key={stage.id}
            className={`${stage.status === "active" ? "active" : ""} ${stage.status === "done" || idx < currentStageIdx ? "done" : ""}`}
          >
            [{stage.code}:{stage.name.toUpperCase()}]
          </span>
        ))}
      </div>

      <div className="stage-pipeline runbook-pipeline">
        {stages.map((stage) => (
          <div
            key={stage.id}
            className={`stage-node ${stage.status === "active" ? "active" : ""} ${stage.status === "done" ? "done" : ""}`}
          >
            <div className="stage-number">{stage.code}</div>
            <div className="stage-name">{stage.name}</div>
            <p className="stage-summary">{stage.summary}</p>
            <div className="stage-counters">
              <span>{stage.evidence_count} evid</span>
              <span>{stage.candidate_count} cand</span>
              <span>{stage.findings_count} conf</span>
            </div>
            {stage.status === "active" && progress && (
              <div className="stage-progress-bar">
                <div
                  className="stage-progress-fill"
                  style={{ width: `${progress.progress * 100}%` }}
                />
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="scan-asm-grid">
        <AsmGraph runbook={runbook} auditMode={displayMode} />

        <section className="coverage-grid-card">
          <div className="coverage-grid-head">
            <div>
              <span className="eyebrow">COVERAGE GRID</span>
              <h3>Taxonomy health</h3>
            </div>
            <strong>{stats.coverage_mapped}/{stats.coverage_total}</strong>
          </div>
          <div className="coverage-heatmap">
            {coverage.map((item) => (
              <article key={item.id} className={`coverage-heat-cell ${item.status}`}>
                <span>{item.category.toUpperCase()}</span>
                <strong>{item.mapped_count}{item.total_hint ? `/${item.total_hint}` : ""}</strong>
                <p>{item.label}</p>
              </article>
            ))}
          </div>
        </section>
      </div>

      <section className="runbook-chain-strip">
        <div className="coverage-grid-head">
          <div>
            <span className="eyebrow">CHAIN PLANNER</span>
            <h3>Cross-lane exploit paths</h3>
          </div>
          <strong>{latestChains.length}</strong>
        </div>
        {latestChains.length === 0 ? (
          <p className="runbook-empty">Awaiting bridgeable attack atoms from multiple lanes.</p>
        ) : (
          <div className="runbook-chain-list">
            {latestChains.map((chain) => (
              <article key={chain.id} className={`runbook-row chain-${chain.status}`}>
                <div>
                  <span>{chain.id}</span>
                  <strong>{chain.status} · {chain.score}</strong>
                </div>
                <p>{chain.title}</p>
                <small>{chain.bridge_keys.join(", ")}{chain.verify_plan ? ` · ${chain.verify_plan}` : ""}</small>
              </article>
            ))}
          </div>
        )}
      </section>

      <details className="runbook-ledger-drawer">
        <summary>Raw ledger / debug feed</summary>

        <div className="runbook-grid">
          <section className="runbook-feed">
            <h3>CLAIM MACHINE</h3>
            {latestClaims.length === 0 ? (
              <p className="runbook-empty">Awaiting claim seeds from S1/S2.</p>
            ) : (
              latestClaims.map((claim) => (
                <article key={claim.id} className={`runbook-row claim-${claim.status}`}>
                  <div>
                    <span>{claim.id}</span>
                    <strong>{claim.status.replace("_", " ")}</strong>
                  </div>
                  <p>{claim.title}</p>
                  <small>{claim.evidence_level.replace("_", " ")} · {claim.category}{claim.merged_into ? ` · merged into ${claim.merged_into}` : ""}</small>
                </article>
              ))
            )}
          </section>

          <section className="runbook-feed">
            <h3>ATTACK SURFACE</h3>
            {latestSurfaces.length === 0 ? (
              <p className="runbook-empty">Awaiting endpoint, sink, guard, or parameter surfaces.</p>
            ) : (
              latestSurfaces.map((surface) => (
                <article key={surface.id} className="runbook-row">
                  <div>
                    <span>{surface.kind}</span>
                    <strong>{surface.category}</strong>
                  </div>
                  <p>{surface.label}</p>
                  {surface.target && <small>{surface.target}</small>}
                </article>
              ))
            )}
          </section>

          <section className="runbook-feed">
            <h3>ATTACK ATOMS</h3>
            {latestAtoms.length === 0 ? (
              <p className="runbook-empty">Awaiting reusable exploit atoms.</p>
            ) : (
              latestAtoms.map((atom) => (
                <article key={atom.id} className="runbook-row">
                  <div>
                    <span>{atom.kind}</span>
                    <strong>{atom.lane_id || atom.category}</strong>
                  </div>
                  <p>{atom.label}</p>
                  <small>{atom.bridge_keys.join(", ")}{atom.claim_id ? ` · ${atom.claim_id}` : ""}</small>
                </article>
              ))
            )}
          </section>

          <section className="runbook-feed">
            <h3>CANDIDATE LEDGER</h3>
            {latestCandidates.length === 0 ? (
              <p className="runbook-empty">Awaiting broad S1/S2 candidate expansion.</p>
            ) : (
              latestCandidates.map((candidate) => (
                <article key={candidate.id} className={`runbook-row candidate-${candidate.status}`}>
                  <div>
                    <span>{candidate.id}</span>
                    <strong>{candidate.status.replace("_", " ")}</strong>
                  </div>
                  <p>{candidate.title}</p>
                  {candidate.target && <small>{candidate.target}</small>}
                </article>
              ))
            )}
          </section>

          <section className="runbook-feed">
            <h3>EVIDENCE</h3>
            {latestEvidence.length === 0 ? (
              <p className="runbook-empty">Awaiting command, trace, or report evidence.</p>
            ) : (
              latestEvidence.map((item) => (
                <article key={item.id} className="runbook-row">
                  <div>
                    <span>{item.stage.toUpperCase()}</span>
                    <strong>{item.kind}</strong>
                  </div>
                  <p>{item.title}</p>
                </article>
              ))
            )}
          </section>

          <section className="runbook-feed">
            <h3>CONFIRMED</h3>
            {latestFindings.length === 0 ? (
              <p className="runbook-empty">No evidence-gated finding confirmed yet.</p>
            ) : (
              latestFindings.map((finding) => (
                <article key={finding.id} className={`runbook-row severity-${finding.severity}`}>
                  <div>
                    <span>{finding.candidate_id || finding.stage.toUpperCase()}</span>
                    <strong>{finding.severity} · {finding.confidence}</strong>
                  </div>
                  <p>{finding.title}</p>
                  <small>{finding.evidence_state}{finding.code_path ? ` · ${finding.code_path}` : ""}</small>
                </article>
              ))
            )}
          </section>
        </div>
      </details>
    </div>
  );
}
