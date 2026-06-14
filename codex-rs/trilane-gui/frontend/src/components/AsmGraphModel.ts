import { MarkerType, Position, type Edge as FlowEdge, type Node } from "@xyflow/react";
import { graphlib, layout as dagreLayout } from "dagre";

export interface RunbookCoverage {
  id: string;
  category: string;
  label: string;
  mapped_count: number;
  total_hint: number | null;
  status: "pending" | "mapped" | "partial";
}

export interface RunbookSurface {
  id: string;
  stage: string;
  kind: string;
  category: string;
  label: string;
  target: string;
  signal_count: number;
}

export interface RunbookCandidate {
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
}

export interface RunbookClaim {
  id: string;
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
}

export interface RunbookFinding {
  id: string;
  stage: string;
  candidate_id: string | null;
  severity: string;
  title: string;
  code_path: string;
  confidence: string;
  evidence_state: string;
  detail: string;
}

export interface RunbookAttackAtom {
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

export interface RunbookChainCandidate {
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

export interface RunbookStats {
  confirmed: number;
  candidates: number;
  root_claims: number;
  probed: number;
  rejected: number;
  merged_claims: number;
  blocked_claims: number;
  publishable_claims: number;
  evidence_signals: number;
}

export interface RunbookStage {
  id: string;
  code: string;
  name: string;
  status: "pending" | "active" | "done" | "blocked";
}

export interface RunbookState {
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
  findings: RunbookFinding[];
  attack_atoms?: RunbookAttackAtom[];
  chain_candidates?: RunbookChainCandidate[];
  stats: RunbookStats;
}

export interface AsmGraphProps {
  runbook: RunbookState | null;
  auditMode: "safe" | "lab";
}

export type AsmNodeKind = "target" | "domain" | "surface" | "claim" | "chain" | "finding" | "overflow";
export type AsmTone = "target" | "domain" | "surface" | "active" | "verified" | "critical" | "blocked" | "merged" | "muted";

export interface AsmNodeData extends Record<string, unknown> {
  kind: AsmNodeKind;
  tone: AsmTone;
  title: string;
  subtitle: string;
  metric: string;
  detail: string;
  category: string;
  status: string;
  severity: string | null;
  stage: string;
}

export interface DomainSummary {
  category: string;
  label: string;
  surfaces: RunbookSurface[];
  candidates: number;
  claims: number;
  findings: number;
  signals: number;
  status: string;
  stage: string;
}

export type AsmFlowNode = Node<AsmNodeData, "asmNode">;

const GRAPH_NODE_WIDTH = 230;
const GRAPH_NODE_HEIGHT = 96;
const MAX_DOMAINS = 9;
const MAX_SURFACES_PER_DOMAIN = 3;
const MAX_CLAIMS = 72;
const MAX_CHAINS = 24;
const MAX_FINDINGS = 80;

export function buildGraph(runbook: RunbookState | null, auditMode: "safe" | "lab") {
  const visibleStage = currentStageIndex(runbook);
  const nodes: AsmFlowNode[] = [];
  const edges: FlowEdge[] = [];
  let selectedFallbackId = "";
  const objective = compactObjective(runbook?.objective || "No active objective. Describe target in Agent.");
  const domainSummaries = runbook ? buildDomainSummaries(runbook) : [];
  const visibleDomains = domainSummaries.slice(0, MAX_DOMAINS);
  const domainNodeIds = new Map<string, string>();
  const visibleSurfaceNodeIds = new Set<string>();

  if (visibleStage >= 1 && runbook) {
    nodes.push(makeNode("target", {
      kind: "target",
      tone: runbook?.status === "error" ? "blocked" : "target",
      title: "TRILANE TARGET",
      subtitle: objective,
      metric: runbook?.turn_id ? `turn ${runbook.turn_id.slice(0, 8)}` : "standby",
      detail: runbook?.objective || "The graph wakes up once the agent receives an objective.",
      category: "target",
      status: (runbook?.status ?? "idle").toUpperCase(),
      severity: null,
      stage: runbook?.current_stage || "S0",
    }));
    selectedFallbackId = "target";

    visibleDomains.forEach((domain) => {
      const domainId = `domain-${safeId(domain.category)}`;
      domainNodeIds.set(domain.category, domainId);
      nodes.push(makeNode(domainId, {
        kind: "domain",
        tone: toneForDomain(domain),
        title: domain.label,
        subtitle: `${domain.surfaces.length} surfaces / ${domain.claims} claims`,
        metric: `${domain.signals} signal${domain.signals === 1 ? "" : "s"}`,
        detail: `${domain.label} domain: ${domain.surfaces.length} surfaces, ${domain.candidates} candidates, ${domain.claims} claims, ${domain.findings} findings.`,
        category: domain.category,
        status: domain.status,
        severity: null,
        stage: domain.stage,
      }));
      edges.push(makeEdge("target", domainId, "domain", true));

      const visibleSurfaces = domain.surfaces.slice(-MAX_SURFACES_PER_DOMAIN);
      visibleSurfaces.forEach((surface) => {
        const nodeId = `surface-${safeId(surface.id)}`;
        visibleSurfaceNodeIds.add(nodeId);
        nodes.push(makeNode(nodeId, {
          kind: "surface",
          tone: "surface",
          title: surface.label || surface.target || surface.kind,
          subtitle: surface.target || surface.category,
          metric: `${surface.signal_count} signal${surface.signal_count === 1 ? "" : "s"}`,
          detail: `${surface.kind} surface from ${surface.stage}. ${surface.target}`,
          category: surface.category,
          status: surface.kind,
          severity: null,
          stage: surface.stage.toUpperCase(),
        }));
        edges.push(makeEdge(domainId, nodeId, "surface", true));
      });
      addOverflowNode(nodes, edges, "surface", domain.surfaces.length, visibleSurfaces.length, domainId);
    });
    addOverflowNode(nodes, edges, "domain", domainSummaries.length, visibleDomains.length, "target");
  }

  if (visibleStage >= 2 && runbook?.surfaces.length) {
    const claims = normalizedClaims(runbook);
    const visibleClaims = claims.slice(-MAX_CLAIMS);
    visibleClaims.forEach((claim) => {
      const nodeId = `claim-${safeId(claim.id)}`;
      const surfaceId = findSurfaceParentId(
        claim.category,
        [claim.title, claim.target, claim.detail],
        runbook,
        visibleSurfaceNodeIds,
      );
      const domainId = domainNodeIds.get(claim.category) ?? "target";
      nodes.push(makeNode(nodeId, {
        kind: "claim",
        tone: toneForClaim(claim.status, claim.severity),
        title: claim.title || claim.id,
        subtitle: claim.target || claim.category,
        metric: claimMetric(claim),
        detail: claim.detail,
        category: claim.category,
        status: claim.status,
        severity: claim.severity,
        stage: claim.stage.toUpperCase(),
      }));
      edges.push(makeEdge(surfaceId ?? domainId, nodeId, claim.status, claim.status !== "discarded"));
      if (claim.mergedInto) {
        edges.push(makeEdge(nodeId, `claim-${safeId(claim.mergedInto)}`, "merged", true));
      }
    });
    addOverflowNode(nodes, edges, "claim", claims.length, visibleClaims.length, "target");
  }

  if (visibleStage >= 3 && runbook) {
    const visibleChains = (runbook.chain_candidates ?? []).slice(0, MAX_CHAINS);
    visibleChains.forEach((chain) => {
      const nodeId = `chain-${safeId(chain.id)}`;
      const parentId = chainParentId(chain, runbook, nodes, domainNodeIds, visibleSurfaceNodeIds);
      nodes.push(makeNode(nodeId, {
        kind: "chain",
        tone: toneForChain(chain.status),
        title: chain.title || chain.id,
        subtitle: chain.bridge_keys.slice(0, 4).join(" / ") || chain.impact || "cross-lane path",
        metric: `${chain.status || "candidate"} / ${chain.score}`,
        detail: chain.verify_plan || chain.impact || "Awaiting isolated S4 verification plan.",
        category: categoryForChain(chain, runbook),
        status: chain.status || "candidate",
        severity: null,
        stage: chain.stage.toUpperCase(),
      }));
      edges.push(makeEdge(parentId, nodeId, "chain", chain.status !== "rejected"));
    });
    addOverflowNode(nodes, edges, "chain", runbook.chain_candidates?.length ?? 0, visibleChains.length, "target");
  }

  if (visibleStage >= 3 && runbook?.surfaces.length && runbook?.findings.length) {
    const visibleFindings = runbook.findings.slice(-MAX_FINDINGS);
    visibleFindings.forEach((finding) => {
      const nodeId = `finding-${safeId(finding.id)}`;
      const category = categoryForFinding(finding, runbook);
      const sourceId = finding.candidate_id
        ? `claim-${safeId(finding.candidate_id)}`
        : findSurfaceParentId(category, [finding.title, finding.code_path, finding.detail], runbook, visibleSurfaceNodeIds)
          ?? domainNodeIds.get(category)
          ?? "target";
      const parentId = nodes.some((node) => node.id === sourceId)
        ? sourceId
        : findSurfaceParentId(category, [finding.title, finding.code_path, finding.detail], runbook, visibleSurfaceNodeIds)
          ?? domainNodeIds.get(category)
          ?? "target";
      nodes.push(makeNode(nodeId, {
        kind: "finding",
        tone: toneForSeverity(finding.severity),
        title: finding.title,
        subtitle: finding.code_path || finding.evidence_state || finding.stage,
        metric: `${finding.severity} / ${finding.confidence}`,
        detail: finding.detail || finding.evidence_state,
        category,
        status: finding.evidence_state || "confirmed",
        severity: finding.severity,
        stage: finding.stage.toUpperCase(),
      }));
      edges.push(makeEdge(parentId, nodeId, "finding", true));
    });
    addOverflowNode(nodes, edges, "finding", runbook.findings.length, visibleFindings.length, "target");
  }

  const laidOutNodes = layoutGraph(nodes, edges);
  selectedFallbackId = selectedFallbackId || laidOutNodes[0]?.id || "";
  return {
    nodes: laidOutNodes,
    edges,
    selectedFallbackId,
    summary: {
      phase: phaseLabel(runbook, visibleStage),
      complexity: `${laidOutNodes.length} nodes / ${edges.length} edges`,
      mode: (runbook?.audit_mode ?? auditMode).toUpperCase(),
      findings: runbook?.stats.confirmed ?? runbook?.findings.length ?? 0,
    },
  };
}

function layoutGraph(nodes: AsmFlowNode[], edges: FlowEdge[]) {
  const graph = new graphlib.Graph();
  graph.setDefaultEdgeLabel(() => ({}));
  graph.setGraph({
    rankdir: "LR",
    ranksep: 92,
    nodesep: 34,
    marginx: 28,
    marginy: 28,
  });

  nodes.forEach((node) => {
    const height = node.data.kind === "target" ? 118 : GRAPH_NODE_HEIGHT;
    const width = node.data.kind === "finding" || node.data.kind === "chain" ? 260 : GRAPH_NODE_WIDTH;
    graph.setNode(node.id, { width, height });
  });
  edges.forEach((edge) => graph.setEdge(edge.source, edge.target));
  dagreLayout(graph);

  return nodes.map((node) => {
    const graphNode = graph.node(node.id);
    const height = node.data.kind === "target" ? 118 : GRAPH_NODE_HEIGHT;
    const width = node.data.kind === "finding" || node.data.kind === "chain" ? 260 : GRAPH_NODE_WIDTH;
    return {
      ...node,
      position: {
        x: graphNode.x - width / 2,
        y: graphNode.y - height / 2,
      },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    };
  });
}

function makeNode(id: string, data: AsmNodeData): AsmFlowNode {
  return {
    id,
    type: "asmNode",
    data,
    position: { x: 0, y: 0 },
  };
}

function makeEdge(source: string, target: string, label: string, strong: boolean): FlowEdge {
  const rejected = label.includes("rejected") || label.includes("discarded");
  const merged = label.includes("merged") || label.includes("duplicate");
  return {
    id: `${source}->${target}-${safeId(label)}`,
    source,
    target,
    label: label.replace("_", " "),
    type: "smoothstep",
    animated: strong && !rejected && !merged,
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: rejected ? "#cc241d" : merged ? "#b16286" : strong ? "#d79921" : "#665c54",
    },
    className: `asm-edge ${strong ? "strong" : "weak"} ${rejected ? "rejected" : ""} ${merged ? "merged" : ""}`,
  };
}

function addOverflowNode(
  nodes: AsmFlowNode[],
  edges: FlowEdge[],
  kind: "domain" | "surface" | "claim" | "chain" | "finding",
  total: number,
  visible: number,
  parentId: string,
) {
  const hidden = total - visible;
  if (hidden <= 0) return;
  const nodeId = `overflow-${kind}-${safeId(parentId)}`;
  nodes.push(makeNode(nodeId, {
    kind: "overflow",
    tone: "muted",
    title: `+${hidden} ${kind}s`,
    subtitle: "Hidden to keep the map readable",
    metric: `${total} total`,
    detail: `The full ledger still keeps every ${kind}; this graph condenses the tail into an overflow node.`,
    category: kind,
    status: "overflow",
    severity: null,
    stage: "ASM",
  }));
  edges.push(makeEdge(parentId, nodeId, "overflow", false));
}

function currentStageIndex(runbook: RunbookState | null) {
  if (!runbook || runbook.status === "idle") return 0;
  if (runbook.status === "completed") return 5;
  const activeIdx = runbook.stages.findIndex((stage) => stage.status === "active");
  if (activeIdx >= 0) return activeIdx;
  const currentIdx = runbook.stages.findIndex((stage) => stage.id === runbook.current_stage);
  if (currentIdx >= 0) return currentIdx;
  const doneIndexes = runbook.stages
    .map((stage, idx) => (stage.status === "done" ? idx : -1))
    .filter((idx) => idx >= 0);
  return doneIndexes.length ? Math.max(...doneIndexes) : 0;
}

function normalizedClaims(runbook: RunbookState | null) {
  if (runbook?.claims.length) {
    return runbook.claims.map((claim) => ({
      id: claim.id,
      stage: claim.stage,
      category: claim.category,
      title: claim.title,
      target: claim.target,
      status: claim.status,
      severity: claim.severity,
      evidence: claim.evidence_level,
      signalCount: claim.signal_count,
      probeCount: claim.probe_count,
      verificationCount: claim.verification_count,
      mergedInto: claim.merged_into,
      detail: [
        claim.root_cause,
        claim.precondition && `Precondition: ${claim.precondition}`,
        claim.impact && `Impact: ${claim.impact}`,
        claim.payload && `Payload: ${claim.payload}`,
        claim.positive_evidence,
        claim.negative_evidence && `Control: ${claim.negative_evidence}`,
      ].filter(Boolean).join(" · "),
    }));
  }
  return (runbook?.candidates ?? []).map((candidate) => ({
    id: candidate.id,
    stage: candidate.stage,
    category: candidate.category,
    title: candidate.title,
    target: candidate.target,
    status: candidate.status,
    severity: candidate.severity,
    evidence: candidate.source_confirmed ? "source_backed" : "signal",
    signalCount: candidate.evidence_count,
    probeCount: candidate.verification_count,
    verificationCount: candidate.verification_count,
    mergedInto: null,
    detail: `${candidate.status} candidate. ${candidate.target}`,
  }));
}

function buildDomainSummaries(runbook: RunbookState): DomainSummary[] {
  const domains = new Map<string, DomainSummary>();

  const ensureDomain = (category: string) => {
    const normalized = category || "uncategorized";
    let domain = domains.get(normalized);
    if (!domain) {
      domain = {
        category: normalized,
        label: domainLabel(normalized),
        surfaces: [],
        candidates: 0,
        claims: 0,
        findings: 0,
        signals: 0,
        status: "mapped",
        stage: "ASM",
      };
      domains.set(normalized, domain);
    }
    return domain;
  };

  runbook.coverage
    .filter((coverage) => coverage.status !== "pending")
    .forEach((coverage) => {
      const domain = ensureDomain(coverage.category);
      domain.signals += coverage.mapped_count;
      domain.status = coverage.status;
    });

  runbook.surfaces.forEach((surface) => {
    const domain = ensureDomain(surface.category);
    domain.surfaces.push(surface);
    domain.signals += surface.signal_count;
    domain.stage = surface.stage.toUpperCase();
  });

  runbook.candidates.forEach((candidate) => {
    const domain = ensureDomain(candidate.category);
    domain.candidates += 1;
    domain.signals += candidate.evidence_count;
    if (candidate.status === "confirmed") domain.status = "confirmed";
  });

  runbook.claims.forEach((claim) => {
    const domain = ensureDomain(claim.category);
    domain.claims += 1;
    domain.signals += claim.signal_count;
    if (["verified", "weaponized", "publishable"].includes(claim.status)) {
      domain.status = "verified";
    } else if (["armed", "running", "corroborated"].includes(claim.status) && domain.status === "mapped") {
      domain.status = "running";
    }
  });

  runbook.findings.forEach((finding) => {
    const category = categoryForFinding(finding, runbook);
    const domain = ensureDomain(category);
    domain.findings += 1;
    domain.status = "finding";
  });

  return Array.from(domains.values()).sort((left, right) => {
    const rightWeight = domainWeight(right);
    const leftWeight = domainWeight(left);
    if (rightWeight !== leftWeight) return rightWeight - leftWeight;
    return domainOrder(left.category) - domainOrder(right.category);
  });
}

function domainWeight(domain: DomainSummary) {
  return domain.findings * 1000 + domain.claims * 100 + domain.candidates * 20 + domain.surfaces.length * 4 + domain.signals;
}

function domainOrder(category: string) {
  const order = [
    "auth",
    "authz",
    "session",
    "injection",
    "xss",
    "ssrf_redirect",
    "file_upload_xxe",
    "traversal_lfi",
    "secrets_config",
    "observability_leak",
    "cors_headers_tls",
    "rate_limit",
    "state_invariant_abuse",
    "anti_automation_bypass",
    "crypto",
  ];
  const index = order.indexOf(category);
  return index === -1 ? order.length : index;
}

function domainLabel(category: string) {
  const labels: Record<string, string> = {
    auth: "Identity / AuthN",
    authz: "Authorization",
    session: "Session / Token",
    injection: "Injection",
    xss: "Browser Trust",
    ssrf_redirect: "SSRF / Redirect",
    file_upload_xxe: "Upload / Parser",
    traversal_lfi: "Traversal / LFI",
    secrets_config: "Secrets / Config",
    observability_leak: "Observability Leak",
    cors_headers_tls: "CORS / Headers",
    rate_limit: "Rate Limit",
    state_invariant_abuse: "State Invariant",
    anti_automation_bypass: "Anti-Automation",
    crypto: "Crypto",
  };
  return labels[category] ?? category.replaceAll("_", " ").toUpperCase();
}

function toneForDomain(domain: DomainSummary): AsmTone {
  if (domain.findings > 0 || domain.status === "finding" || domain.status === "verified") return "verified";
  if (domain.claims > 0 || domain.candidates > 0 || domain.status === "running") return "active";
  return "domain";
}

function findSurfaceParentId(
  category: string,
  hints: string[],
  runbook: RunbookState | null,
  visibleSurfaceNodeIds: Set<string>,
) {
  if (!runbook?.surfaces.length) return null;
  const normalizedHints = hints.join("\n").toLowerCase();
  const visibleSurfaces = runbook.surfaces.filter((surface) => visibleSurfaceNodeIds.has(`surface-${safeId(surface.id)}`));
  const direct = visibleSurfaces.find((surface) => {
    const target = surface.target.toLowerCase();
    const label = surface.label.toLowerCase();
    return surface.category === category
      && ((target.length > 3 && normalizedHints.includes(target))
        || (label.length > 8 && normalizedHints.includes(label)));
  });
  const surface = direct ?? visibleSurfaces.find((item) => item.category === category);
  return surface ? `surface-${safeId(surface.id)}` : null;
}

function chainParentId(
  chain: RunbookChainCandidate,
  runbook: RunbookState,
  nodes: AsmFlowNode[],
  domainNodeIds: Map<string, string>,
  visibleSurfaceNodeIds: Set<string>,
) {
  const nodeIds = new Set(nodes.map((node) => node.id));
  const atoms = atomsForChain(chain, runbook);
  const claimId = atoms.map((atom) => atom.claim_id).find(Boolean);
  if (claimId) {
    const nodeId = `claim-${safeId(claimId)}`;
    if (nodeIds.has(nodeId)) return nodeId;
  }

  const category = categoryForChain(chain, runbook);
  const surfaceParent = findSurfaceParentId(
    category,
    [chain.title, chain.impact, chain.verify_plan, ...atoms.flatMap((atom) => [atom.label, atom.target])],
    runbook,
    visibleSurfaceNodeIds,
  );
  if (surfaceParent) return surfaceParent;
  return domainNodeIds.get(category) ?? "target";
}

function atomsForChain(chain: RunbookChainCandidate, runbook: RunbookState) {
  const atoms = runbook.attack_atoms ?? [];
  if (!chain.atom_ids.length) return [];
  const wanted = new Set(chain.atom_ids);
  return atoms.filter((atom) => wanted.has(atom.id));
}

function categoryForChain(chain: RunbookChainCandidate, runbook: RunbookState) {
  const atoms = atomsForChain(chain, runbook);
  const category = atoms.find((atom) => atom.category)?.category;
  if (category) return category;
  const text = [chain.title, chain.impact, chain.verify_plan, chain.bridge_keys.join(" ")].join(" ").toLowerCase();
  if (text.includes("jwt") || text.includes("login") || text.includes("password")) return "auth";
  if (text.includes("idor") || text.includes("basket") || text.includes("access")) return "authz";
  if (text.includes("sql") || text.includes("injection") || text.includes("ssti")) return "injection";
  if (text.includes("xss") || text.includes("browser")) return "xss";
  if (text.includes("file") || text.includes("upload") || text.includes("xxe")) return "file_upload_xxe";
  if (text.includes("redirect") || text.includes("ssrf")) return "ssrf_redirect";
  if (text.includes("secret") || text.includes("config") || text.includes("key")) return "secrets_config";
  return "state_invariant_abuse";
}

function claimMetric(claim: ReturnType<typeof normalizedClaims>[number]) {
  const parts = [
    claim.evidence.replace("_", " "),
    claim.probeCount > 0 ? `${claim.probeCount} probes` : "",
    claim.verificationCount > 0 ? `${claim.verificationCount} verify` : "",
  ].filter(Boolean);
  return parts.join(" / ");
}

function categoryForFinding(finding: RunbookFinding, runbook: RunbookState | null) {
  const candidate = runbook?.candidates.find((item) => item.id === finding.candidate_id);
  if (candidate?.category) return candidate.category;
  const claim = runbook?.claims.find((item) => item.id === finding.candidate_id);
  if (claim?.category) return claim.category;
  const title = finding.title.toLowerCase();
  if (title.includes("sql") || title.includes("injection") || title.includes("ssti")) return "injection";
  if (title.includes("xss")) return "xss";
  if (title.includes("jwt") || title.includes("password") || title.includes("auth")) return "auth";
  if (title.includes("idor") || title.includes("access")) return "authz";
  if (title.includes("ssrf") || title.includes("redirect")) return "ssrf_redirect";
  if (title.includes("file") || title.includes("xxe") || title.includes("upload")) return "file_upload_xxe";
  if (title.includes("metric") || title.includes("log") || title.includes("debug") || title.includes("swagger")) return "observability_leak";
  if (title.includes("captcha") || title.includes("reset") || title.includes("recovery") || title.includes("rate")) return "anti_automation_bypass";
  if (title.includes("crypto") || title.includes("md5")) return "crypto";
  return "state_invariant_abuse";
}

function toneForChain(status: string): AsmTone {
  const normalized = status.toLowerCase();
  if (normalized === "verified" || normalized === "publishable") return "critical";
  if (normalized === "rejected" || normalized === "blocked") return "blocked";
  if (normalized === "running" || normalized === "candidate" || normalized === "needs_verify") return "active";
  return "surface";
}

function toneForClaim(status: string, severity: string | null): AsmTone {
  if (status === "discarded" || status === "blocked") return "blocked";
  if (status === "merged") return "merged";
  if (status === "verified" || status === "weaponized" || status === "publishable") {
    return toneForSeverity(severity);
  }
  if (status === "running" || status === "armed" || status === "corroborated") return "active";
  return "surface";
}

function toneForSeverity(severity: string | null): AsmTone {
  const normalized = (severity ?? "").toLowerCase();
  if (normalized === "critical" || normalized === "high") return "critical";
  if (normalized === "medium") return "active";
  return "verified";
}

export function toneColor(tone: unknown) {
  switch (tone) {
    case "target":
      return "#d79921";
    case "domain":
      return "#458588";
    case "surface":
      return "#689d6a";
    case "active":
      return "#fabd2f";
    case "verified":
      return "#98971a";
    case "critical":
      return "#cc241d";
    case "blocked":
      return "#fb4934";
    case "merged":
      return "#b16286";
    case "muted":
      return "#665c54";
    default:
      return "#928374";
  }
}

function phaseLabel(runbook: RunbookState | null, stageIndex: number) {
  if (!runbook) return "S0 standby";
  const stage = runbook.stages[stageIndex];
  return stage ? `${stage.code} ${stage.name}` : runbook.current_stage.toUpperCase();
}

function compactObjective(objective: string) {
  if (objective.length <= 88) return objective;
  return `${objective.slice(0, 85)}...`;
}

function safeId(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "node";
}
