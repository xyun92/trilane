import { useState } from "react";
import { invokeWithTimeout } from "../lib/invoke";

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  location: string;
  code_path: string;
  description: string;
  payload: string;
  cwe: string;
  confidence: string;
  evidence_state: string;
  duplicate_count: number;
  original_id: string;
  candidate_id: string | null;
}

interface Props {
  findings: Finding[];
}

const SEVERITY_META: Record<string, { label: string; color: string }> = {
  critical: { label: "CRIT", color: "#ff5a52" },
  high: { label: "HIGH", color: "#ffb454" },
  medium: { label: "MED", color: "#e7d36a" },
  low: { label: "LOW", color: "#79d673" },
  info: { label: "INFO", color: "#7cc8ff" },
};

export default function FindingsPanel({ findings }: Props) {
  const [selected, setSelected] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [exportState, setExportState] = useState<string>("");

  const filtered =
    filter === "all"
      ? findings
      : findings.filter((f) => f.severity === filter);

  const severityKeys = ["critical", "high", "medium", "low", "info"] as const;
  const counts = Object.fromEntries(
    severityKeys.map((sev) => [
      sev,
      findings.filter((f) => f.severity === sev).length,
    ]),
  ) as Record<(typeof severityKeys)[number], number>;

  async function exportReport() {
    setExportState("exporting");
    try {
      const path = await invokeWithTimeout<string>("export_final_report", undefined, 15000);
      setExportState(`saved ${path}`);
    } catch (error) {
      setExportState(`failed ${error}`);
    }
  }

  return (
    <div className="findings-panel">
      <div className="findings-topline">
        <div>
          <span className="eyebrow">TRIAGE/QUEUE</span>
          <h2>findings table</h2>
        </div>
        <div className="findings-total">
          <span>{filtered.length}</span>
          visible
        </div>
      </div>

      <div className="findings-actions">
        <button type="button" onClick={exportReport}>
          DOWNLOAD REPORT
        </button>
        {exportState && <span>{exportState}</span>}
      </div>

      {/* Summary Bar */}
      <div className="findings-summary">
        <button
          className={`severity-badge all ${filter === "all" ? "active" : ""}`}
          onClick={() => setFilter("all")}
        >
          <span className="severity-label">ALL</span>
          <strong>{findings.length}</strong>
        </button>
        {severityKeys.map((sev) => (
          <button
            key={sev}
            className={`severity-badge ${filter === sev ? "active" : ""}`}
            style={{ borderColor: SEVERITY_META[sev].color }}
            onClick={() => setFilter(filter === sev ? "all" : sev)}
          >
            <span
              className="severity-dot"
              style={{ background: SEVERITY_META[sev].color }}
            />
            <span className="severity-label">{SEVERITY_META[sev].label}</span>
            <strong>{counts[sev]}</strong>
          </button>
        ))}
      </div>

      {/* Findings List */}
      {filtered.length === 0 ? (
        <div className="queue-empty">
          <span>QUEUE EMPTY</span>
          <p>No findings match this filter.</p>
        </div>
      ) : (
        <div className="findings-list">
          <div className="findings-table-head">
            <span>SEV</span>
            <span>ID</span>
            <span>VULNERABILITY</span>
            <span>STATUS</span>
          </div>
          {filtered.map((f) => (
            <div
              key={f.id}
              className={`finding-card ${selected === f.id ? "expanded" : ""}`}
              onClick={() => setSelected(selected === f.id ? null : f.id)}
            >
              <div className="finding-header">
                <span
                  className="finding-severity"
                  style={{ color: SEVERITY_META[f.severity]?.color }}
                >
                  {SEVERITY_META[f.severity]?.label || f.severity.toUpperCase()}
                </span>
                <span className="finding-id">{f.id}</span>
                <span className="finding-title">
                  <strong>{f.title}</strong>
                  <em>{f.original_id}</em>
                </span>
                <span className={`finding-status ${f.status}`}>
                  {f.status}
                </span>
              </div>

              {selected === f.id && (
                <div className="finding-details">
                  <div className="finding-meta">
                    <div>
                      <strong>location</strong>
                      <code>{f.location || "-"}</code>
                    </div>
                    <div>
                      <strong>confidence</strong>
                      <code>{f.confidence} / {f.evidence_state}</code>
                    </div>
                    <div>
                      <strong>class</strong>
                      <code>{f.cwe} · dup {f.duplicate_count}</code>
                    </div>
                  </div>
                  {f.code_path && (
                    <div className="finding-location">
                      <strong>affected code</strong>
                      <code>{f.code_path}</code>
                    </div>
                  )}
                  <div className="finding-desc">
                    <strong>analysis</strong>
                    <p>{f.description}</p>
                  </div>
                  {f.payload && (
                    <details className="finding-poc">
                      <summary>payload / exploit</summary>
                      <pre><code>{f.payload}</code></pre>
                    </details>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
