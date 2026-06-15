interface ScanProgress {
  stage: string;
  stage_name: string;
  progress: number;
  message: string;
  findings_count: number;
}

interface Props {
  progress: ScanProgress;
}

const STAGES = ["stage0", "stage1", "stage2", "stage3", "stage4", "stage5"];

export default function StageProgress({ progress }: Props) {
  const idx = STAGES.indexOf(progress.stage);
  const overall = ((idx + progress.progress) / STAGES.length) * 100;

  return (
    <div className="stage-progress-global">
      <div className="stage-progress-bar-global">
        <div
          className="stage-progress-fill-global"
          style={{ width: `${overall}%` }}
        />
      </div>
      <div className="stage-progress-info">
        <span>{progress.stage_name}</span>
        <span>{progress.message}</span>
        <span>{progress.findings_count} findings</span>
      </div>
    </div>
  );
}
