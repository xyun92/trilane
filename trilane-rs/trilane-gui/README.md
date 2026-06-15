# TriLane GUI

TriLane GUI is the local desktop cockpit for lane-orchestrated vulnerability hunting.

## Develop

```bash
pnpm install
pnpm --filter trilane-gui-frontend install
cd path/to/trilane-gui
cargo tauri dev
```

## Build

```bash
cd path/to/trilane-gui
cargo tauri build
```

## Local State

- Config: `~/.trilane/config.toml`
- Secrets: `~/.trilane/secrets.toml`
- Run transcripts: `~/.trilane/transcripts`
- Downloaded reports: `~/Downloads/trilane-final-report-*.md`

## Modes

- **Safe**: full workflow with constrained local access.
- **Lab**: full workflow with full local access after GUI confirmation.
