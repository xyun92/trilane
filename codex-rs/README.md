# TriLane Rust Workspace

This directory contains the Rust workspace used by the TriLane desktop app. The main application crate is [`trilane-gui`](./trilane-gui).

Build the frontend first:

```bash
cd trilane-gui/frontend
npm install
npm run build
```

Then build the desktop binary from this directory:

```bash
cargo build -p trilane-gui --release
./target/release/trilane-gui
```

The workspace contains supporting crates derived from the Apache-2.0 OpenAI Codex codebase. TriLane-specific orchestration, workflow, runbook, transcript, and GUI code lives under `trilane-gui`.
