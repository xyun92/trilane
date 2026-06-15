<p align="center">
  <img src="https://raw.githubusercontent.com/xyun92/trilane/v0.1.1/trilane-rs/trilane-gui/icons/128x128.png" alt="TriLane" width="96" height="96">
</p>

<h1 align="center">TriLane</h1>

<p align="center">
  <strong>Desktop security agent for authorized gray-box vulnerability hunting.</strong>
</p>

<p align="center">
  <img alt="npm version" src="https://img.shields.io/npm/v/trilane?style=for-the-badge&label=npm&color=d9a441">
  <img alt="Apache-2.0 license" src="https://img.shields.io/badge/license-Apache--2.0-2f6f73?style=for-the-badge">
  <img alt="macOS arm64" src="https://img.shields.io/badge/prebuilt-macOS%20arm64-111827?style=for-the-badge">
  <img alt="desktop GUI" src="https://img.shields.io/badge/interface-desktop%20GUI-98971a?style=for-the-badge">
</p>

TriLane turns one natural-language objective into a staged audit cockpit for authorized local labs, internal codebases, training apps, and bounty targets where you have permission to test.

```bash
npm install -g trilane
trilane doctor
trilane app
```

You can also run it without a global install:

```bash
npx trilane@latest app
```

The first npm release includes a macOS Apple Silicon binary. On other platforms, build `trilane-gui` from source and point the launcher at it:

```bash
TRILANE_BIN=/path/to/trilane-gui npx trilane app
```

Use TriLane only on systems you own, operate, or are explicitly authorized to test.
