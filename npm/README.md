# TriLane

TriLane is a desktop security agent for authorized gray-box vulnerability hunting.

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
