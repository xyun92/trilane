#!/usr/bin/env node

const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const packageJson = require("../package.json");

main().catch((error) => {
  console.error(`TriLane: ${error.message}`);
  process.exit(1);
});

async function main() {
  const command = process.argv[2] || "app";

  if (command === "--help" || command === "-h" || command === "help") {
    printHelp();
    return;
  }

  if (command === "--version" || command === "-v" || command === "version") {
    console.log(packageJson.version);
    return;
  }

  if (command === "doctor") {
    runDoctor();
    return;
  }

  if (command !== "app") {
    console.error(`TriLane: unknown command ${JSON.stringify(command)}`);
    printHelp();
    process.exit(2);
  }

  const target = await resolveLaunchTarget({ allowDownload: true });
  runLaunchTarget(target, process.argv.slice(3));
}

function printHelp() {
  console.log(`TriLane ${packageJson.version}

Usage:
  trilane app        Launch the TriLane desktop app
  trilane doctor     Verify that this npm package can find a runnable binary
  trilane --version  Print the package version

Environment:
  TRILANE_BIN          Use an explicit local trilane-gui binary
  TRILANE_VERSION      Override the release version used for downloads
  TRILANE_RELEASE_BASE Override the GitHub release URL base
`);
}

function runDoctor() {
  console.log(`TriLane package: ${packageJson.version}`);
  console.log(`Platform: ${os.platform()}/${os.arch()}`);

  const target = resolveLocalLaunchTarget();
  if (!target) {
    console.error("Launcher: missing");
    console.error("Set TRILANE_BIN to a locally built trilane-gui binary, or use a package with a bundled launcher for this platform.");
    process.exit(1);
  }

  if (target.kind === "app") {
    console.log(`App bundle: ${target.path}`);
    console.log(`Executable: ${target.executable}`);
  } else {
    console.log(`Binary: ${target.path}`);
  }
}

async function resolveLaunchTarget({ allowDownload }) {
  const localTarget = resolveLocalLaunchTarget();
  if (localTarget) {
    return localTarget;
  }

  if (!allowDownload) {
    return null;
  }

  const version = process.env.TRILANE_VERSION || packageJson.version;
  const releaseBase = process.env.TRILANE_RELEASE_BASE
    || `https://github.com/xyun92/trilane/releases/download/v${version}`;
  const asset = platformAssetName();
  const cacheDir = path.join(os.homedir(), ".trilane", "bin", version);
  const cachedTarget = path.join(cacheDir, asset.targetName);

  if (!fs.existsSync(cachedTarget)) {
    fs.mkdirSync(cacheDir, { recursive: true });
    const archivePath = path.join(cacheDir, asset.archiveName);
    await download(`${releaseBase}/${asset.archiveName}`, archivePath);
    unpackArchive(archivePath, cacheDir, asset);
  }

  if (asset.kind === "app") {
    const executable = path.join(cacheDir, asset.executablePath);
    if (!executablePathOrNull(executable)) {
      throw new Error(`archive did not contain executable ${asset.executablePath}`);
    }
    return appLaunchTarget(cachedTarget, executable);
  }

  if (!executablePathOrNull(cachedTarget)) {
    throw new Error(`archive did not contain executable ${asset.executablePath}`);
  }
  return binaryLaunchTarget(cachedTarget);
}

function resolveLocalLaunchTarget() {
  const explicitBin = process.env.TRILANE_BIN;
  if (explicitBin) {
    const explicitPath = executablePathOrNull(explicitBin);
    return explicitPath ? binaryLaunchTarget(explicitPath) : null;
  }

  const bundledApp = bundledAppPath();
  const bundledAppExecutable = bundledAppExecutablePath(bundledApp);
  if (isDirectory(bundledApp) && executablePathOrNull(bundledAppExecutable)) {
    return appLaunchTarget(bundledApp, bundledAppExecutable);
  }

  const bundled = bundledBinaryPath();
  const bundledPath = executablePathOrNull(bundled);
  return bundledPath ? binaryLaunchTarget(bundledPath) : null;
}

function executablePathOrNull(candidate) {
  if (!candidate || !fs.existsSync(candidate)) {
    return null;
  }

  try {
    fs.accessSync(candidate, fs.constants.X_OK);
    return candidate;
  } catch {
    return null;
  }
}

function bundledBinaryPath() {
  const platform = os.platform();
  const arch = os.arch();
  const binaryName = platform === "win32" ? "trilane.exe" : "trilane";
  return path.join(__dirname, "..", "vendor", `${platform}-${arch}`, binaryName);
}

function bundledAppPath() {
  if (os.platform() !== "darwin") {
    return null;
  }
  return path.join(__dirname, "..", "vendor", `darwin-${os.arch()}`, "TriLane.app");
}

function bundledAppExecutablePath(appPath) {
  if (!appPath) {
    return null;
  }
  return path.join(appPath, "Contents", "MacOS", "trilane-gui");
}

function isDirectory(candidate) {
  try {
    return fs.statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

function appLaunchTarget(appPath, executable) {
  return { kind: "app", path: appPath, executable };
}

function binaryLaunchTarget(binaryPath) {
  return { kind: "binary", path: binaryPath };
}

function platformAssetName() {
  const platform = os.platform();
  const arch = os.arch();

  if (platform === "darwin" && arch === "arm64") {
    return appAsset("trilane-aarch64-apple-darwin.tar.gz", "TriLane.app", "TriLane.app/Contents/MacOS/trilane-gui");
  }
  if (platform === "darwin" && arch === "x64") {
    return appAsset("trilane-x86_64-apple-darwin.tar.gz", "TriLane.app", "TriLane.app/Contents/MacOS/trilane-gui");
  }
  if (platform === "linux" && arch === "x64") {
    return binaryAsset("trilane-x86_64-unknown-linux-musl.tar.gz", "trilane");
  }
  if (platform === "linux" && arch === "arm64") {
    return binaryAsset("trilane-aarch64-unknown-linux-musl.tar.gz", "trilane");
  }
  if (platform === "win32" && arch === "x64") {
    return binaryAsset("trilane-x86_64-pc-windows-msvc.zip", "trilane.exe");
  }

  throw new Error(`unsupported platform ${platform}/${arch}`);
}

function appAsset(archiveName, targetName, executablePath) {
  return { kind: "app", archiveName, targetName, executablePath };
}

function binaryAsset(archiveName, executablePath) {
  return { kind: "binary", archiveName, targetName: executablePath, executablePath };
}

async function download(url, destination) {
  console.error(`TriLane: downloading ${url}`);
  await downloadWithRedirects(url, destination, 0);
}

function downloadWithRedirects(url, destination, redirects) {
  if (redirects > 5) {
    return Promise.reject(new Error("too many download redirects"));
  }

  return new Promise((resolve, reject) => {
    const request = https.get(url, (response) => {
      const location = response.headers.location;
      if (response.statusCode && response.statusCode >= 300 && response.statusCode < 400 && location) {
        response.resume();
        resolve(downloadWithRedirects(new URL(location, url).toString(), destination, redirects + 1));
        return;
      }

      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`download failed with HTTP ${response.statusCode}`));
        return;
      }

      const file = fs.createWriteStream(destination);
      response.pipe(file);
      file.on("finish", () => file.close(resolve));
      file.on("error", reject);
    });
    request.on("error", reject);
  });
}

function unpackArchive(archivePath, outputDir, assetSpec) {
  if (assetSpec.archiveName.endsWith(".tar.gz")) {
    run("tar", ["-xzf", archivePath, "-C", outputDir]);
  } else if (assetSpec.archiveName.endsWith(".zip")) {
    if (process.platform === "win32") {
      run("powershell.exe", [
        "-NoProfile",
        "-Command",
        `Expand-Archive -Force ${JSON.stringify(archivePath)} ${JSON.stringify(outputDir)}`,
      ]);
    } else {
      run("unzip", ["-o", archivePath, "-d", outputDir]);
    }
  } else {
    throw new Error(`unsupported archive type ${assetSpec.archiveName}`);
  }

  const executablePath = path.join(outputDir, assetSpec.executablePath);
  if (!fs.existsSync(executablePath)) {
    throw new Error(`archive did not contain ${assetSpec.executablePath}`);
  }
  fs.chmodSync(executablePath, 0o755);
}

function run(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.status !== 0) {
    throw new Error(`${command} failed`);
  }
}

function runLaunchTarget(target, args) {
  if (target.kind === "app") {
    const openArgs = ["-n", target.path];
    if (args.length > 0) {
      openArgs.push("--args", ...args);
    }
    const result = spawnSync("open", openArgs, { stdio: "inherit" });
    if (result.error) {
      throw result.error;
    }
    process.exit(result.status ?? 1);
  }

  const result = spawnSync(target.path, args, { stdio: "inherit" });
  if (result.error) {
    throw result.error;
  }
  process.exit(result.status ?? 1);
}
