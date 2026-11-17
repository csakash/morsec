#!/usr/bin/env node
// morsec's npm launcher for `ms` and `mors` (packaging/npm, loop distribution).
//
// The real, Developer ID signed binaries are in the platform package morsec-darwin-arm64, an
// optional dependency that npm installs only on Apple silicon macOS. This file finds it and runs
// its `ms` with the same arguments and the same terminal. It runs nothing at install time (the
// package has no scripts), reads no environment variable to choose what to run, and needs no
// dependency.
"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const PLATFORM_PACKAGE = "morsec-darwin-arm64";
const OWN_VERSION = require("../package.json").version;

function fail(message) {
  process.stderr.write(`morsec: ${message}\n`);
  process.exit(1);
}

function rosetta() {
  // An x64 Node on an Apple silicon Mac runs under Rosetta: npm then skips the arm64 package.
  try {
    const out = require("child_process").execFileSync("/usr/sbin/sysctl", ["-in", "sysctl.proc_translated"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return out.trim() === "1";
  } catch {
    return false;
  }
}

function checkPlatform() {
  if (process.platform === "darwin" && process.arch === "arm64") return;
  if (process.platform === "darwin" && process.arch === "x64" && rosetta()) {
    fail(
      "this Node.js is an x64 build running under Rosetta, so npm skipped morsec's Apple silicon " +
        "binaries. Install an arm64 Node.js (https://nodejs.org), then: npm install -g morsec"
    );
  }
  fail(
    `morsec runs on Apple silicon macOS only (this is ${process.platform}/${process.arch}). ` +
      "See https://github.com/csakash/morsec#install"
  );
}

function findBinary() {
  let manifest;
  try {
    manifest = require.resolve(`${PLATFORM_PACKAGE}/package.json`, { paths: [path.join(__dirname, "..")] });
  } catch {
    fail(
      `the package ${PLATFORM_PACKAGE}, which holds morsec's binaries, is not installed. npm skips it ` +
        "when optional dependencies are turned off (--omit=optional, --no-optional). Reinstall with: " +
        "npm install -g morsec"
    );
  }
  const dir = path.dirname(manifest);
  let version;
  try {
    version = JSON.parse(fs.readFileSync(manifest, "utf8")).version;
  } catch (e) {
    fail(`can't read ${manifest}: ${e.message}`);
  }
  if (version !== OWN_VERSION) {
    fail(
      `morsec ${OWN_VERSION} found ${PLATFORM_PACKAGE} ${version} at ${dir}; the two must be the same ` +
        "version. Reinstall with: npm install -g morsec"
    );
  }
  const bin = path.join(dir, "bin", "ms");
  try {
    fs.accessSync(bin, fs.constants.X_OK);
  } catch {
    fail(`${bin} is missing or not executable. Reinstall with: npm install -g morsec`);
  }
  return bin;
}

function run(bin) {
  const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
  // The terminal sends Ctrl-C and Ctrl-\ to the whole foreground group, so ms gets those itself:
  // ignore them here. SIGTERM and SIGHUP may be sent to this process alone (a parent stopping
  // `ms mcp`, `kill <pid>`), so pass them on; a second copy of the same signal is harmless.
  const ignore = () => {};
  const forward = (s) => () => {
    try {
      child.kill(s);
    } catch {}
  };
  const handlers = { SIGINT: ignore, SIGQUIT: ignore, SIGTERM: forward("SIGTERM"), SIGHUP: forward("SIGHUP") };
  for (const [s, h] of Object.entries(handlers)) process.on(s, h);
  child.on("error", (e) => fail(`can't run ${bin}: ${e.message}`));
  child.on("exit", (code, signal) => {
    if (signal) {
      for (const [s, h] of Object.entries(handlers)) process.removeListener(s, h);
      process.kill(process.pid, signal);
      // Only reached if the signal did not end this process: exit the way a shell reports it.
      setTimeout(() => process.exit(128 + (require("os").constants.signals[signal] || 0)), 200);
      return;
    }
    process.exit(code === null ? 1 : code);
  });
}

checkPlatform();
run(findBinary());
