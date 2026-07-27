#!/bin/bash -eu
# Build the Jazzer.js fuzz targets for ClusterFuzzLite / OSS-Fuzz.
# Each target is an ESM module exporting a synchronous `fuzz(data)`; the
# invariants are the fail-safe contracts at plumbline's trust boundary — the
# trajectory parser and scorer never throw anything but the controlled
# TrajectoryError on hostile JSONL, the agentlog capability inference never
# throws on an attacker-named tool, and schema normalization stays controlled
# while entropyOf never returns NaN.
cd "$SRC/plumbline"

# plumbline ships ZERO runtime dependencies, so its committed lockfile installs
# nothing — `npm ci` here would be a no-op. Jazzer.js is a fuzz-build-time-only
# tool: install it transiently (pinned, --no-save) so it never becomes a
# committed dependency, never enters the lockfile, and never enters the
# published package. The fuzz targets in ./fuzz import only from ../src, so no
# project install is needed beyond Jazzer itself.
npm install --no-save --no-audit --no-fund @jazzer.js/core@4.0.0

# --sync: every target's fuzz() is synchronous (assessTrajectory, buildTrajectory
# and normalizeEvent are all sync). An async target would omit this flag.
for target in assess_trajectory infer_capability normalize_event; do
  compile_javascript_fuzzer plumbline "fuzz/${target}.fuzz.js" --sync
done
