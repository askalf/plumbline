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
# nothing and `npm ci` at the root would be a no-op. Jazzer.js is a
# fuzz-build-time-only tool, kept out of plumbline's own package.json so the
# published dependency tree stays exactly as committed. It comes from its own
# lockfile (.clusterfuzzlite/package-lock.json) so `npm ci` verifies every
# integrity hash (Scorecard Pinned-Dependencies), then gets copied into the
# project node_modules where compile_javascript_fuzzer expects to resolve it.
# The fuzz targets in ./fuzz import only from ../src, so no project install is
# needed beyond Jazzer itself.
npm ci --prefix .clusterfuzzlite --no-audit --no-fund
mkdir -p node_modules
cp -r .clusterfuzzlite/node_modules/. node_modules/

# --sync: every target's fuzz() is synchronous (assessTrajectory, buildTrajectory
# and normalizeEvent are all sync). An async target would omit this flag.
for target in assess_trajectory infer_capability normalize_event; do
  compile_javascript_fuzzer plumbline "fuzz/${target}.fuzz.js" --sync
done
