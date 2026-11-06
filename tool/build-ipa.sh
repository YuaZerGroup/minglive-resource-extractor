#!/usr/bin/env bash
# Builds an unsigned `.ipa` locally on macOS.
#
# This mirrors exactly what .github/workflows/build-ipa.yml does step by step, so
# the same result can be produced without CI (useful when the hosted macOS runner
# quota is unavailable).
#
# Usage:
#   ./tool/build-ipa.sh                 # full build + package
#   ./tool/build-ipa.sh --skip-tests    # faster iteration
#
# Output:
#   build/ipa/MingLiveExtractor-unsigned.ipa
#   build/ipa/MingLiveExtractor-unsigned.ipa.sha256
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SKIP_TESTS=0
for arg in "$@"; do
  case "$arg" in
    --skip-tests) SKIP_TESTS=1 ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

step "Checking host"
[ "$(uname -s)" = "Darwin" ] || fail "iOS builds require macOS; detected $(uname -s)"
command -v xcodebuild >/dev/null 2>&1 || fail "xcodebuild not found; install Xcode"
command -v flutter    >/dev/null 2>&1 || fail "flutter not found on PATH"
xcodebuild -version
flutter --version

step "Checking Git LFS payload"
if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
  git lfs pull || echo "warning: 'git lfs pull' failed; continuing with local files"
fi
count=$(find assets/builtin-slices -name '*.part' -type f | wc -l | tr -d ' ')
echo "slice files: $count"
[ "$count" -eq 340 ] || fail "expected 340 slice files, found $count"
smallest=$(find assets/builtin-slices -name '*.part' -type f -exec stat -f '%z' {} + | sort -n | head -n 1)
echo "smallest slice: ${smallest} bytes"
[ "$smallest" -ge 1000 ] || fail "slice files look like LFS pointers; run 'git lfs pull'"
du -sh assets/builtin-slices

step "Regenerating the asset manifest"
dart tool/gen_asset_manifest.dart
echo "asset entries: $(grep -c '^    - assets/' pubspec.yaml)"

step "Installing dependencies"
flutter pub get

step "Static analysis"
flutter analyze --no-fatal-infos --no-fatal-warnings

if [ "$SKIP_TESTS" -eq 0 ]; then
  step "Running tests"
  flutter test --reporter expanded
else
  echo "tests skipped (--skip-tests)"
fi

step "Installing CocoaPods"
( cd ios && pod install --repo-update )

step "Building iOS release without code signing"
set -o pipefail
flutter build ios --release --no-codesign 2>&1 | tail -n 250

APP="build/ios/iphoneos/Runner.app"
[ -d "$APP" ] || fail "missing $APP"
echo "app size: $(du -sh "$APP" | cut -f1)"
file "$APP/Runner" || true

n=$(find "$APP/Frameworks/App.framework/flutter_assets/assets/builtin-slices" -name '*.part' | wc -l | tr -d ' ')
echo "bundled slices: $n"
[ "$n" -eq 340 ] || fail "expected 340 bundled slices, got $n"

step "Packaging the unsigned IPA"
OUT="build/ipa"
rm -rf "$OUT"
mkdir -p "$OUT/Payload"
cp -R "$APP" "$OUT/Payload/Runner.app"
( cd "$OUT" && zip -qry -y MingLiveExtractor-unsigned.ipa Payload )
ls -lh "$OUT/MingLiveExtractor-unsigned.ipa"
( cd "$OUT" && shasum -a 256 MingLiveExtractor-unsigned.ipa \
    | tee MingLiveExtractor-unsigned.ipa.sha256 )

step "Validating the IPA"
IPA="$OUT/MingLiveExtractor-unsigned.ipa"
unzip -l "$IPA" | head -n 15
unzip -l "$IPA" | grep -q 'Payload/Runner.app/Runner' \
  || fail "Runner binary missing from IPA"
inipa=$(unzip -l "$IPA" | grep -c 'builtin-slices/.*\.part' || true)
echo "slices in IPA: $inipa"
[ "$inipa" -eq 340 ] || fail "expected 340 slices inside the IPA, got $inipa"

printf '\n\033[1;32mDone.\033[0m\n'
echo "IPA:      $REPO_ROOT/$OUT/MingLiveExtractor-unsigned.ipa"
echo "Checksum: $REPO_ROOT/$OUT/MingLiveExtractor-unsigned.ipa.sha256"
echo
echo "The IPA is UNSIGNED. Signing is up to you, e.g.:"
echo "  codesign -f -s \"Apple Development: you@example.com\" --entitlements Runner.entitlements Payload/Runner.app"
