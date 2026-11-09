#!/bin/sh
# Run a guard with whichever Python 3 is available (python3, or python on Windows).
# Usage: sh <this folder>/run.sh <guard>.py [args...]   (stdin is passed through for agent hooks)
DIR=$(cd "$(dirname "$0")" && pwd)
SCRIPT=$1
shift
for py in python3 python; do
  # Windows' python3 Store stub fails this check and falls through to python.
  ok=$("$py" -c "import sys; print(sys.version_info >= (3, 8))" 2>&1)
  if [ "$ok" = "True" ]; then
    exec "$py" "$DIR/$SCRIPT" "$@"
  fi
done
echo "[guard] Python 3.8+ not found; guards skipped" >&2
exit 0
