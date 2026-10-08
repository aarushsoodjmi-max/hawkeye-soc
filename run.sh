#!/usr/bin/env bash

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "🚀 Starting HawkEye SOC..."

# Use the existing Python 3.12 virtual environment.
if [[ ! -d "$ROOT_DIR/.venv" ]]; then
    echo "❌ .venv not found."
    echo "Create it with:"
    echo "    python3.12 -m venv .venv"
    exit 1
fi

source "$ROOT_DIR/.venv/bin/activate"

echo "🐍 Python: $(python --version)"

# Start backend
echo "🛡️ Starting backend on http://127.0.0.1:8000..."

python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    > "$ROOT_DIR/backend.log" 2>&1 &

BACKEND_PID=$!

cleanup() {
    echo
    echo "🛑 Stopping HawkEye..."

    kill "$BACKEND_PID" 2>/dev/null || true

    if [[ -n "${FRONTEND_PID:-}" ]]; then
        kill "$FRONTEND_PID" 2>/dev/null || true
    fi

    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# Give backend a moment to initialize
sleep 2

if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "❌ Backend failed to start."
    echo
    cat "$ROOT_DIR/backend.log"
    exit 1
fi

echo "✅ Backend running (PID $BACKEND_PID)"

# Start frontend
if [[ ! -d "$ROOT_DIR/app" ]]; then
    echo "❌ Frontend directory '$ROOT_DIR/app' not found."
    exit 1
fi

cd "$ROOT_DIR/app"

echo "🌐 Starting frontend..."

npm run dev &
FRONTEND_PID=$!

echo
echo "======================================"
echo "       HAWKEYE SOC IS RUNNING"
echo "======================================"
echo
echo "Backend:  http://127.0.0.1:8000"
echo "API Docs: http://127.0.0.1:8000/docs"
echo "Frontend: http://127.0.0.1:5173"
echo
echo "Press Ctrl+C to stop everything."
echo

wait "$FRONTEND_PID"
