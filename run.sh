#!/usr/bin/env bash
set -e

if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo "Warning: ANTHROPIC_API_KEY is not set."
fi

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY

SESSION="proxywatcher"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "[proxywatcher] Session '$SESSION' already running. Attaching..."
  tmux attach -t "$SESSION"
  exit 0
fi

tmux new-session -d -s "$SESSION" -x 220 -y 50

# Pane 0: FastAPI backend
tmux send-keys -t "$SESSION:0" \
  "cd $PROJECT_ROOT && source .venv/bin/activate && uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload" Enter

# Pane 1: mitmproxy
tmux split-window -v -t "$SESSION:0"
tmux send-keys -t "$SESSION:0.1" \
  "cd $PROJECT_ROOT && source .venv/bin/activate && ~/.local/bin/mitmdump --listen-host 0.0.0.0 --listen-port 8080 --ssl-insecure -s addon/interceptor.py" Enter

# Pane 2: DNS monitor
tmux split-window -v -t "$SESSION:0"
tmux send-keys -t "$SESSION:0.2" \
  "cd $PROJECT_ROOT && sudo /usr/bin/python3.10 dns_monitor.py" Enter

tmux select-layout -t "$SESSION:0" even-vertical

echo ""
echo "  Dashboard  : http://localhost:8000"
echo "  HTTP Proxy : 0.0.0.0:8080"
echo "  DNS Monitor: 10.10.10.1:5353"
echo ""
echo "  Session: tmux attach -t $SESSION"
echo "  Stop:    tmux kill-session -t $SESSION"
echo ""

tmux attach -t "$SESSION"
