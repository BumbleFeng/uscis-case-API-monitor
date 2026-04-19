#!/bin/bash
# USCIS Case Monitor - Daemon Management Script

DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$DIR/state/scheduler.pid"
LOG_FILE="$DIR/state/scheduler.log"

start() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "⚠️  Scheduler already running (PID $(cat "$PID_FILE"))"
    return 1
  fi

  echo "🚀 Starting USCIS scheduler in background..."
  cd "$DIR"
  nohup node src/monitor.mjs scheduler >> "$LOG_FILE" 2>&1 &
  local pid=$!
  echo "$pid" > "$PID_FILE"
  echo "✅ Scheduler started (PID $pid)"
  echo "   Log: $LOG_FILE"
}

stop() {
  if [ ! -f "$PID_FILE" ]; then
    echo "⚠️  No PID file found. Scheduler not running?"
    return 1
  fi

  local pid
  pid=$(cat "$PID_FILE")
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    rm -f "$PID_FILE"
    echo "🛑 Scheduler stopped (PID $pid)"
  else
    rm -f "$PID_FILE"
    echo "⚠️  Process $pid not found. Cleaned up stale PID file."
  fi
}

status() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    local pid
    pid=$(cat "$PID_FILE")
    local uptime
    uptime=$(ps -p "$pid" -o etime= 2>/dev/null | xargs)
    echo "✅ Scheduler is running (PID $pid, uptime $uptime)"
  else
    [ -f "$PID_FILE" ] && rm -f "$PID_FILE"
    echo "❌ Scheduler is not running"
  fi
}

logs() {
  local lines="${1:-50}"
  if [ -f "$LOG_FILE" ]; then
    tail -n "$lines" "$LOG_FILE"
  else
    echo "No log file found."
  fi
}

follow() {
  if [ -f "$LOG_FILE" ]; then
    tail -f "$LOG_FILE"
  else
    echo "No log file found."
  fi
}

restart() {
  stop 2>/dev/null
  sleep 1
  start
}

case "${1:-}" in
  start)   start ;;
  stop)    stop ;;
  status)  status ;;
  logs)    logs "$2" ;;
  follow)  follow ;;
  restart) restart ;;
  *)
    echo "Usage: $0 {start|stop|status|restart|logs [N]|follow}"
    echo ""
    echo "  start    Start scheduler in background"
    echo "  stop     Stop scheduler"
    echo "  status   Check if scheduler is running"
    echo "  restart  Stop and restart scheduler"
    echo "  logs N   Show last N lines of log (default 50)"
    echo "  follow   Tail log in real time (Ctrl+C to stop)"
    ;;
esac
