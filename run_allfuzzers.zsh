#!/bin/zsh

set -euo pipefail

SESSION="safe_fuzz"
CORPUS="corpus"

export AFL_SKIP_BIN_CHECK=1
export AFL_NO_AFFINITY=1

# Build fuzzers and seed corpus up front
make all corpus

tmux kill-session -t "$SESSION" 2>/dev/null || true

# Launch each fuzzer in its own window (avoid pane-size issues)
tmux new-session -d -s "$SESSION" -n strings
tmux new-window  -t "$SESSION" -n memory
tmux new-window  -t "$SESSION" -n alloc
tmux new-window  -t "$SESSION" -n snprintf
tmux new-window  -t "$SESSION" -n bounds
tmux new-window  -t "$SESSION" -n strings_lim

tmux send-keys -t "$SESSION":strings     "afl-fuzz -i $CORPUS -o findings_strings        -- ./fuzz_safe_strings" C-m
tmux send-keys -t "$SESSION":memory      "afl-fuzz -i $CORPUS -o findings_memory         -- ./fuzz_safe_memory" C-m
tmux send-keys -t "$SESSION":alloc       "afl-fuzz -i $CORPUS -o findings_alloc          -- ./fuzz_safe_alloc" C-m
tmux send-keys -t "$SESSION":snprintf    "afl-fuzz -i $CORPUS -o findings_snprintf       -- ./fuzz_safe_snprintf" C-m
tmux send-keys -t "$SESSION":bounds      "afl-fuzz -i $CORPUS -o findings_bounds         -- ./fuzz_safe_bounds" C-m
tmux send-keys -t "$SESSION":strings_lim "afl-fuzz -i $CORPUS -o findings_strings_limit  -- ./fuzz_safe_strings_limit" C-m

tmux select-window -t "$SESSION":strings
tmux attach-session -t "$SESSION"
