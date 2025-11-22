#!/bin/zsh

SESSION="safe_fuzz"
CORPUS="corpus"

export AFL_SKIP_BIN_CHECK=1
export AFL_NO_AFFINITY=1

tmux kill-session -t $SESSION 2>/dev/null

tmux new-session  -d -s $SESSION "afl-fuzz -i corpus -o findings_strings  -- ./fuzz_safe_strings"
tmux split-window -v                "afl-fuzz -i corpus -o findings_memory  -- ./fuzz_safe_memory"
tmux split-window -h                "afl-fuzz -i corpus -o findings_alloc   -- ./fuzz_safe_alloc"

tmux select-pane -t 0
tmux split-window -h                "afl-fuzz -i corpus -o findings_snprintf -- ./fuzz_safe_snprintf"

tmux split-window -v                "afl-fuzz -i corpus -o findings_bounds   -- ./fuzz_safe_bounds"

tmux select-layout tiled
tmux attach-session -t $SESSION