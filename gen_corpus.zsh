#!/usr/bin/env zsh
set -e

CORPUS_DIR="${1:-corpus}"

mkdir -p "$CORPUS_DIR"

# Simple small seeds
echo "" > "$CORPUS_DIR/empty"
echo "A" > "$CORPUS_DIR/one_char"
echo "Hello, world!" > "$CORPUS_DIR/hello"
printf '%%%%%%%s\n' > "$CORPUS_DIR/percent_signs"

# Long-ish ASCII seed
python3 - << 'EOF' > "$CORPUS_DIR/long_ascii" 2>/dev/null || \
perl -e 'print "A" x 200' > "$CORPUS_DIR/long_ascii"
EOF

# Random-ish binary seed
if [ -r /dev/urandom ]; then
  head -c 256 /dev/urandom > "$CORPUS_DIR/random_256" || true
fi

echo "Corpus created in $CORPUS_DIR"