#!/usr/bin/env zsh
set -euo pipefail

CORPUS_DIR="${1:-corpus}"
mkdir -p "$CORPUS_DIR"

emit() {
  local name="$1"; shift
  printf '%s' "$*" > "$CORPUS_DIR/$name"
}

# Basic structures
emit empty "\n"
emit one_char "A"
emit hello "Hello, world!"
printf '%%%%%%%s\n' > "$CORPUS_DIR/percent_signs"
emit whitespace " \t \n"
emit mixed_case "AbCdEfGhIjKlMnOpQrStUvWxYz"

# Boundary-length strings around common buffer sizes
python3 - "$CORPUS_DIR" << 'EOF' 2>/dev/null || true
import os, random, string, sys
dst = sys.argv[1]
def write(name, data):
    open(os.path.join(dst, name), 'wb').write(data)

def rand_ascii(n):
    return ''.join(random.choice(string.ascii_letters + string.digits + ' _-') for _ in range(n)).encode()

for n in (7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256):
    write(f"len_{n}", rand_ascii(n))

# Near a small SAFE_C_MAX_STR used in limit fuzzer (8)
write("max_str_minus1", b"ABCDEFG")
write("max_str_exact", b"ABCDEFGH")
write("max_str_plus1", b"ABCDEFGHI")

# Include embedded NULs and high bytes
write("embedded_nul", b"ABC\0DEF")
write("double_nul", b"\0\0")
write("high_bytes", bytes([0xff, 0xfe, 0xfd, 0x00, 0x7f, 0x80]))

# Repeated patterns and numeric content
write("pattern_ab", (b"ab" * 64))
write("numbers", b"0123456789" * 16)

# Longer ASCII body
write("long_ascii", rand_ascii(512))

# Random-ish binary seeds
write("random_64", os.urandom(64))
write("random_256", os.urandom(256))
EOF

echo "Corpus created in $CORPUS_DIR" >&2
