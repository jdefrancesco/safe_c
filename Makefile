###############################
# AFL++ Makefile (macOS ARM64)
###############################

CC     = afl-clang-fast
CFLAGS = -O3 -g -std=gnu17 -Wall \
       -fsanitize=address,undefined \
       -D__AFL_HAVE_MANUAL_CONTROL 

FUZZERS = \
    fuzz_safe_strings \
    fuzz_safe_memory  \
    fuzz_safe_alloc   \
    fuzz_safe_snprintf \
    fuzz_safe_bounds

.PHONY: all clean corpus

all: $(FUZZERS)

###########################################
# Build fuzzers using AFL instrumentation
###########################################

fuzz_%: fuzz_%.c safe_c.h
	$(CC) $(CFLAGS) $< -o $@


###########################################
# Corpus generation
###########################################
corpus:
	mkdir -p corpus
	echo "seed" > corpus/seed1
	echo "AAAA" > corpus/seed2
	echo "12345678" > corpus/seed3

###########################################
# Cleanup
###########################################
clean:
	rm -f $(FUZZERS)
	rm -rf *.dSYM
