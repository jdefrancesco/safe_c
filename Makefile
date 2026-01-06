CC     = afl-clang-fast
CFLAGS = -O3 -g -std=gnu17 -Wall \
       -fsanitize=address,undefined \
       -D__AFL_HAVE_MANUAL_CONTROL

TEST_CC     = clang
TEST_CFLAGS = -std=gnu17 -Wall -Wextra -g -fsanitize=address,undefined

FUZZERS = \
    fuzz_safe_strings \
    fuzz_safe_strings_limit \
    fuzz_safe_memory  \
    fuzz_safe_alloc   \
    fuzz_safe_snprintf \
    fuzz_safe_bounds

.PHONY: all clean corpus tests

all: $(FUZZERS)



fuzz_%: fuzz_%.c safe_c.h
	$(CC) $(CFLAGS) $< -o $@

test_safe_strings: test_safe_strings.c safe_c.h
	$(TEST_CC) $(TEST_CFLAGS) $< -o $@

tests: test_safe_strings
	./test_safe_strings



corpus: gen_corpus.zsh
	./gen_corpus.zsh corpus


clean:
	rm -f $(FUZZERS)
	rm -rf *.dSYM
	rm -rf findings_*
