# libncrypt build, test, and analysis.
#
#   make              build libncrypt.a
#   make check        build and run the test suite
#   make strict       compile everything with the full warning set, -Werror
#   make sanitize      run the test suite under AddressSanitizer and UBSan
#   make valgrind     run the test suite under Valgrind's memcheck
#   make ct           run the constant-time harness under Valgrind
#   make fuzz         standalone fuzz sweep under ASan and UBSan
#   make interop      cross-check against PQClean via the pqcrypto package
#   make differential adversarial inputs, libncrypt vs PQClean verdicts
#   make install      install the headers and the library under PREFIX
#   make clean
#
# The compiler and its flags are overridable as usual:
#   make CC=clang CFLAGS=-O3
#
# Nothing here needs anything beyond a C99 compiler; the analysis targets
# need Valgrind and/or a sanitizer-capable compiler and say so when they
# are missing.

CC       ?= cc
AR       ?= ar
PREFIX   ?= /usr/local
CFLAGS   ?= -O2
CFLAGS   += -std=c99 -Wall -Wextra -Wpedantic -Wshadow \
            -Wstrict-prototypes -Wmissing-prototypes
CPPFLAGS +=

# The library sources must be clean under this set, and are built that
# way by `make strict`; the test programs too.
STRICT_CFLAGS = -Wconversion -Wsign-conversion -Wcast-qual -Wvla \
                -Wundef -Wwrite-strings -Werror

SAN_CFLAGS = -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
             -fno-sanitize-recover=all

VG          ?= valgrind
VG_FLAGS    ?= -q --error-exitcode=42 --leak-check=full \
               --show-leak-kinds=all --track-origins=yes

SRC = ncrypt.c ncrypt-pqc.c
HDR = ncrypt.h ncrypt-pqc.h
OBJ = $(SRC:.c=.o)
LIB = libncrypt.a

TESTS      = test_classic test_pqc test_kat
TEST_SRC   = tests/test_classic.c tests/test_pqc.c tests/test_kat.c
TEST_HDR   = tests/classic_utils.h tests/classic_vectors.h tests/utils.h

.PHONY: all check strict sanitize valgrind ct fuzz interop differential \
        install uninstall clean

all: $(LIB)

$(LIB): $(OBJ)
	$(AR) rcs $@ $(OBJ)

ncrypt.o: ncrypt.c ncrypt.h
ncrypt-pqc.o: ncrypt-pqc.c ncrypt-pqc.h ncrypt.h

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

test_classic: tests/test_classic.c $(TEST_HDR) $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_classic.c $(LIB)

test_pqc: tests/test_pqc.c $(TEST_HDR) $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_pqc.c $(LIB)

test_kat: tests/test_kat.c $(TEST_HDR) $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_kat.c $(LIB)

check: $(TESTS)
	./test_classic
	./test_pqc
	./test_kat tests/vectors
	@echo "all tests passed"

# Compile every translation unit with the full warning set.  Nothing is
# linked; the point is the diagnostics.
strict:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT_CFLAGS) -c -o /dev/null ncrypt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT_CFLAGS) -c -o /dev/null ncrypt-pqc.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT_CFLAGS) -c -o /dev/null tests/test_classic.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT_CFLAGS) -c -o /dev/null tests/test_pqc.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT_CFLAGS) -c -o /dev/null tests/test_kat.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT_CFLAGS) -c -o /dev/null tests/test_ct.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT_CFLAGS) -Wno-missing-prototypes \
	      -c -o /dev/null tests/fuzz_pqc.c
	@echo "strict: no diagnostics"

sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(SAN_CFLAGS)" check
	$(MAKE) clean

valgrind:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -std=c99 -Wall -Wextra" check-keep
	$(MAKE) clean

# Build and run under memcheck without going through `clean` first.
check-keep: $(TESTS)
	$(VG) $(VG_FLAGS) ./test_classic
	$(VG) $(VG_FLAGS) ./test_pqc
	$(VG) $(VG_FLAGS) ./test_kat tests/vectors
	@echo "valgrind: clean"

# Constant-time harness.  Secrets are marked undefined and Valgrind
# reports every branch or memory access that depends on them; the
# reviewed exceptions are in tests/ct.supp.  See doc/TESTING.md.
ct: test_ct
	$(VG) -q --error-exitcode=42 --suppressions=tests/ct.supp ./test_ct
	@echo "ct: no unsuppressed secret-dependent branch"

test_ct: tests/test_ct.c tests/ct.supp $(SRC) $(HDR)
	$(CC) $(CPPFLAGS) -O1 -g -std=c99 -Wall -Wextra -Wpedantic \
	      -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
	      -DHAVE_VALGRIND -o $@ tests/test_ct.c $(SRC)

fuzz_pqc: tests/fuzz_pqc.c $(SRC) $(HDR)
	$(CC) $(CPPFLAGS) -std=c99 -O1 -g -fsanitize=address,undefined \
	      -fno-sanitize-recover=all -DFUZZ_STANDALONE \
	      -o $@ tests/fuzz_pqc.c $(SRC)

fuzz: fuzz_pqc
	./fuzz_pqc
	@echo "fuzz: sweep completed"

# Cross-implementation check.  Needs python3 and `pip install pqcrypto`;
# skipped with a message when the package is missing.
interop:
	python3 tests/interop.py

# Differential test on inputs an attacker chooses.  Same dependency as
# interop; ROUNDS>1 repeats the sweep with a different random stream.
ROUNDS ?= 1
differential:
	python3 tests/differential.py $(ROUNDS)

install: $(LIB)
	mkdir -p $(DESTDIR)$(PREFIX)/include $(DESTDIR)$(PREFIX)/lib
	cp $(HDR) $(DESTDIR)$(PREFIX)/include/
	cp $(LIB) $(DESTDIR)$(PREFIX)/lib/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/include/ncrypt.h
	rm -f $(DESTDIR)$(PREFIX)/include/ncrypt-pqc.h
	rm -f $(DESTDIR)$(PREFIX)/lib/$(LIB)

clean:
	rm -f $(OBJ) $(LIB) $(TESTS) test_ct fuzz_pqc
