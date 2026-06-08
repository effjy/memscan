CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=gnu99 -D_FILE_OFFSET_BITS=64
TARGETS = memscan test_target

all: $(TARGETS)

memscan: memscan.c
	$(CC) $(CFLAGS) -o memscan memscan.c

test_target: test_target.c
	$(CC) $(CFLAGS) -o test_target test_target.c

clean:
	rm -f $(TARGETS)

.PHONY: all clean
