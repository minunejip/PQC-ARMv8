CC = gcc
CFLAGS += -I. -O3 -Wall -Wextra -march=native -fomit-frame-pointer
NISTFLAGS = -Wno-sign-compare -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-unused-result
EXECUTABLE_speed = main

.PHONY: all clean

all: $(EXECUTABLE_speed)

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

$(EXECUTABLE_speed): main2.c aes.c fips202.c randombytes.c sign.c snova.c m1cycles.c rng.c AES_assembly.s asm_add.s
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(EXECUTABLE_speed) *.o


