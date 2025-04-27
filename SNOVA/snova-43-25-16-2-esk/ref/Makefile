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



# CC = gcc
# CFLAGS += -I. -O3 -Wall -Wextra -march=native -fomit-frame-pointer
# NISTFLAGS = -Wno-sign-compare -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-unused-result
# EXECUTABLE_speed = main

# SRC_C = main2.c aes.c fips202.c randombytes.c sign.c snova.c m1cycles.c rng.c
# SRC_S = AES_assembly.s asm_add.s asm_mul.s asm_get_add.s asm_get_mul.s asm_get_gf.s asm_set_gf.s asm_mt4b_test.s

# OBJ_C = $(SRC_C:.c=.o)
# OBJ_S = $(SRC_S:.s=.o)

# .PHONY: all clean

# # 기본 타겟
# all: $(EXECUTABLE_speed)

# # C 소스 파일 빌드 규칙
# %.o: %.c
# 	$(CC) -c $(CFLAGS) $< -o $@

# # 어셈블리 파일 빌드 규칙
# %.o: %.s
# 	$(CC) -c $< -o $@

# # 실행 파일 생성
# $(EXECUTABLE_speed): $(OBJ_C) $(OBJ_S)
# 	$(CC) $(CFLAGS) $^ -o $@

# # 클린 빌드
# clean:
# 	rm -f $(EXECUTABLE_speed) *.o
