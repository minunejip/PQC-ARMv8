#include <stdint.h>
#ifndef GF16_H
#define GF16_H

#define mt(p, q) mt4b[((p) << 4) ^ (q)]
#define inv(gf16) inv4b[(gf16)]
#define gf16_get_add(a, b) ((a) ^ (b))
#define gf16_get_mul(a, b) (mt((a), (b)))

static uint8_t mt4b[256] = {0};
static uint8_t inv4b[16] = {0};

#define ASSEMBLY        // assembly optimization mode(add)
#define ASSEMBLY_MUL     // assembly optimization mode(mul)
#define ASSEMBLY_AES     // assembly optimization mode(AES)

typedef uint8_t gf16_t;

#endif

//ref
// crypto_sign_keypair: 57911107
// crypto_sign: 60674453
// crypto_sign_verify: 35254524

// 셋다
// crypto_sign_keypair: 46343915
// crypto_sign: 59117498
// crypto_sign_verify: 31426092

// ref 3-10
// crypto_sign_keypair: 5846818
// crypto_sign: 2175569
// crypto_sign_verify: 2275998

// asm 3-10 all
// crypto_sign_keypair: 5464205
// crypto_sign: 2187351
// crypto_sign_verify: 1597795