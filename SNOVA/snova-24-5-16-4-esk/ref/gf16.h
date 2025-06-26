#include <stdint.h>
#ifndef GF16_H
#define GF16_H

#define mt(p, q) mt4b[((p) << 4) ^ (q)]
#define inv(gf16) inv4b[(gf16)]
#define gf16_get_add(a, b) ((a) ^ (b))
#define gf16_get_mul(a, b) (mt((a), (b)))

static uint8_t mt4b[256] = {0};
static uint8_t inv4b[16] = {0};

// #define ASSEMBLY         // rank4 assembly optimization mode(add)
#define ASSEMBLY_RANK2   // rank2 assembly optimization mode(add)
#define ASSEMBLY_MUL     // assembly optimization mode(mul)
#define ASSEMBLY_AES     // assembly optimization mode(AES)


typedef uint8_t gf16_t;

#endif



