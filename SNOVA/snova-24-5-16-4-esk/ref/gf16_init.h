#include <stdint.h>
#include <arm_neon.h>
#ifndef GF16_INIT_H
#define GF16_INIT_H
#include "gf16.h"


#ifdef __cplusplus
extern "C" {
#endif

// batch mul registers
static uint8x16_t gf16_tbl0, gf16_tbl1, gf16_tbl2, gf16_tbl3;

static inline void gf16_neon_tbl_init(void)
{
    // mt4b[  0.. 15], mt4b[ 64.. 79], mt4b[128..143], mt4b[192..207]
    gf16_tbl0 = vld1q_u8(mt4b +   0);
    gf16_tbl1 = vld1q_u8(mt4b +  64);
    gf16_tbl2 = vld1q_u8(mt4b + 128);
    gf16_tbl3 = vld1q_u8(mt4b + 192);
}

/**
 * init gf16 tables
 */
void init_gf16_tables() {
    uint8_t F_star[15] = {1, 2,  4, 8,  3,  6,  12, 11,
                          5, 10, 7, 14, 15, 13, 9};  // Z2[x]/(x^4+x+1)
    for (int i = 0; i < 16; ++i) {
        mt(0, i) = mt(i, 0) = 0;
    }

    for (int i = 0; i < 15; ++i)
        for (int j = 0; j < 15; ++j)
            mt(F_star[i], F_star[j]) = F_star[(i + j) % 15];
    {
        int g = F_star[1], g_inv = F_star[14], gn = 1, gn_inv = 1;
        inv4b[0] = 0;
        inv4b[1] = 1;
        for (int index = 0; index < 14; index++)
            inv4b[(gn = mt(gn, g))] = (gn_inv = mt(gn_inv, g_inv));
    }

    gf16_neon_tbl_init();     

}

#ifdef __cplusplus
}
#endif

#endif