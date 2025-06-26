#ifndef GF16M_INLINE_H
#define GF16M_INLINE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "deriv_params.h"
#include "gf16_init.h"
#include "gf16_matrix.h"

#include <arm_neon.h>


extern void asm_add(
    gf16_t *A,
    gf16_t *B,
    gf16_t *C
);

static uint8x16_t gf16_tbl0, gf16_tbl1, gf16_tbl2, gf16_tbl3;


static inline void gf16m_rank2_add_batch4(
        const uint8_t *A4x4,  
              uint8_t *C4x4)   
{

    uint8x16_t va = vld1q_u8(A4x4);
    uint8x16_t vc = vld1q_u8(C4x4);
    vc = veorq_u8(vc, va);
    vst1q_u8(C4x4, vc);

}

void pack4_rank2(const uint8_t *M, int nMat, uint8_t *flat)
{
    int blk = 0;
    for (int i = 0; i < nMat; i += 4) {
    
        for (int m = 0; m < 4; ++m)  {
            if (i + m < nMat)
                memcpy(flat + blk*16 + m*4, M + (i+m)*4, 4);
            else                    /* tail - pad 0 */
                memset(flat + blk*16 + m*4, 0, 4);
        }
        blk++;
    }
}


static inline void gf16_add_batch16(
        const uint8_t *A,   /* 16B */
        const uint8_t *B,   /* 16B */
              uint8_t *C)   /* 16B : C ← C ⊕ (A ⊕ B) */
{
    uint8x16_t va = vld1q_u8(A);
    uint8x16_t vb = vld1q_u8(B);
    uint8x16_t vc = vld1q_u8(C);

    vc = veorq_u8(vc, veorq_u8(va, vb));   
    vst1q_u8(C, vc);
}


static inline void gf16m_rank2_muladd_batch4(
        const uint8_t *A16,
        const uint8_t *B16,
              uint8_t *C16)
{

    uint8x16_t va = vld1q_u8(A16);          /* a0 a1 a2 a3 | … */
    uint8x16_t vb = vld1q_u8(B16);          /* b0 b1 b2 b3 | … */


    const uint8x16_t mask = vdupq_n_u8(0x0F);

    uint8x16_t idx1 = vorrq_u8(vshlq_n_u8(va & mask, 4),
                               vb & mask);

   
    const uint8x16_t rot = { 1,0, 3,2, 5,4, 7,6,
                             9,8,11,10,13,12,15,14 };
    uint8x16_t vb_sw = vqtbl1q_u8(vb, rot);

    uint8x16_t idx2 = vorrq_u8(vshlq_n_u8(va & mask, 4),
                               vb_sw & mask);

    /* 3) GF(16) LUT  */
    const uint8x16x4_t tbl = { .val = {gf16_tbl0,gf16_tbl1,gf16_tbl2,gf16_tbl3} };

    uint8x16_t prod =
        veorq_u8(vqtbl4q_u8(tbl, idx1),
                 vqtbl4q_u8(tbl, idx2));    /* (a*b0)⊕(a*b1) */

    /* 4) C ← C ⊕ prod */
    vst1q_u8(C16, veorq_u8(vld1q_u8(C16), prod));
}





// POD -> entry[a][b] * (entry[c][d] * entry[e][f] + entry[g][h] * entry[i][j])
#define POD(entry, a, b, c, d, e, f, g, h, i, j)                          \
    gf16_get_mul(                                                         \
        get_gf16m(entry, a, b),                                           \
        gf16_get_add(                                                     \
            gf16_get_mul(get_gf16m(entry, c, d), get_gf16m(entry, e, f)), \
            gf16_get_mul(get_gf16m(entry, g, h), get_gf16m(entry, i, j))))

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Zeroing the GF16 Matrix a.
 */
static inline void gf16m_set_zero(gf16m_t a) { memset(a, 0, sq_rank); }

/**
 * Adding GF16 Matrices. c = a + b
 */
static inline void gf16m_add(gf16_t *a, gf16_t *b, gf16_t *c) {
    for (int i = 0; i < rank; ++i) {
        for (int j = 0; j < rank; ++j) {
            set_gf16m(c, i, j,
                      gf16_get_add(get_gf16m(a, i, j), get_gf16m(b, i, j)));
        }
    }
 
}


/**
 * Multiplying GF16 Matrices. c = a * b
 */
static inline void gf16m_mul(gf16m_t a, gf16m_t b, gf16m_t c) {
    for (int i = 0; i < rank; ++i) {
        for (int j = 0; j < rank; ++j) {
            set_gf16m(c, i, j,
                      gf16_get_mul(get_gf16m(a, i, 0), get_gf16m(b, 0, j)));
            for (int k = 1; k < rank; ++k) {
                set_gf16m(c, i, j,
                          gf16_get_add(get_gf16m(c, i, j),
                                       gf16_get_mul(get_gf16m(a, i, k),
                                                    get_gf16m(b, k, j))));
            }
        }
    }
}

// neon mul 4x4
static inline void gf16m_neon_mul_rank4(const gf16m_t a, const gf16m_t b, gf16m_t c) {
    for (int i = 0; i < rank; ++i) { 
       
        uint8x16_t sum0 = vdupq_n_u8(gf16_get_mul(a[i * 4], b[0]));
        uint8x16_t sum1 = vdupq_n_u8(gf16_get_mul(a[i * 4], b[1]));
        uint8x16_t sum2 = vdupq_n_u8(gf16_get_mul(a[i * 4], b[2]));
        uint8x16_t sum3 = vdupq_n_u8(gf16_get_mul(a[i * 4], b[3]));

        for (int k = 1; k < 4; ++k) {
            
            uint8x16_t prod0 = vdupq_n_u8(gf16_get_mul(a[i * 4 + k], b[k * 4]));
            uint8x16_t prod1 = vdupq_n_u8(gf16_get_mul(a[i * 4 + k], b[k * 4 + 1]));
            uint8x16_t prod2 = vdupq_n_u8(gf16_get_mul(a[i * 4 + k], b[k * 4 + 2]));
            uint8x16_t prod3 = vdupq_n_u8(gf16_get_mul(a[i * 4 + k], b[k * 4 + 3]));

            
            sum0 = veorq_u8(sum0, prod0); 
            sum1 = veorq_u8(sum1, prod1);
            sum2 = veorq_u8(sum2, prod2);
            sum3 = veorq_u8(sum3, prod3);
        }


        c[i * 4 + 0] = vgetq_lane_u8(sum0, 0); 
        c[i * 4 + 1] = vgetq_lane_u8(sum1, 0); 
        c[i * 4 + 2] = vgetq_lane_u8(sum2, 0); 
        c[i * 4 + 3] = vgetq_lane_u8(sum3, 0); 
    }
}

static inline void gf16m_neon_mul_rank3(const gf16m_t a, const gf16m_t b, gf16m_t c) {
 
}

// neon mul 2x2
static inline void gf16m_neon_mul_rank2(const gf16m_t a, const gf16m_t b, gf16m_t c) {
    for (int i = 0; i < 2; ++i) { 

        uint8x16_t sum0 = vdupq_n_u8(gf16_get_mul(a[i * 2 + 0], b[0]));
        uint8x16_t sum1 = vdupq_n_u8(gf16_get_mul(a[i * 2 + 0], b[1]));


        uint8x16_t prod0 = vdupq_n_u8(gf16_get_mul(a[i * 2 + 1], b[2]));
        uint8x16_t prod1 = vdupq_n_u8(gf16_get_mul(a[i * 2 + 1], b[3]));


        sum0 = veorq_u8(sum0, prod0);
        sum1 = veorq_u8(sum1, prod1);


        c[i * 2 + 0] = vgetq_lane_u8(sum0, 0);  
        c[i * 2 + 1] = vgetq_lane_u8(sum1, 0); 
    }
}


#if defined(ASSEMBLY_MUL)
#define gf16m_neon_mul(a, b, c)         \
    do {                                \
        if (rank == 2) {                \
            gf16m_neon_mul_rank2(a, b, c); \
        } else if (rank == 3) {         \
            gf16m_neon_mul_rank3(a, b, c); \
        } else if (rank == 4) {         \
            gf16m_neon_mul_rank4(a, b, c); \
        } else {                        \
            fprintf(stderr, "Error: Unsupported rank value %d.\n", rank); \
            exit(EXIT_FAILURE);         \
        }                               \
    } while (0)
#endif






/**
 * Scaling the GF16 Matrix. c = Scaling "a" by a factor of "k"
 */
static inline void gf16m_scale(gf16m_t a, gf16_t k, gf16m_t c) {
    for (int i = 0; i < rank; ++i) {
        for (int j = 0; j < rank; ++j) {
            set_gf16m(c, i, j, gf16_get_mul(get_gf16m(a, i, j), k));
        }
    }
}

/**
 * Transposing the GF16 Matrix. ap = aT
 */
static inline void gf16m_transpose(gf16m_t a, gf16m_t ap) {
    for (int i = 0; i < rank; ++i) {
        for (int j = 0; j < rank; ++j) {
            set_gf16m(ap, i, j, get_gf16m(a, j, i));
        }
    }
}

/**
 * Cloning the GF16 Matrix target = source
 */
static inline void gf16m_clone(gf16m_t target, gf16m_t source) {
    memcpy(target, source, sq_rank);
}

/**
 * be_aI
 */
static inline void be_aI(gf16m_t target, gf16_t a) {
    for (int i = 0; i < rank; ++i) {
        for (int j = 0; j < rank; ++j) {
            set_gf16m(target, i, j, (i == j) ? a : 0);
        }
    }
}

/**
 * be_the_S
 */
static inline void be_the_S(gf16m_t target) {
    for (int i = 0; i < rank; ++i) {
        for (int j = 0; j < rank; ++j) {
            set_gf16m(target, i, j, (8 - (i + j)));
        }
    }
}

/**
 * gf16m_det
 */
static inline gf16_t gf16m_det(gf16m_t entry) {
#if rank == 2
    return gf16_get_add(
        gf16_get_mul(get_gf16m(entry, 0, 0), get_gf16m(entry, 1, 1)),
        gf16_get_mul(get_gf16m(entry, 0, 1), get_gf16m(entry, 1, 0)));
    // (entry[0][0] * entry[1][1] + entry[0][1] * entry[1][0]);
#elif rank == 3
    return gf16_get_add(
        gf16_get_add(
            gf16_get_mul(get_gf16m(entry, 0, 0),
                         gf16_get_add(gf16_get_mul(get_gf16m(entry, 1, 1),
                                                   get_gf16m(entry, 2, 2)),
                                      gf16_get_mul(get_gf16m(entry, 1, 2),
                                                   get_gf16m(entry, 2, 1)))),
            // AAAAA(entry, 0, 0, 1, 1, 2, 2, 1, 2, 2, 1),
            gf16_get_mul(get_gf16m(entry, 0, 1),
                         gf16_get_add(gf16_get_mul(get_gf16m(entry, 1, 0),
                                                   get_gf16m(entry, 2, 2)),
                                      gf16_get_mul(get_gf16m(entry, 1, 2),
                                                   get_gf16m(entry, 2, 0))))),
        gf16_get_mul(
            get_gf16m(entry, 0, 2),
            gf16_get_add(
                gf16_get_mul(get_gf16m(entry, 1, 0), get_gf16m(entry, 2, 1)),
                gf16_get_mul(get_gf16m(entry, 1, 1), get_gf16m(entry, 2, 0)))));

    /*
    (
            (entry[0][0] * (entry[1][1] * entry[2][2] + entry[1][2] *
    entry[2][1])) + (entry[0][1] * (entry[1][0] * entry[2][2] + entry[1][2] *
    entry[2][0])) + (entry[0][2] * (entry[1][0] * entry[2][1] + entry[1][1] *
    entry[2][0]))
    )

    */

    // gf16_get_mul(gf16_get_mul(get_gf16m(entry, 0, 1),
    // gf16_get_add(gf16_get_mul(get_gf16m(entry, 1, 0), get_gf16m(entry, 2,
    // 2)), gf16_get_mul(get_gf16m(entry, 1, 2), get_gf16m(entry, 2, 0)))))),
    // gf16_get_mul(gf16_get_mul(get_gf16m(entry, 0, 2),
    // gf16_get_add(gf16_get_mul(get_gf16m(entry, 1, 0), get_gf16m(entry, 2,
    // 1)), gf16_get_mul(get_gf16m(entry, 1, 1), get_gf16m(entry, 2, 0))))));

#elif rank == 4

    gf16_t d0 = gf16_get_mul(
        get_gf16m(entry, 0, 0),
        gf16_get_add(gf16_get_add(POD(entry, 1, 1, 2, 2, 3, 3, 2, 3, 3, 2),
                                  POD(entry, 1, 2, 2, 1, 3, 3, 2, 3, 3, 1)),
                     POD(entry, 1, 3, 2, 1, 3, 2, 2, 2, 3, 1)));

    gf16_t d1 = gf16_get_mul(
        get_gf16m(entry, 0, 1),
        gf16_get_add(gf16_get_add(POD(entry, 1, 0, 2, 2, 3, 3, 2, 3, 3, 2),
                                  POD(entry, 1, 2, 2, 0, 3, 3, 2, 3, 3, 0)),
                     POD(entry, 1, 3, 2, 0, 3, 2, 2, 2, 3, 0)));

    gf16_t d2 = gf16_get_mul(
        get_gf16m(entry, 0, 2),
        gf16_get_add(gf16_get_add(POD(entry, 1, 0, 2, 1, 3, 3, 2, 3, 3, 1),
                                  POD(entry, 1, 1, 2, 0, 3, 3, 2, 3, 3, 0)),
                     POD(entry, 1, 3, 2, 0, 3, 1, 2, 1, 3, 0)));

    gf16_t d3 = gf16_get_mul(
        get_gf16m(entry, 0, 3),
        gf16_get_add(gf16_get_add(POD(entry, 1, 0, 2, 1, 3, 2, 2, 2, 3, 1),
                                  POD(entry, 1, 1, 2, 0, 3, 2, 2, 2, 3, 0)),
                     POD(entry, 1, 2, 2, 0, 3, 1, 2, 1, 3, 0)));

    return gf16_get_add(gf16_get_add(gf16_get_add(d0, d1), d2), d3);
    /*
    (
            entry[0][0] * (
                    (entry[1][1] * (entry[2][2] * entry[3][3] + entry[2][3] *
    entry[3][2])) + (entry[1][2] * (entry[2][1] * entry[3][3] + entry[2][3] *
    entry[3][1])) + (entry[1][3] * (entry[2][1] * entry[3][2] + entry[2][2] *
    entry[3][1]))

            ) +

            entry[0][1] * (
                    (entry[1][0] * (entry[2][2] * entry[3][3] + entry[2][3] *
    entry[3][2])) + (entry[1][2] * (entry[2][0] * entry[3][3] + entry[2][3] *
    entry[3][0])) + (entry[1][3] * (entry[2][0] * entry[3][2] + entry[2][2] *
    entry[3][0])) ) +

            entry[0][2] * (
                    (entry[1][0] * (entry[2][1] * entry[3][3] + entry[2][3] *
    entry[3][1])) + (entry[1][1] * (entry[2][0] * entry[3][3] + entry[2][3] *
    entry[3][0])) + (entry[1][3] * (entry[2][0] * entry[3][1] + entry[2][1] *
    entry[3][0])) ) +

            entry[0][3] * (
                    (entry[1][0] * (entry[2][1] * entry[3][2] + entry[2][2] *
    entry[3][1])) + (entry[1][1] * (entry[2][0] * entry[3][2] + entry[2][2] *
    entry[3][0])) + (entry[1][2] * (entry[2][0] * entry[3][1] + entry[2][1] *
    entry[3][0]))
    )
    */
#endif
    return 0;
}

/**
 * be_aS
 */
static inline void be_aS(gf16m_t target, gf16_t a) {
    for (int i = 0; i < rank; ++i) {
        for (int j = 0; j < rank; ++j) {
            set_gf16m(target, i, j, gf16_get_mul((8 - (i + j)), a));
        }
    }
}

/**
 * be_invertible_by_add_aS
 */
static inline void be_invertible_by_add_aS(gf16m_t source) {
    gf16m_t temp;
    if (gf16m_det(source) == 0) {
        for (uint8_t a = 1; a < 16; ++a) {
            be_aS(temp, a);

        #ifndef ASSEMBLY
            gf16m_add(temp, source, source);
        #else
            asm_add(temp, source, source);
        #endif

            if (gf16m_det(source) != 0) {
                return;
            }
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif