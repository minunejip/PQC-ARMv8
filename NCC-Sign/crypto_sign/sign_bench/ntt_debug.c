/*
 * Debug: check twiddle index k after each NTT stage
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "poly.h"
#include "reduce.h"
#include "randombytes.h"
#include "cpucycles.h"

#include <arm_neon.h>

extern int32_t zetas[];
extern int32_t zetas_inv[];

/* Replicate the merged radix2_upper to trace k */
int main(void) {
#if defined(__aarch64__)
    setup_rdtsc();
#endif

    printf("=== Twiddle index debug for %s (N=%d) ===\n", CRYPTO_ALGNAME, N);

#if NIMS_TRI_NTT_MODE == 3
    #define R3L 1
#else
    #define R3L 3
#endif
    int redlen = (N >> 8);
    printf("radix2_redlen_ntt = %d\n", redlen);
    printf("radix3_len = %d, 3*radix3_len = %d\n", R3L, 3*R3L);

    /* Count expected twiddles for sequential processing */
    int k_expected = 1; /* after stage0 */
    printf("\nExpected sequential twiddle consumption:\n");

    /* radix2_upper */
    for (int len = N >> 2; len > redlen; len >>= 1) {
        int blocks = N / (len << 1);
        printf("  upper len=%d: %d blocks, k: %d -> %d\n", len, blocks, k_expected, k_expected + blocks);
        k_expected += blocks;
    }
    int k_after_upper = k_expected;
    printf("  k after radix2_upper: %d\n", k_after_upper);

    /* radix2_lower */
    for (int len = redlen; len >= 3 * R3L; len >>= 1) {
        int blocks = N / (len << 1);
        printf("  lower len=%d: %d blocks, k: %d -> %d\n", len, blocks, k_expected, k_expected + blocks);
        k_expected += blocks;
    }
    printf("  k after radix2_lower: %d\n", k_expected);

    /* Now check what the merged kernel actually produces */
    printf("\nMerged kernel twiddle consumption:\n");

    /* Simulate merged radix2_upper */
    int k_merged = 1;
    int len = N >> 2;
    while (len > redlen) {
        int len_inner = len >> 1;
        if (len_inner > redlen) {
            int num_outer = N / (len << 1);
            int num_inner = N / (len_inner << 1);
            printf("  merged (len_o=%d, len_i=%d): outer=%d + inner=%d twiddles, k: %d -> %d\n",
                   len, len_inner, num_outer, num_inner, k_merged, k_merged + num_outer + num_inner);
            k_merged += num_outer + num_inner;
            len >>= 2;
        } else {
            int blocks = N / (len << 1);
            printf("  single len=%d: %d blocks, k: %d -> %d\n", len, blocks, k_merged, k_merged + blocks);
            k_merged += blocks;
            len >>= 1;
        }
    }
    printf("  k after merged radix2_upper: %d\n", k_merged);

    if (k_merged != k_after_upper) {
        printf("  *** MISMATCH! expected=%d, got=%d ***\n", k_after_upper, k_merged);
    } else {
        printf("  OK: twiddle count matches.\n");
    }

    /* Also check inverse NTT structure */
    printf("\nInverse NTT twiddle consumption:\n");

    int k_inv_expected = 0;
#if NIMS_TRI_NTT_MODE != 3
    /* radix3 inverse */
    for (int len = 1; len <= R3L; len *= 3) {
        int blocks = N / (3*len);
        printf("  radix3_inv len=%d: %d blocks × 2 twiddles, k: %d -> %d\n",
               len, blocks, k_inv_expected, k_inv_expected + 2*blocks);
        k_inv_expected += 2*blocks;
    }
#endif

    /* radix2 lower (ascending) */
    for (int len = 3*R3L; len < (N>>3); len <<= 1) {
        int blocks = N / (len<<1);
        printf("  inv_lower len=%d: %d blocks, k: %d -> %d\n", len, blocks, k_inv_expected, k_inv_expected + blocks);
        k_inv_expected += blocks;
    }
    int k_inv_before_reduce = k_inv_expected;
    printf("  k before reduce32: %d\n", k_inv_before_reduce);

    /* radix2 upper (ascending) */
    for (int len = (N>>3); len <= (N>>2); len <<= 1) {
        int blocks = N / (len<<1);
        printf("  inv_upper len=%d: %d blocks, k: %d -> %d\n", len, blocks, k_inv_expected, k_inv_expected + blocks);
        k_inv_expected += blocks;
    }
    printf("  k before final: %d\n", k_inv_expected);

    /* Now check merged inverse */
    printf("\nMerged inverse NTT:\n");

    int k_inv_merged = 0;
#if NIMS_TRI_NTT_MODE != 3
    for (int ll = 1; ll <= R3L; ll *= 3) {
        int blocks = N / (3*ll);
        k_inv_merged += 2*blocks;
    }
    printf("  after radix3_inv: k=%d\n", k_inv_merged);
#endif

    /* Merged inverse lower */
    len = 3*R3L;
    while (len < (N>>3)) {
        int len_next = len << 1;
        if (len_next < (N>>3)) {
            int num_inner = N / (len<<1);
            int num_outer = N / (len_next<<1);
            printf("  inv_merged_lower (len_i=%d, len_o=%d): inner=%d + outer=%d, k: %d -> %d\n",
                   len, len_next, num_inner, num_outer, k_inv_merged, k_inv_merged + num_inner + num_outer);
            k_inv_merged += num_inner + num_outer;
            len <<= 2;
        } else {
            int blocks = N / (len<<1);
            printf("  inv_single_lower len=%d: %d blocks, k: %d -> %d\n", len, blocks, k_inv_merged, k_inv_merged + blocks);
            k_inv_merged += blocks;
            len <<= 1;
        }
    }
    printf("  k before reduce32 (merged): %d (expected: %d) %s\n",
           k_inv_merged, k_inv_before_reduce,
           k_inv_merged == k_inv_before_reduce ? "OK" : "*** MISMATCH ***");

    /* Merged inverse upper */
    len = (N>>3);
    while (len <= (N>>2)) {
        int len_next = len << 1;
        if (len_next <= (N>>2)) {
            int num_inner = N / (len<<1);
            int num_outer = N / (len_next<<1);
            printf("  inv_merged_upper (len_i=%d, len_o=%d): inner=%d + outer=%d, k: %d -> %d\n",
                   len, len_next, num_inner, num_outer, k_inv_merged, k_inv_merged + num_inner + num_outer);
            k_inv_merged += num_inner + num_outer;
            len <<= 2;
        } else {
            int blocks = N / (len<<1);
            printf("  inv_single_upper len=%d: %d blocks, k: %d -> %d\n", len, blocks, k_inv_merged, k_inv_merged + blocks);
            k_inv_merged += blocks;
            len <<= 1;
        }
    }
    printf("  k before final (merged): %d (expected: %d) %s\n",
           k_inv_merged, k_inv_expected,
           k_inv_merged == k_inv_expected ? "OK" : "*** MISMATCH ***");

    return 0;
}
