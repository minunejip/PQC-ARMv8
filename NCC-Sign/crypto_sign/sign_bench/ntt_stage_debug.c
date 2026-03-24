/*
 * Stage-by-stage NTT comparison: find exactly where merged diverges from reference.
 * Only for Sign-5 (N=2304).
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

/* Import the NEON helpers from poly.c — we redefine them here for testing */
extern int32x4_t reduce32_vec(int32x4_t x);
extern int32x4_t montgomery_mul4_sqdmulh(int32x4_t b, int32x4_t vZ,
                                          int32x4_t vQ, int32x4_t vQINV);

static int compare_arrays(const char *label, int32_t *a, int32_t *b, int n) {
    int mismatches = 0;
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            if (mismatches < 3)
                printf("  %s mismatch at [%d]: got=%d expected=%d diff=%d\n",
                       label, i, a[i], b[i], a[i] - b[i]);
            mismatches++;
        }
    }
    if (mismatches > 0)
        printf("  %s: %d/%d mismatches\n", label, mismatches, n);
    else
        printf("  %s: OK (all match)\n", label);
    return mismatches;
}

int main(void) {
#if defined(__aarch64__)
    setup_rdtsc();
#endif

    printf("=== Stage-by-stage NTT debug for %s (N=%d) ===\n", CRYPTO_ALGNAME, N);

    int32_t input[N], ref[N], merged[N];

    randombytes((uint8_t*)input, sizeof(input));
    for (int i = 0; i < N; i++) input[i] = ((int32_t)input[i]) % Q;

    memcpy(ref, input, sizeof(ref));
    memcpy(merged, input, sizeof(merged));

    int32_t t1;
    int k_ref = 0, k_merged = 1;

    /* Stage 0: identical for both */
    {
        int32_t z = zetas[k_ref++];
        for (int j = 0; j < N/2; j++) {
            t1 = montgomery_reduce((int64_t)z * ref[j + N/2]);
            ref[j + N/2] = ref[j] + ref[j + N/2] - t1;
            ref[j] = ref[j] + t1;
        }
    }
    /* Same for merged path */
    {
        const int32x4_t vQ_ = vdupq_n_s32(Q);
        const int32x4_t vQINV_ = vdupq_n_s32(QINV);
        int32_t z = zetas[0];
        int32x4_t vZ = vdupq_n_s32(z);
        for (int j = 0; j < N/2; j += 4) {
            int32x4_t a = vld1q_s32(&merged[j]);
            int32x4_t b = vld1q_s32(&merged[j + N/2]);
            int32x4_t t = montgomery_mul4_sqdmulh(b, vZ, vQ_, vQINV_);
            int32x4_t a_plus_t = vaddq_s32(a, t);
            int32x4_t a_plus_b = vaddq_s32(a, b);
            int32x4_t b_new    = vsubq_s32(a_plus_b, t);
            vst1q_s32(&merged[j], a_plus_t);
            vst1q_s32(&merged[j + N/2], b_new);
        }
    }
    compare_arrays("After stage0", merged, ref, N);

    /* Radix2 upper: reference (sequential) */
    int redlen = (N >> 8);
    for (int len = N >> 2; len > redlen; len >>= 1) {
        for (int start = 0; start < N; start += (len << 1)) {
            int32_t z = zetas[k_ref++];
            for (int j = start; j < start + len; j++) {
                t1 = montgomery_reduce((int64_t)z * ref[j + len]);
                ref[j + len] = ref[j] - t1;
                ref[j] = ref[j] + t1;
            }
        }
    }

    /* Radix2 upper: merged */
    {
        const int32x4_t vQ_ = vdupq_n_s32(Q);
        const int32x4_t vQINV_ = vdupq_n_s32(QINV);
        /* Call the actual merged function through ntt code */
        /* We can't call it directly, so let's do it manually */
        int len = N >> 2;
        while (len > redlen) {
            int len_inner = len >> 1;
            if (len_inner > redlen) {
                /* Merged 2-stage */
                int len_o = len, len_i = len_inner;
                int block = len_o << 1;
                int num_outer = N / block;
                int k_o = k_merged;
                int k_i = k_o + num_outer;

                for (int blk = 0; blk < N; blk += block) {
                    int32x4_t vZ_o  = vdupq_n_s32(zetas[k_o++]);
                    int32x4_t vZ_i0 = vdupq_n_s32(zetas[k_i++]);
                    int32x4_t vZ_i1 = vdupq_n_s32(zetas[k_i++]);
                    int j = blk, j_end = blk + len_i;

                    for (; j + 4 <= j_end; j += 4) {
                        int32x4_t va = vld1q_s32(&merged[j]);
                        int32x4_t vb = vld1q_s32(&merged[j + len_i]);
                        int32x4_t vc = vld1q_s32(&merged[j + len_o]);
                        int32x4_t vd = vld1q_s32(&merged[j + len_o + len_i]);

                        int32x4_t t1v = montgomery_mul4_sqdmulh(vc, vZ_o, vQ_, vQINV_);
                        int32x4_t t2v = montgomery_mul4_sqdmulh(vd, vZ_o, vQ_, vQINV_);
                        int32x4_t u0 = vaddq_s32(va, t1v);
                        int32x4_t v0 = vsubq_s32(va, t1v);
                        int32x4_t w0 = vaddq_s32(vb, t2v);
                        int32x4_t x0 = vsubq_s32(vb, t2v);

                        int32x4_t t3v = montgomery_mul4_sqdmulh(w0, vZ_i0, vQ_, vQINV_);
                        int32x4_t t4v = montgomery_mul4_sqdmulh(x0, vZ_i1, vQ_, vQINV_);

                        vst1q_s32(&merged[j],                vaddq_s32(u0, t3v));
                        vst1q_s32(&merged[j + len_i],        vsubq_s32(u0, t3v));
                        vst1q_s32(&merged[j + len_o],        vaddq_s32(v0, t4v));
                        vst1q_s32(&merged[j + len_o + len_i], vsubq_s32(v0, t4v));
                    }
                    for (; j < j_end; ++j) {
                        int32_t a = merged[j], b = merged[j+len_i];
                        int32_t c = merged[j+len_o], d = merged[j+len_o+len_i];
                        int z_o = zetas[k_o-1], z_i0v = zetas[k_i-2], z_i1v = zetas[k_i-1];
                        int32_t tt1 = montgomery_reduce((int64_t)z_o * c);
                        int32_t tt2 = montgomery_reduce((int64_t)z_o * d);
                        int32_t uu = a+tt1, vv = a-tt1, ww = b+tt2, xx = b-tt2;
                        int32_t tt3 = montgomery_reduce((int64_t)z_i0v * ww);
                        int32_t tt4 = montgomery_reduce((int64_t)z_i1v * xx);
                        merged[j] = uu+tt3;
                        merged[j+len_i] = uu-tt3;
                        merged[j+len_o] = vv+tt4;
                        merged[j+len_o+len_i] = vv-tt4;
                    }
                }
                k_merged = k_i;
                len >>= 2;
            } else {
                for (int start = 0; start < N; start += (len<<1)) {
                    int32_t z = zetas[k_merged++];
                    for (int j = start; j < start+len; j++) {
                        t1 = montgomery_reduce((int64_t)z * merged[j+len]);
                        merged[j+len] = merged[j] - t1;
                        merged[j] = merged[j] + t1;
                    }
                }
                len >>= 1;
            }
        }
    }

    printf("k_ref after upper: %d, k_merged after upper: %d\n", k_ref, k_merged);
    compare_arrays("After radix2_upper", merged, ref, N);

    /* Reduce32 */
    for (int i = 0; i < N; i++) {
        ref[i] = reduce32(ref[i]);
        merged[i] = reduce32(merged[i]);
    }
    compare_arrays("After reduce32", merged, ref, N);

    /* Radix2 lower: identical scalar for both */
#if NIMS_TRI_NTT_MODE == 3
    #define R3L 1
#else
    #define R3L 3
#endif
    for (int len = redlen; len >= 3*R3L; len >>= 1) {
        for (int start = 0; start < N; start += (len<<1)) {
            int32_t z_r = zetas[k_ref++];
            int32_t z_m = zetas[k_merged++];
            for (int j = start; j < start+len; j++) {
                t1 = montgomery_reduce((int64_t)z_r * ref[j+len]);
                ref[j+len] = ref[j] - t1;
                ref[j] = ref[j] + t1;
                t1 = montgomery_reduce((int64_t)z_m * merged[j+len]);
                merged[j+len] = merged[j] - t1;
                merged[j] = merged[j] + t1;
            }
        }
    }
    compare_arrays("After radix2_lower", merged, ref, N);

    printf("Final k_ref=%d, k_merged=%d\n", k_ref, k_merged);
    return 0;
}
