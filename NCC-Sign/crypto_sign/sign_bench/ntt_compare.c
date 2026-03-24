/*
 * NTT comparison test: compare NEON (merged) NTT/INTT output vs C reference.
 * Also measures rejection rate.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "sign.h"
#include "poly.h"
#include "reduce.h"
#include "randombytes.h"
#include "fips202.h"
#include "cpucycles.h"

/* Access to internal zetas/zetas_inv arrays */
extern int32_t zetas[];
extern int32_t zetas_inv[];

/* Reference scalar NTT (from the ntt() function in C reference path) */
static void ntt_ref(int32_t *Out, const int32_t *A) {
    int32_t t1;
    int len, start, j, k = 0;

    if (Out != A) memcpy(Out, A, sizeof(int32_t)*N);

    /* stage 0 */
    int32_t zeta1 = zetas[k++];
    for (j = 0; j < N/2; j++) {
        t1 = montgomery_reduce((int64_t)zeta1 * Out[j + N/2]);
        Out[j + N/2] = Out[j] + Out[j + N/2] - t1;
        Out[j] = Out[j] + t1;
    }

    /* radix-2 upper */
    for (len = N >> 2; len > (N >> 8); len >>= 1) {
        for (start = 0; start < N; start += (len << 1)) {
            zeta1 = zetas[k++];
            for (j = start; j < start + len; j++) {
                t1 = montgomery_reduce((int64_t)zeta1 * Out[j + len]);
                Out[j + len] = Out[j] - t1;
                Out[j] = Out[j] + t1;
            }
        }
    }

    /* reduce32 */
    for (j = 0; j < N; j++) {
        Out[j] = reduce32(Out[j]);
    }

    /* radix-2 lower */
#if NIMS_TRI_NTT_MODE == 3
    #define radix3_len_local 1
#else
    #define radix3_len_local 3
#endif
    for (len = (N >> 8); len >= 3 * radix3_len_local; len >>= 1) {
        for (start = 0; start < N; start += (len << 1)) {
            zeta1 = zetas[k++];
            for (j = start; j < start + len; j++) {
                t1 = montgomery_reduce((int64_t)zeta1 * Out[j + len]);
                Out[j + len] = Out[j] - t1;
                Out[j] = Out[j] + t1;
            }
        }
    }

    /* radix-3 (sign1/5 only) */
#if NIMS_TRI_NTT_MODE != 3
#if NIMS_TRI_NTT_MODE == 1
    #define WMONT_REF  1857311
    #define W2MONT_REF 4762337
#elif NIMS_TRI_NTT_MODE == 5
    #define WMONT_REF  6675549
    #define W2MONT_REF 1713571
#endif
    for (len = radix3_len_local; len >= 1; len = len / 3) {
        for (start = 0; start < N; start += 3 * len) {
            int32_t z1 = zetas[k++];
            int32_t z2 = zetas[k++];
            for (j = start; j < start + len; j++) {
                int32_t a0 = Out[j], a1 = Out[j+len], a2 = Out[j+2*len];
                t1 = montgomery_reduce((int64_t)z1 * a1);
                int32_t t2 = montgomery_reduce((int64_t)z2 * a2);
                int32_t t3 = montgomery_reduce((int64_t)WMONT_REF * t1);
                int32_t t4 = montgomery_reduce((int64_t)W2MONT_REF * t2);
                int32_t t12 = t1 + t2;
                int32_t t34 = t3 + t4;
                Out[j + 2*len] = a0 - (t12 + t34);
                Out[j + len] = a0 + t34;
                Out[j] = a0 + t12;
            }
        }
    }
#endif
}

/* Reference scalar INTT */
static void invntt_ref(int32_t *Out, const int32_t *A) {
    int32_t t1, t2;
    int len, start, j, k = 0;

    if (Out != A) memcpy(Out, A, sizeof(int32_t)*N);

#if NIMS_TRI_NTT_MODE != 3
    /* radix-3 inverse */
    for (len = 1; len <= radix3_len_local; len *= 3) {
        for (start = 0; start < N; start += 3*len) {
            int32_t z1 = zetas_inv[k++], z2 = zetas_inv[k++];
            for (j = start; j < start+len; j++) {
                int32_t a0=Out[j], a1=Out[j+len], a2=Out[j+2*len];
                t1 = montgomery_reduce((int64_t)W2MONT_REF*a1) + montgomery_reduce((int64_t)WMONT_REF*a2);
                t2 = a1 + a2;
                Out[j+2*len] = montgomery_reduce((int64_t)z2*(a0-(t1+t2)));
                Out[j+len]   = montgomery_reduce((int64_t)z1*(a0+t1));
                Out[j]       = a0+t2;
            }
        }
    }
#endif

    /* radix-2 lower (ascending) */
    for (len = 3*radix3_len_local; len < (N>>3); len <<= 1) {
        for (start = 0; start < N; start += (len<<1)) {
            int32_t z1 = zetas_inv[k++];
            for (j = start; j < start+len; j++) {
                t1 = Out[j]; t2 = Out[j+len];
                Out[j] = t1+t2;
                Out[j+len] = montgomery_reduce((int64_t)z1*(t1-t2));
            }
        }
    }

    /* reduce32 */
    for (j = 0; j < N; j++) Out[j] = reduce32(Out[j]);

    /* radix-2 upper (ascending) */
    for (len = (N>>3); len <= (N>>2); len <<= 1) {
        for (start = 0; start < N; start += (len<<1)) {
            int32_t z1 = zetas_inv[k++];
            for (j = start; j < start+len; j++) {
                t1 = Out[j]; t2 = Out[j+len];
                Out[j] = t1+t2;
                Out[j+len] = montgomery_reduce((int64_t)z1*(t1-t2));
            }
        }
    }

    /* final stage */
    {
        int32_t z1 = zetas_inv[k];
#if NIMS_TRI_NTT_MODE == 1
        int32_t f1=5143946, f2=1886355;
#elif NIMS_TRI_NTT_MODE == 3
        int32_t f1=2250740, f2=4501480;
#elif NIMS_TRI_NTT_MODE == 5
        int32_t f1=6642923, f2=4880853;
#endif
        for (j = 0; j < N/2; j++) {
            t1 = Out[j] + Out[j+N/2];
            t2 = montgomery_reduce((int64_t)z1*(Out[j]-Out[j+N/2]));
            Out[j]     = montgomery_reduce((int64_t)f1*(t1-t2));
            Out[j+N/2] = montgomery_reduce((int64_t)f2*t2);
        }
    }
}

int main(void) {
#if defined(__aarch64__)
    setup_rdtsc();
#endif

    poly a, ntt_neon, ntt_scalar, intt_neon, intt_scalar;

    printf("=== NTT/INTT Comparison Test for %s (N=%d) ===\n", CRYPTO_ALGNAME, N);

    /* Test with multiple random inputs */
    int ntt_mismatch_total = 0, intt_mismatch_total = 0;
    for (int trial = 0; trial < 100; trial++) {
        randombytes((uint8_t*)a.coeffs, sizeof(a.coeffs));
        for (int i = 0; i < N; i++) a.coeffs[i] = ((int32_t)a.coeffs[i]) % Q;

        /* Forward NTT comparison */
        ntt(ntt_neon.coeffs, a.coeffs);       /* NEON merged */
        ntt_ref(ntt_scalar.coeffs, a.coeffs); /* scalar reference */

        int ntt_mismatch = 0;
        for (int i = 0; i < N; i++) {
            int32_t diff = ntt_neon.coeffs[i] - ntt_scalar.coeffs[i];
            if (diff != 0) {
                if (ntt_mismatch < 5 && trial == 0) {
                    printf("  NTT mismatch at [%d]: neon=%d scalar=%d diff=%d\n",
                           i, ntt_neon.coeffs[i], ntt_scalar.coeffs[i], diff);
                }
                ntt_mismatch++;
            }
        }
        if (ntt_mismatch > 0) ntt_mismatch_total++;

        /* Inverse NTT comparison */
        invntt_tomont(intt_neon.coeffs, ntt_neon.coeffs);     /* NEON merged */
        invntt_ref(intt_scalar.coeffs, ntt_scalar.coeffs);    /* scalar reference */

        int intt_mismatch = 0;
        for (int i = 0; i < N; i++) {
            int32_t diff = intt_neon.coeffs[i] - intt_scalar.coeffs[i];
            if (diff != 0) {
                if (intt_mismatch < 5 && trial == 0) {
                    printf("  INTT mismatch at [%d]: neon=%d scalar=%d diff=%d\n",
                           i, intt_neon.coeffs[i], intt_scalar.coeffs[i], diff);
                }
                intt_mismatch++;
            }
        }
        if (intt_mismatch > 0) intt_mismatch_total++;
    }

    printf("NTT  mismatches: %d/100 trials\n", ntt_mismatch_total);
    printf("INTT mismatches: %d/100 trials\n", intt_mismatch_total);

    /* Rejection rate measurement */
    printf("\n=== Rejection Rate Measurement (1000 Sign calls) ===\n");

    uint8_t pk[NCC_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[NCC_CRYPTO_SECRETKEYBYTES];
    uint8_t m[24], sm[24 + NCC_CRYPTO_BYTES];
    size_t smlen;

    crypto_sign_keypair(pk, sk);
    randombytes(m, 24);

    /* We need to count rejections. Since we can't easily instrument sign.c,
       we measure total cycles per sign as a proxy — if rejection rate is higher,
       average cycles will be proportionally higher. */
    uint64_t total_cycles = 0;
    for (int i = 0; i < 1000; i++) {
        for (int j = 0; j < 24; j++)
            sm[NCC_CRYPTO_BYTES + 24 - 1 - j] = m[24 - 1 - j];
        uint64_t t0 = cpucycles();
        crypto_sign_signature(sm, &smlen, sm + NCC_CRYPTO_BYTES, 24, sk);
        uint64_t t1 = cpucycles();
        total_cycles += t1 - t0;
    }
    printf("Average Sign cycles: %llu\n", (unsigned long long)(total_cycles / 1000));

    printf("\n=== Done ===\n");
    return 0;
}
