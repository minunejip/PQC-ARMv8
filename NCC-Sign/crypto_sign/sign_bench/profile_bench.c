/*
 * NCC-Sign Profiling Harness
 * Measures per-category cycle counts for KeyGen, Sign, and Verify.
 *
 * Categories:
 *   0: NTT (forward)
 *   1: INTT (inverse NTT)
 *   2: Pointwise / Montgomery multiplication (poly_base_mul, poly_add, poly_sub, etc.)
 *   3: Sampling (poly_uniform, poly_uniform_eta, poly_uniform_gamma1, poly_challenge)
 *   4: Hashing / SHAKE (shake256, shake256_inc_*)
 *   5: Packing / Encoding / Decoding (pack/unpack, polyw1_pack, etc.)
 *   6: Other (rounding, decompose, hint, chknorm, randombytes, etc.)
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "sign.h"
#include "packing.h"
#include "poly.h"
#include "reduce.h"
#include "rounding.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"
#include "cpucycles.h"

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */
#define PROFILE_LOOPS  1000
#define MLEN           24

#define NUM_CATEGORIES 7
static const char *cat_names[NUM_CATEGORIES] = {
    "NTT (forward)",
    "INTT (inverse)",
    "Pointwise/Mont",
    "Sampling",
    "Hashing/SHAKE",
    "Packing/Enc/Dec",
    "Other"
};

enum {
    CAT_NTT      = 0,
    CAT_INTT     = 1,
    CAT_POINTWISE = 2,
    CAT_SAMPLING = 3,
    CAT_HASHING  = 4,
    CAT_PACKING  = 5,
    CAT_OTHER    = 6
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
static int cmp_uint64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return  1;
    return 0;
}

static uint64_t median(uint64_t *arr, int n) {
    qsort(arr, n, sizeof(uint64_t), cmp_uint64);
    if (n % 2 == 1) return arr[n / 2];
    return (arr[n / 2 - 1] + arr[n / 2]) / 2;
}

/* Calibrate cpucycles overhead */
static uint64_t calibrate_overhead(void) {
    uint64_t samples[1001];
    for (int i = 0; i < 1001; i++) {
        uint64_t t0 = cpucycles();
        uint64_t t1 = cpucycles();
        samples[i] = t1 - t0;
    }
    return median(samples, 1001);
}

/* ------------------------------------------------------------------ */
/* Macro helpers for cycle measurement                                 */
/* ------------------------------------------------------------------ */
#define CYCLE_START() do { _t0 = cpucycles(); } while(0)
#define CYCLE_END(cat) do { _t1 = cpucycles(); cats[cat] += (_t1 - _t0); } while(0)

/* ------------------------------------------------------------------ */
/* Profiled KeyGen                                                     */
/* ------------------------------------------------------------------ */
static void profile_keygen(uint8_t *pk, uint8_t *sk, uint64_t cats[NUM_CATEGORIES]) {
    uint64_t _t0, _t1;
    uint8_t zeta[SEEDBYTES];
    uint8_t seedbuf[3 * SEEDBYTES];
    uint8_t tr[SEEDBYTES];
    const uint8_t *xi_1, *xi_2, *key;
    poly mat, s1, s1hat, s2, t1, t0;

    memset(cats, 0, sizeof(uint64_t) * NUM_CATEGORIES);

    /* randombytes + seed expansion */
    CYCLE_START();
    randombytes(zeta, SEEDBYTES);
    randombytes(seedbuf, SEEDBYTES);
    CYCLE_END(CAT_OTHER);

    CYCLE_START();
    shake256(seedbuf, 3 * SEEDBYTES, seedbuf, SEEDBYTES);
    CYCLE_END(CAT_HASHING);

    xi_1 = seedbuf;
    xi_2 = seedbuf + SEEDBYTES;
    key  = seedbuf + 2 * SEEDBYTES;

    /* Sampling: ExpandA, sample s1, s2 */
    CYCLE_START();
    poly_uniform(&mat, zeta, 0);
    CYCLE_END(CAT_SAMPLING);

    CYCLE_START();
#ifdef HAS_POLY_UNIFORM_ETA_X2
    poly_uniform_eta_x2(&s1, &s2, xi_1, xi_2, 0, 0);
#else
    poly_uniform_eta(&s1, xi_1, 0);
    poly_uniform_eta(&s2, xi_2, 0);
#endif
    CYCLE_END(CAT_SAMPLING);

    /* NTT */
    CYCLE_START();
    ntt(s1hat.coeffs, s1.coeffs);
    CYCLE_END(CAT_NTT);

    /* Pointwise multiplication */
    CYCLE_START();
    poly_base_mul(&t1, &s1hat, &mat);
    CYCLE_END(CAT_POINTWISE);

    /* INTT */
    CYCLE_START();
    invntt_tomont(t1.coeffs, t1.coeffs);
    CYCLE_END(CAT_INTT);

    /* Pointwise: caddq, add, caddq */
    CYCLE_START();
    poly_caddq(&t1);
    poly_add(&t1, &t1, &s2);
    poly_caddq(&t1);
    CYCLE_END(CAT_POINTWISE);

    /* Other: power2round */
    CYCLE_START();
    poly_power2round(&t1, &t0, &t1);
    CYCLE_END(CAT_OTHER);

    /* Packing: pack_pk */
    CYCLE_START();
    pack_pk(pk, zeta, &t1);
    CYCLE_END(CAT_PACKING);

    /* Hashing: compute tr */
    CYCLE_START();
    shake256(tr, SEEDBYTES, pk, NCC_CRYPTO_PUBLICKEYBYTES);
    CYCLE_END(CAT_HASHING);

    /* Packing: pack_sk */
    CYCLE_START();
    pack_sk(sk, zeta, tr, key, &t0, &s1, &s2);
    CYCLE_END(CAT_PACKING);
}

/* ------------------------------------------------------------------ */
/* Profiled Sign                                                       */
/* ------------------------------------------------------------------ */
static void profile_sign(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk,
                          uint64_t cats[NUM_CATEGORIES]) {
    uint64_t _t0, _t1;
    unsigned int n;
    uint8_t seedbuf[3 * SEEDBYTES + 2 * CRHBYTES];
    uint8_t *zeta, *tr, *key, *mu, *rho;
    uint16_t nonce = 0;
    poly mat, s1, y, z, t0, s2, w1, w0, h, cp;
    shake256incctx state;

    memset(cats, 0, sizeof(uint64_t) * NUM_CATEGORIES);

    zeta = seedbuf;
    tr   = zeta + SEEDBYTES;
    key  = tr + SEEDBYTES;
    mu   = key + SEEDBYTES;
    rho  = mu + CRHBYTES;

    /* Packing: unpack_sk */
    CYCLE_START();
    unpack_sk(zeta, tr, key, &t0, &s1, &s2, sk);
    CYCLE_END(CAT_PACKING);

    /* Hashing: hash(tr || m) -> mu */
    CYCLE_START();
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    CYCLE_END(CAT_HASHING);

    /* Hashing: derive rho */
    CYCLE_START();
#ifdef NIMS_RANDOMIZED_SIGNING
    randombytes(rho, CRHBYTES);
#else
    shake256(rho, CRHBYTES, key, SEEDBYTES + CRHBYTES);
#endif
    CYCLE_END(CAT_HASHING);

    /* Sampling: ExpandA */
    CYCLE_START();
    poly_uniform(&mat, zeta, 0);
    CYCLE_END(CAT_SAMPLING);

    /* NTT: transform secrets */
    CYCLE_START();
    ntt(s1.coeffs, s1.coeffs);
    ntt(s2.coeffs, s2.coeffs);
    ntt(t0.coeffs, t0.coeffs);
    CYCLE_END(CAT_NTT);

    /* Rejection loop */
rej:
    /* Sampling: sample y */
    CYCLE_START();
    poly_uniform_gamma1(&y, rho, nonce++);
    CYCLE_END(CAT_SAMPLING);

    z = y;

    /* NTT: forward on z */
    CYCLE_START();
    ntt(z.coeffs, z.coeffs);
    CYCLE_END(CAT_NTT);

    /* Pointwise: A*z */
    CYCLE_START();
    poly_base_mul(&w1, &z, &mat);
    CYCLE_END(CAT_POINTWISE);

    /* INTT: w1 */
    CYCLE_START();
    invntt_tomont(w1.coeffs, w1.coeffs);
    CYCLE_END(CAT_INTT);

    /* Pointwise: caddq */
    CYCLE_START();
    poly_caddq(&w1);
    CYCLE_END(CAT_POINTWISE);

    /* Other: decompose */
    CYCLE_START();
    poly_decompose(&w1, &w0, &w1);
    CYCLE_END(CAT_OTHER);

    /* Packing: polyw1_pack */
    CYCLE_START();
    polyw1_pack(sig, &w1);
    CYCLE_END(CAT_PACKING);

    /* Hashing: hash(mu || w1) -> challenge seed */
    CYCLE_START();
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, SEEDBYTES, &state);
    CYCLE_END(CAT_HASHING);

    /* Sampling: poly_challenge */
    CYCLE_START();
    poly_challenge(&cp, sig);
    CYCLE_END(CAT_SAMPLING);

    /* NTT: challenge polynomial */
    CYCLE_START();
    ntt(cp.coeffs, cp.coeffs);
    CYCLE_END(CAT_NTT);

    /* Pointwise: c*s1 */
    CYCLE_START();
    poly_base_mul(&z, &cp, &s1);
    CYCLE_END(CAT_POINTWISE);

    /* INTT: z */
    CYCLE_START();
    invntt_tomont(z.coeffs, z.coeffs);
    CYCLE_END(CAT_INTT);

    /* Pointwise: caddq, add, reduce */
    CYCLE_START();
    poly_caddq(&z);
    poly_add(&z, &z, &y);
    poly_reduce(&z);
    CYCLE_END(CAT_POINTWISE);

    /* Other: chknorm */
    CYCLE_START();
    if (poly_chknorm(&z, GAMMA1 - BETA)) {
        CYCLE_END(CAT_OTHER);
        goto rej;
    }
    CYCLE_END(CAT_OTHER);

    /* Pointwise: c*s2 */
    CYCLE_START();
    poly_base_mul(&h, &cp, &s2);
    CYCLE_END(CAT_POINTWISE);

    /* INTT: h */
    CYCLE_START();
    invntt_tomont(h.coeffs, h.coeffs);
    CYCLE_END(CAT_INTT);

    /* Pointwise: caddq, sub, reduce */
    CYCLE_START();
    poly_caddq(&h);
    poly_sub(&w0, &w0, &h);
    poly_reduce(&w0);
    CYCLE_END(CAT_POINTWISE);

    /* Other: chknorm */
    CYCLE_START();
    if (poly_chknorm(&w0, GAMMA2 - BETA)) {
        CYCLE_END(CAT_OTHER);
        goto rej;
    }
    CYCLE_END(CAT_OTHER);

    /* Pointwise: c*t0 */
    CYCLE_START();
    poly_base_mul(&h, &cp, &t0);
    CYCLE_END(CAT_POINTWISE);

    /* INTT: h */
    CYCLE_START();
    invntt_tomont(h.coeffs, h.coeffs);
    CYCLE_END(CAT_INTT);

    /* Pointwise: caddq, reduce */
    CYCLE_START();
    poly_caddq(&h);
    poly_reduce(&h);
    CYCLE_END(CAT_POINTWISE);

    /* Other: chknorm */
    CYCLE_START();
    if (poly_chknorm(&h, GAMMA2)) {
        CYCLE_END(CAT_OTHER);
        goto rej;
    }
    CYCLE_END(CAT_OTHER);

    /* Pointwise: add */
    CYCLE_START();
    poly_add(&w0, &w0, &h);
    CYCLE_END(CAT_POINTWISE);

    /* Other: make_hint */
    CYCLE_START();
    n = poly_make_hint(&h, &w0, &w1);
    CYCLE_END(CAT_OTHER);

    if (n > OMEGA)
        goto rej;

    /* Packing: pack_sig */
    CYCLE_START();
    pack_sig(sig, sig, &z, &h);
    CYCLE_END(CAT_PACKING);

    *siglen = NCC_CRYPTO_BYTES;
}

/* ------------------------------------------------------------------ */
/* Profiled Verify                                                     */
/* ------------------------------------------------------------------ */
static int profile_verify(const uint8_t *sig, size_t siglen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *pk,
                           uint64_t cats[NUM_CATEGORIES]) {
    uint64_t _t0, _t1;
    unsigned int i;
    uint8_t buf[POLYW1_PACKEDBYTES];
    uint8_t zeta[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[SEEDBYTES];
    uint8_t c2[SEEDBYTES];
    poly cp, mat, z, t1, t11, w1, h;
    shake256incctx state;

    memset(cats, 0, sizeof(uint64_t) * NUM_CATEGORIES);

    if (siglen != NCC_CRYPTO_BYTES)
        return -1;

    /* Packing: unpack_pk */
    CYCLE_START();
    unpack_pk(zeta, &t1, pk);
    CYCLE_END(CAT_PACKING);

    /* Packing: unpack_sig */
    CYCLE_START();
    if (unpack_sig(c, &z, &h, sig)) {
        CYCLE_END(CAT_PACKING);
        return -1;
    }
    CYCLE_END(CAT_PACKING);

    /* Other: chknorm */
    CYCLE_START();
    if (poly_chknorm(&z, GAMMA1 - BETA)) {
        CYCLE_END(CAT_OTHER);
        return -1;
    }
    CYCLE_END(CAT_OTHER);

    /* Hashing: hash pk, then hash(mu || m) */
    CYCLE_START();
    shake256(mu, SEEDBYTES, pk, NCC_CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    CYCLE_END(CAT_HASHING);

    /* Sampling: poly_challenge */
    CYCLE_START();
    poly_challenge(&cp, c);
    CYCLE_END(CAT_SAMPLING);

    /* Sampling: ExpandA */
    CYCLE_START();
    poly_uniform(&mat, zeta, 0);
    CYCLE_END(CAT_SAMPLING);

    /* NTT: z */
    CYCLE_START();
    ntt(z.coeffs, z.coeffs);
    CYCLE_END(CAT_NTT);

    /* Pointwise: A*z */
    CYCLE_START();
    poly_base_mul(&w1, &z, &mat);
    CYCLE_END(CAT_POINTWISE);

    /* INTT: w1 = A*z */
    CYCLE_START();
    invntt_tomont(w1.coeffs, w1.coeffs);
    CYCLE_END(CAT_INTT);

    /* Pointwise: caddq */
    CYCLE_START();
    poly_caddq(&w1);
    CYCLE_END(CAT_POINTWISE);

    /* Other: shiftl */
    CYCLE_START();
    poly_shiftl(&t1);
    CYCLE_END(CAT_OTHER);

    /* NTT: t1, cp */
    CYCLE_START();
    ntt(t11.coeffs, t1.coeffs);
    ntt(cp.coeffs, cp.coeffs);
    CYCLE_END(CAT_NTT);

    /* Pointwise: c*t1 */
    CYCLE_START();
    poly_base_mul(&t1, &cp, &t11);
    CYCLE_END(CAT_POINTWISE);

    /* INTT: c*t1 */
    CYCLE_START();
    invntt_tomont(t1.coeffs, t1.coeffs);
    CYCLE_END(CAT_INTT);

    /* Pointwise: caddq, sub, caddq */
    CYCLE_START();
    poly_caddq(&t1);
    poly_sub(&w1, &w1, &t1);
    poly_caddq(&w1);
    CYCLE_END(CAT_POINTWISE);

    /* Other: use_hint */
    CYCLE_START();
    poly_use_hint(&w1, &w1, &h);
    CYCLE_END(CAT_OTHER);

    /* Packing: polyw1_pack */
    CYCLE_START();
    polyw1_pack(buf, &w1);
    CYCLE_END(CAT_PACKING);

    /* Hashing: hash(mu || w1) -> c2 */
    CYCLE_START();
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf, POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, SEEDBYTES, &state);
    CYCLE_END(CAT_HASHING);

    /* Other: compare */
    CYCLE_START();
    for (i = 0; i < SEEDBYTES; ++i)
        if (c[i] != c2[i]) {
            CYCLE_END(CAT_OTHER);
            return -1;
        }
    CYCLE_END(CAT_OTHER);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Print results                                                       */
/* ------------------------------------------------------------------ */
static void print_results(const char *op_name,
                           uint64_t cat_medians[NUM_CATEGORIES],
                           uint64_t total_median,
                           uint64_t overhead) {
    printf("\n  %-8s  Total median: %10llu cycles (overhead/call: ~%llu)\n",
           op_name, (unsigned long long)total_median, (unsigned long long)overhead);
    printf("  %-8s  %-20s %12s %8s\n", "", "Category", "Cycles", "Ratio");
    printf("  %-8s  %-20s %12s %8s\n", "", "--------------------", "------------", "--------");

    uint64_t cat_sum = 0;
    for (int c = 0; c < NUM_CATEGORIES; c++)
        cat_sum += cat_medians[c];

    for (int c = 0; c < NUM_CATEGORIES; c++) {
        double pct = (cat_sum > 0) ? 100.0 * cat_medians[c] / cat_sum : 0.0;
        printf("  %-8s  %-20s %12llu %7.2f%%\n",
               "", cat_names[c],
               (unsigned long long)cat_medians[c], pct);
    }
    printf("  %-8s  %-20s %12llu %7.2f%%\n",
           "", "SUM(categories)",
           (unsigned long long)cat_sum, 100.0);
    printf("  %-8s  %-20s %12llu\n",
           "", "End-to-end median",
           (unsigned long long)total_median);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */
int main(void) {
#if defined(__aarch64__)
    setup_rdtsc();
#endif

    uint8_t pk[NCC_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[NCC_CRYPTO_SECRETKEYBYTES];
    uint8_t m[MLEN];
    uint8_t sm[MLEN + NCC_CRYPTO_BYTES];
    size_t smlen;

    randombytes(m, MLEN);

    /* ---- Calibration ---- */
    uint64_t overhead = calibrate_overhead();

    printf("================================================================\n");
    printf("  NCC-Sign Profiling Benchmark\n");
    printf("  Algorithm:   %s\n", CRYPTO_ALGNAME);
    printf("  N=%d, Q=%d\n", N, Q);
    printf("  PK bytes:    %d\n", NCC_CRYPTO_PUBLICKEYBYTES);
    printf("  SK bytes:    %d\n", NCC_CRYPTO_SECRETKEYBYTES);
    printf("  Sig bytes:   %d\n", NCC_CRYPTO_BYTES);
    printf("  Iterations:  %d\n", PROFILE_LOOPS);
    printf("  cpucycles overhead: %llu cycles/call\n", (unsigned long long)overhead);
    printf("================================================================\n");

    /* Storage for per-iteration results */
    uint64_t total_cycles[PROFILE_LOOPS];
    uint64_t cat_cycles[PROFILE_LOOPS][NUM_CATEGORIES];

    /* ============================================================== */
    /* KeyGen Profiling                                                */
    /* ============================================================== */
    printf("\n>>> KeyGen Profiling\n");
    for (int i = 0; i < PROFILE_LOOPS; i++) {
        uint64_t cats[NUM_CATEGORIES];
        uint64_t t0 = cpucycles();
        profile_keygen(pk, sk, cats);
        uint64_t t1 = cpucycles();
        total_cycles[i] = t1 - t0;
        for (int c = 0; c < NUM_CATEGORIES; c++)
            cat_cycles[i][c] = cats[c];
    }
    {
        uint64_t total_med = median(total_cycles, PROFILE_LOOPS);
        uint64_t cat_med[NUM_CATEGORIES];
        uint64_t tmp[PROFILE_LOOPS];
        for (int c = 0; c < NUM_CATEGORIES; c++) {
            for (int i = 0; i < PROFILE_LOOPS; i++)
                tmp[i] = cat_cycles[i][c];
            cat_med[c] = median(tmp, PROFILE_LOOPS);
        }
        print_results("KeyGen", cat_med, total_med, overhead);
    }

    /* Generate a valid keypair for Sign/Verify */
    crypto_sign_keypair(pk, sk);

    /* ============================================================== */
    /* Sign Profiling                                                  */
    /* ============================================================== */
    printf("\n>>> Sign Profiling\n");
    for (int i = 0; i < PROFILE_LOOPS; i++) {
        uint64_t cats[NUM_CATEGORIES];
        /* Prepare sm buffer: copy message to end */
        for (size_t j = 0; j < MLEN; j++)
            sm[NCC_CRYPTO_BYTES + MLEN - 1 - j] = m[MLEN - 1 - j];
        uint64_t t0 = cpucycles();
        profile_sign(sm, &smlen, sm + NCC_CRYPTO_BYTES, MLEN, sk, cats);
        uint64_t t1 = cpucycles();
        total_cycles[i] = t1 - t0;
        smlen += MLEN;
        for (int c = 0; c < NUM_CATEGORIES; c++)
            cat_cycles[i][c] = cats[c];
    }
    {
        uint64_t total_med = median(total_cycles, PROFILE_LOOPS);
        uint64_t cat_med[NUM_CATEGORIES];
        uint64_t tmp[PROFILE_LOOPS];
        for (int c = 0; c < NUM_CATEGORIES; c++) {
            for (int i = 0; i < PROFILE_LOOPS; i++)
                tmp[i] = cat_cycles[i][c];
            cat_med[c] = median(tmp, PROFILE_LOOPS);
        }
        print_results("Sign", cat_med, total_med, overhead);
    }

    /* Generate a valid signature for Verify profiling */
    for (size_t j = 0; j < MLEN; j++)
        sm[NCC_CRYPTO_BYTES + MLEN - 1 - j] = m[MLEN - 1 - j];
    crypto_sign_signature(sm, &smlen, sm + NCC_CRYPTO_BYTES, MLEN, sk);
    smlen += MLEN;

    /* ============================================================== */
    /* Verify Profiling                                                */
    /* ============================================================== */
    printf("\n>>> Verify Profiling\n");
    for (int i = 0; i < PROFILE_LOOPS; i++) {
        uint64_t cats[NUM_CATEGORIES];
        uint64_t t0 = cpucycles();
        int ret = profile_verify(sm, NCC_CRYPTO_BYTES,
                                  sm + NCC_CRYPTO_BYTES, smlen - NCC_CRYPTO_BYTES,
                                  pk, cats);
        uint64_t t1 = cpucycles();
        if (ret != 0) {
            printf("  WARNING: Verify failed at iteration %d\n", i);
        }
        total_cycles[i] = t1 - t0;
        for (int c = 0; c < NUM_CATEGORIES; c++)
            cat_cycles[i][c] = cats[c];
    }
    {
        uint64_t total_med = median(total_cycles, PROFILE_LOOPS);
        uint64_t cat_med[NUM_CATEGORIES];
        uint64_t tmp[PROFILE_LOOPS];
        for (int c = 0; c < NUM_CATEGORIES; c++) {
            for (int i = 0; i < PROFILE_LOOPS; i++)
                tmp[i] = cat_cycles[i][c];
            cat_med[c] = median(tmp, PROFILE_LOOPS);
        }
        print_results("Verify", cat_med, total_med, overhead);
    }

    printf("\n================================================================\n");
    printf("  Profiling complete.\n");
    printf("================================================================\n");

    return 0;
}
