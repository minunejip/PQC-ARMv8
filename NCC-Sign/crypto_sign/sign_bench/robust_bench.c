/*
 * Robust NCC-Sign Benchmark
 *
 * Method A: Per-attempt cost — measures a single rejection-loop iteration
 *           (y sampling → NTT → challenge → z computation → rejection check)
 *           Eliminates rejection-count variance entirely.
 *
 * Method B: Full signing cost with proper statistics
 *           Reports: median, mean, std, P5, P95, plus rejection rate.
 *
 * KeyGen/Verify: deterministic, standard statistics reported.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

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
#define SIGN_LOOPS   10000
#define KG_VF_LOOPS  10000
#define MLEN         24

/* Max attempts we can record per signing call */
#define MAX_ATTEMPTS_PER_SIGN 64

/* ------------------------------------------------------------------ */
/* Statistics helpers                                                   */
/* ------------------------------------------------------------------ */
static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

typedef struct {
    uint64_t median;
    double   mean;
    double   std;
    uint64_t p5, p95;
    uint64_t min, max;
    int      n;
} stats_t;

static stats_t compute_stats(uint64_t *arr, int n) {
    stats_t s;
    s.n = n;
    qsort(arr, n, sizeof(uint64_t), cmp_u64);
    s.median = arr[n / 2];
    s.p5     = arr[n * 5 / 100];
    s.p95    = arr[n * 95 / 100];
    s.min    = arr[0];
    s.max    = arr[n - 1];

    double sum = 0;
    for (int i = 0; i < n; i++) sum += (double)arr[i];
    s.mean = sum / n;

    double var = 0;
    for (int i = 0; i < n; i++) {
        double d = (double)arr[i] - s.mean;
        var += d * d;
    }
    s.std = sqrt(var / (n - 1));
    return s;
}

static void print_stats(const char *label, stats_t *s) {
    printf("  %-8s  n=%-6d  median=%10llu  mean=%10.0f  std=%8.0f  "
           "P5=%10llu  P95=%10llu  [%llu, %llu]\n",
           label, s->n,
           (unsigned long long)s->median, s->mean, s->std,
           (unsigned long long)s->p5, (unsigned long long)s->p95,
           (unsigned long long)s->min, (unsigned long long)s->max);
}

/* ------------------------------------------------------------------ */
/* Method A: Per-attempt signing cost                                  */
/* Replicates sign.c logic with per-attempt cycle measurement.         */
/* Does NOT modify original sign.c.                                    */
/* ------------------------------------------------------------------ */
#define NTT_MODE 1  /* NTT=1 always for optimized builds */

typedef struct {
    int      total_attempts;
    int      total_signs;
    uint64_t setup_cycles;       /* unpack + hash + expandA + NTT(secrets) */
} attempt_ctx_t;

static int sign_with_attempt_measurement(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen,
    const uint8_t *sk,
    uint64_t *attempt_cycles,   /* out: per-attempt cycle array */
    int *num_attempts,          /* out: how many attempts this call */
    uint64_t *setup_cost)       /* out: one-time setup cost */
{
    unsigned int n;
    uint8_t seedbuf[3 * SEEDBYTES + 2 * CRHBYTES];
    uint8_t *zeta, *tr, *key, *mu, *rho;
    uint16_t nonce = 0;
    poly mat, s1, y, z, t0, s2, w1, w0, h, cp;
    shake256incctx state;
    uint64_t t_start, t_end;
    int att = 0;

    /* === Setup phase (measured once per sign call) === */
    t_start = cpucycles();

    zeta = seedbuf;
    tr = zeta + SEEDBYTES;
    key = tr + SEEDBYTES;
    mu = key + SEEDBYTES;
    rho = mu + CRHBYTES;
    unpack_sk(zeta, tr, key, &t0, &s1, &s2, sk);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);

#ifdef NIMS_RANDOMIZED_SIGNING
    randombytes(rho, CRHBYTES);
#else
    shake256(rho, CRHBYTES, key, SEEDBYTES + CRHBYTES);
#endif

    poly_uniform(&mat, zeta, 0);

    ntt(s1.coeffs, s1.coeffs);
    ntt(s2.coeffs, s2.coeffs);
    ntt(t0.coeffs, t0.coeffs);

    t_end = cpucycles();
    *setup_cost = t_end - t_start;

    /* === Rejection loop (each attempt measured individually) === */
rej:
    t_start = cpucycles();

    poly_uniform_gamma1(&y, rho, nonce++);
    z = y;

    ntt(z.coeffs, z.coeffs);
    poly_base_mul(&w1, &z, &mat);
    invntt_tomont(w1.coeffs, w1.coeffs);
    poly_caddq(&w1);

    poly_decompose(&w1, &w0, &w1);
    polyw1_pack(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, SEEDBYTES, &state);
    poly_challenge(&cp, sig);

    ntt(cp.coeffs, cp.coeffs);
    poly_base_mul(&z, &cp, &s1);
    invntt_tomont(z.coeffs, z.coeffs);
    poly_caddq(&z);

    poly_add(&z, &z, &y);
    poly_reduce(&z);
    if (poly_chknorm(&z, GAMMA1 - BETA)) {
        t_end = cpucycles();
        if (att < MAX_ATTEMPTS_PER_SIGN)
            attempt_cycles[att++] = t_end - t_start;
        goto rej;
    }

    poly_base_mul(&h, &cp, &s2);
    invntt_tomont(h.coeffs, h.coeffs);
    poly_caddq(&h);

    poly_sub(&w0, &w0, &h);
    poly_reduce(&w0);

    if (poly_chknorm(&w0, GAMMA2 - BETA)) {
        t_end = cpucycles();
        if (att < MAX_ATTEMPTS_PER_SIGN)
            attempt_cycles[att++] = t_end - t_start;
        goto rej;
    }

    poly_base_mul(&h, &cp, &t0);
    invntt_tomont(h.coeffs, h.coeffs);
    poly_caddq(&h);

    poly_reduce(&h);
    if (poly_chknorm(&h, GAMMA2)) {
        t_end = cpucycles();
        if (att < MAX_ATTEMPTS_PER_SIGN)
            attempt_cycles[att++] = t_end - t_start;
        goto rej;
    }

    poly_add(&w0, &w0, &h);
    n = poly_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {
        t_end = cpucycles();
        if (att < MAX_ATTEMPTS_PER_SIGN)
            attempt_cycles[att++] = t_end - t_start;
        goto rej;
    }

    /* Final (successful) attempt */
    t_end = cpucycles();
    if (att < MAX_ATTEMPTS_PER_SIGN)
        attempt_cycles[att++] = t_end - t_start;

    pack_sig(sig, sig, &z, &h);
    *siglen = NCC_CRYPTO_BYTES;
    *num_attempts = att;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main benchmark                                                      */
/* ------------------------------------------------------------------ */
int main(void) {
#if defined(__aarch64__)
    setup_rdtsc();
#endif

    uint8_t pk[NCC_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[NCC_CRYPTO_SECRETKEYBYTES];
    uint8_t m[MLEN];
    uint8_t sm[MLEN + NCC_CRYPTO_BYTES];
    uint8_t m2[MLEN + NCC_CRYPTO_BYTES];
    size_t smlen, mlen2;

    randombytes(m, MLEN);

    /* Calibrate */
    uint64_t overhead_samples[201];
    for (int i = 0; i < 201; i++) {
        uint64_t t0 = cpucycles();
        uint64_t t1 = cpucycles();
        overhead_samples[i] = t1 - t0;
    }
    qsort(overhead_samples, 201, sizeof(uint64_t), cmp_u64);
    uint64_t overhead = overhead_samples[100];

    printf("================================================================\n");
    printf("  NCC-Sign Robust Benchmark\n");
    printf("  Algorithm:    %s\n", CRYPTO_ALGNAME);
    printf("  N=%d, Q=%d\n", N, Q);
    printf("  Iterations:   %d (KeyGen/Verify), %d (Sign)\n", KG_VF_LOOPS, SIGN_LOOPS);
    printf("  cpucycles overhead: %llu cycles/call\n", (unsigned long long)overhead);
    printf("================================================================\n");

    /* ============================================================== */
    /* KeyGen Benchmark                                                */
    /* ============================================================== */
    {
        uint64_t *cycles = malloc(KG_VF_LOOPS * sizeof(uint64_t));
        for (int i = 0; i < KG_VF_LOOPS; i++) {
            uint64_t t0 = cpucycles();
            crypto_sign_keypair(pk, sk);
            uint64_t t1 = cpucycles();
            cycles[i] = t1 - t0;
        }
        stats_t s = compute_stats(cycles, KG_VF_LOOPS);
        printf("\n>>> KeyGen\n");
        print_stats("KeyGen", &s);
        free(cycles);
    }

    /* Generate a fixed keypair for Sign/Verify */
    crypto_sign_keypair(pk, sk);

    /* ============================================================== */
    /* Sign Benchmark — Method A (per-attempt) + Method B (full) +    */
    /*                   Rejection rate                                */
    /* ============================================================== */
    {
        /* Storage for Method B: full sign cycles */
        uint64_t *sign_full = malloc(SIGN_LOOPS * sizeof(uint64_t));

        /* Storage for Method A: all attempt cycles (across all sign calls) */
        /* Worst case: SIGN_LOOPS * MAX_ATTEMPTS_PER_SIGN attempts */
        uint64_t *all_attempts = malloc(SIGN_LOOPS * MAX_ATTEMPTS_PER_SIGN * sizeof(uint64_t));
        uint64_t *setup_costs  = malloc(SIGN_LOOPS * sizeof(uint64_t));
        int total_attempts = 0;
        int total_rejections = 0;

        for (int i = 0; i < SIGN_LOOPS; i++) {
            uint64_t attempt_buf[MAX_ATTEMPTS_PER_SIGN];
            int num_att = 0;
            uint64_t setup_cost = 0;

            /* Prepare sm buffer (same as crypto_sign) */
            for (int j = 0; j < MLEN; j++)
                sm[NCC_CRYPTO_BYTES + MLEN - 1 - j] = m[MLEN - 1 - j];

            uint64_t t0 = cpucycles();
            sign_with_attempt_measurement(sm, &smlen, sm + NCC_CRYPTO_BYTES, MLEN, sk,
                                          attempt_buf, &num_att, &setup_cost);
            uint64_t t1 = cpucycles();
            smlen += MLEN;

            sign_full[i] = t1 - t0;
            setup_costs[i] = setup_cost;

            /* Verify correctness */
            int ret = crypto_sign_open(m2, &mlen2, sm, smlen, pk);
            if (ret != 0) {
                printf("  *** VERIFY FAILED at iteration %d ***\n", i);
            }

            /* Collect per-attempt data */
            for (int a = 0; a < num_att; a++) {
                all_attempts[total_attempts++] = attempt_buf[a];
            }
            total_rejections += (num_att - 1); /* last attempt succeeded */
        }

        /* Method A: per-attempt statistics */
        stats_t att_stats = compute_stats(all_attempts, total_attempts);
        printf("\n>>> Sign — Method A: Per-Attempt Cost\n");
        print_stats("Attempt", &att_stats);
        printf("  Total attempts: %d across %d sign calls\n", total_attempts, SIGN_LOOPS);
        printf("  Avg attempts/sign: %.3f\n", (double)total_attempts / SIGN_LOOPS);
        printf("  Rejection rate: %.3f (rejections/sign)\n",
               (double)total_rejections / SIGN_LOOPS);

        /* Setup cost statistics */
        stats_t setup_stats = compute_stats(setup_costs, SIGN_LOOPS);
        printf("\n>>> Sign — Setup Cost (one-time per sign call)\n");
        print_stats("Setup", &setup_stats);

        /* Method B: full sign statistics */
        stats_t full_stats = compute_stats(sign_full, SIGN_LOOPS);
        printf("\n>>> Sign — Method B: Full Signing Cost\n");
        print_stats("Sign", &full_stats);
        printf("  95%% CI for mean: [%.0f, %.0f]\n",
               full_stats.mean - 1.96 * full_stats.std / sqrt(SIGN_LOOPS),
               full_stats.mean + 1.96 * full_stats.std / sqrt(SIGN_LOOPS));

        free(sign_full);
        free(all_attempts);
        free(setup_costs);
    }

    /* ============================================================== */
    /* Verify Benchmark                                                */
    /* ============================================================== */
    {
        /* Generate a valid signature for verify benchmark */
        for (int j = 0; j < MLEN; j++)
            sm[NCC_CRYPTO_BYTES + MLEN - 1 - j] = m[MLEN - 1 - j];
        crypto_sign_signature(sm, &smlen, sm + NCC_CRYPTO_BYTES, MLEN, sk);
        smlen += MLEN;

        uint64_t *cycles = malloc(KG_VF_LOOPS * sizeof(uint64_t));
        for (int i = 0; i < KG_VF_LOOPS; i++) {
            uint64_t t0 = cpucycles();
            crypto_sign_open(m2, &mlen2, sm, smlen, pk);
            uint64_t t1 = cpucycles();
            cycles[i] = t1 - t0;
        }
        stats_t s = compute_stats(cycles, KG_VF_LOOPS);
        printf("\n>>> Verify\n");
        print_stats("Verify", &s);
        free(cycles);
    }

    printf("\n================================================================\n");
    printf("  Benchmark complete.\n");
    printf("================================================================\n");

    return 0;
}
