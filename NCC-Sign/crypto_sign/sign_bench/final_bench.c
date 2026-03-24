/*
 * final_bench.c - Comprehensive NCC-Sign benchmarking
 *
 * Measures KeyGen, Sign (full + setup + per-attempt), Verify
 * and profiles individual building-block functions.
 *
 * Compile with: -DBENCH_PROFILE -DBUILD_NAME=\"clean\" (or \"optimized\")
 * Output: CSV appended to file (default: results_m1pro_final.csv)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "config.h"
#include "params.h"
#include "api.h"
#include "cpucycles.h"
#include "randombytes.h"
#include "poly.h"
#include "packing.h"
#include "fips202.h"

/* ------------------------------------------------------------------ */
/* Benchmark parameters                                                */
/* ------------------------------------------------------------------ */
#define BENCH_LOOP   10000
#define BENCH_SETS   10
#define WARMUP       100
#define PROFILE_LOOP 1000
#define MLEN         24
#define MAX_ATTEMPTS 300000   /* per set: 10000 signs * ~30 max attempts */

/* ------------------------------------------------------------------ */
/* BENCH_PROFILE globals (written by instrumented sign.c)              */
/* ------------------------------------------------------------------ */
uint64_t g_attempt_cycles[MAX_ATTEMPTS];
int      g_attempt_idx  = 0;
uint64_t g_setup_cycles = 0;

/* ------------------------------------------------------------------ */
/* Compile-time identifiers                                            */
/* ------------------------------------------------------------------ */
#ifndef BUILD_NAME
#define BUILD_NAME "unknown"
#endif

#if NIMS_TRI_NTT_MODE == 1
#define PARAM_NAME "Sign1"
#elif NIMS_TRI_NTT_MODE == 3
#define PARAM_NAME "Sign3"
#elif NIMS_TRI_NTT_MODE == 5
#define PARAM_NAME "Sign5"
#endif

/* ------------------------------------------------------------------ */
/* CSV output                                                          */
/* ------------------------------------------------------------------ */
static FILE *csv_fp;

static void csv_out(const char *op, const char *metric,
                    int set, int iter, uint64_t cyc)
{
    fprintf(csv_fp, "%s,%s,%s,%s,%d,%d,%llu\n",
            PARAM_NAME, BUILD_NAME, op, metric,
            set, iter, (unsigned long long)cyc);
}

/* ------------------------------------------------------------------ */
/* Warmup                                                              */
/* ------------------------------------------------------------------ */
static void warmup_run(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char m[MLEN + CRYPTO_BYTES];
    unsigned char m2[MLEN + CRYPTO_BYTES];
    unsigned char sm[MLEN + CRYPTO_BYTES];
    size_t smlen, mlen2;

    randombytes(m, MLEN);
    for (int i = 0; i < WARMUP; i++) {
        crypto_sign_keypair(pk, sk);
        crypto_sign(sm, &smlen, m, MLEN, sk);
        crypto_sign_open(m2, &mlen2, sm, smlen, pk);
    }
}

/* ------------------------------------------------------------------ */
/* KeyGen benchmark: 10 sets x 10,000 iterations                       */
/* ------------------------------------------------------------------ */
static void bench_keygen(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    uint64_t c1, c2;
    uint64_t cycles[BENCH_LOOP];

    for (int s = 0; s < BENCH_SETS; s++) {
        /* Measure */
        for (int i = 0; i < BENCH_LOOP; i++) {
            c1 = cpucycles();
            crypto_sign_keypair(pk, sk);
            c2 = cpucycles();
            cycles[i] = c2 - c1;
        }
        /* Output (after measuring to avoid I/O interference) */
        for (int i = 0; i < BENCH_LOOP; i++)
            csv_out("keygen", "end2end", s + 1, i + 1, cycles[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Sign benchmark: full, setup, per-attempt                            */
/* ------------------------------------------------------------------ */
static void bench_sign(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char m[MLEN + CRYPTO_BYTES];
    unsigned char sm[MLEN + CRYPTO_BYTES];
    size_t smlen;
    uint64_t c1, c2;
    uint64_t full_cycles[BENCH_LOOP];
    uint64_t setup_cycles_arr[BENCH_LOOP];

    /* Generate keys once */
    randombytes(m, MLEN);
    crypto_sign_keypair(pk, sk);

    for (int s = 0; s < BENCH_SETS; s++) {
        g_attempt_idx = 0;

        /* Measure */
        for (int i = 0; i < BENCH_LOOP; i++) {
            c1 = cpucycles();
            crypto_sign(sm, &smlen, m, MLEN, sk);
            c2 = cpucycles();
            full_cycles[i]      = c2 - c1;
            setup_cycles_arr[i] = g_setup_cycles;
        }

        int total_attempts = g_attempt_idx;

        /* Output: full sign cycles */
        for (int i = 0; i < BENCH_LOOP; i++)
            csv_out("sign", "full", s + 1, i + 1, full_cycles[i]);

        /* Output: setup cycles (per sign call) */
        for (int i = 0; i < BENCH_LOOP; i++)
            csv_out("sign", "setup", s + 1, i + 1, setup_cycles_arr[i]);

        /* Output: per-attempt cycles (flat array across all sign calls) */
        for (int i = 0; i < total_attempts; i++)
            csv_out("sign", "per_attempt", s + 1, i + 1, g_attempt_cycles[i]);

        /* Reset for next set */
        g_attempt_idx = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Verify benchmark: 10 sets x 10,000 iterations                      */
/* ------------------------------------------------------------------ */
static void bench_verify(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char m[MLEN + CRYPTO_BYTES];
    unsigned char m2[MLEN + CRYPTO_BYTES];
    unsigned char sm[MLEN + CRYPTO_BYTES];
    size_t smlen, mlen2;
    uint64_t c1, c2;
    uint64_t cycles[BENCH_LOOP];

    /* Generate keys and a valid signature */
    randombytes(m, MLEN);
    crypto_sign_keypair(pk, sk);
    crypto_sign(sm, &smlen, m, MLEN, sk);

    for (int s = 0; s < BENCH_SETS; s++) {
        for (int i = 0; i < BENCH_LOOP; i++) {
            c1 = cpucycles();
            crypto_sign_open(m2, &mlen2, sm, smlen, pk);
            c2 = cpucycles();
            cycles[i] = c2 - c1;
        }
        for (int i = 0; i < BENCH_LOOP; i++)
            csv_out("verify", "end2end", s + 1, i + 1, cycles[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Function profiling: 1,000 iterations each                           */
/* ------------------------------------------------------------------ */
#define PROF_BEGIN(name_str)                                        \
    do {                                                            \
        uint64_t _prof_cycles[PROFILE_LOOP];                        \
        const char *_prof_name = (name_str);

#define PROF_ITER_START  _prof_c1 = cpucycles();
#define PROF_ITER_END(i) _prof_cycles[i] = cpucycles() - _prof_c1;

#define PROF_OUTPUT                                                 \
        for (int _k = 0; _k < PROFILE_LOOP; _k++)                  \
            csv_out("profile", _prof_name, 0, _k + 1, _prof_cycles[_k]); \
    } while (0)

/* Convenience macro: simple expression profiling */
#define PROF(name, setup_expr, bench_expr)                          \
    do {                                                            \
        uint64_t _pcyc[PROFILE_LOOP];                               \
        uint64_t _prof_c1;                                          \
        for (int _pi = 0; _pi < PROFILE_LOOP; _pi++) {             \
            setup_expr;                                             \
            _prof_c1 = cpucycles();                                 \
            bench_expr;                                             \
            _pcyc[_pi] = cpucycles() - _prof_c1;                   \
        }                                                           \
        for (int _pi = 0; _pi < PROFILE_LOOP; _pi++)               \
            csv_out("profile", name, 0, _pi + 1, _pcyc[_pi]);      \
    } while (0)

static void bench_profile(void)
{
    poly a, b, c_poly;
    int32_t ntt_in[N], ntt_out[N];
    uint8_t seed[SEEDBYTES];
    uint8_t crh[CRHBYTES];

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];

    /* Generate test data */
    randombytes(seed, SEEDBYTES);
    randombytes(crh, CRHBYTES);
    randombytes((uint8_t *)a.coeffs, sizeof(a.coeffs));
    randombytes((uint8_t *)b.coeffs, sizeof(b.coeffs));
    crypto_sign_keypair(pk, sk);

    /* Reduce coefficients to valid range */
    for (int i = 0; i < N; i++) {
        a.coeffs[i] = ((uint32_t)a.coeffs[i]) % Q;
        b.coeffs[i] = ((uint32_t)b.coeffs[i]) % Q;
    }
    memcpy(ntt_in, a.coeffs, sizeof(ntt_in));

    /* === Core arithmetic === */
    PROF("ntt",
         memcpy(ntt_in, a.coeffs, sizeof(ntt_in)),
         ntt(ntt_out, ntt_in));

    PROF("invntt",
         memcpy(ntt_in, a.coeffs, sizeof(ntt_in)),
         invntt_tomont(ntt_out, ntt_in));

    PROF("basemul",
         (void)0,
         poly_base_mul(&c_poly, &a, &b));

    /* === Sampling === */
    PROF("poly_uniform",
         (void)0,
         poly_uniform(&c_poly, seed, 0));

    PROF("poly_uniform_eta",
         (void)0,
         poly_uniform_eta(&c_poly, crh, 0));

#ifdef HAS_POLY_UNIFORM_ETA_X2
    PROF("poly_uniform_eta_x2",
         (void)0,
         poly_uniform_eta_x2(&a, &b, crh, crh, 0, 1));
#endif

    PROF("poly_uniform_gamma1",
         (void)0,
         poly_uniform_gamma1(&c_poly, crh, 0));

    /* === Hashing === */
    {
        uint8_t hash_out[CRHBYTES];
        PROF("shake256_hash",
             (void)0,
             shake256(hash_out, CRHBYTES, seed, SEEDBYTES));
    }

    PROF("poly_challenge",
         (void)0,
         poly_challenge(&c_poly, seed));

    /* === Packing === */
    {
        uint8_t zeta[SEEDBYTES], tr[SEEDBYTES], key[SEEDBYTES];
        poly t0p, s1p, s2p, t1p;
        uint8_t pk_buf[CRYPTO_PUBLICKEYBYTES];
        uint8_t sk_buf[CRYPTO_SECRETKEYBYTES];

        randombytes(zeta, SEEDBYTES);
        randombytes(tr, SEEDBYTES);
        randombytes(key, SEEDBYTES);
        randombytes((uint8_t *)t1p.coeffs, sizeof(t1p.coeffs));
        randombytes((uint8_t *)t0p.coeffs, sizeof(t0p.coeffs));
        randombytes((uint8_t *)s1p.coeffs, sizeof(s1p.coeffs));
        randombytes((uint8_t *)s2p.coeffs, sizeof(s2p.coeffs));
        for (int i = 0; i < N; i++) {
            t1p.coeffs[i] = ((uint32_t)t1p.coeffs[i]) % Q;
            t0p.coeffs[i] = ((uint32_t)t0p.coeffs[i]) % Q;
            s1p.coeffs[i] = ((int32_t)s1p.coeffs[i]) % (int32_t)(2 * ETA + 1);
            s2p.coeffs[i] = ((int32_t)s2p.coeffs[i]) % (int32_t)(2 * ETA + 1);
        }

        /* First pack so unpack has valid data */
        pack_pk(pk_buf, zeta, &t1p);
        pack_sk(sk_buf, zeta, tr, key, &t0p, &s1p, &s2p);

        PROF("pack_pk", (void)0, pack_pk(pk_buf, zeta, &t1p));
        PROF("pack_sk", (void)0, pack_sk(sk_buf, zeta, tr, key, &t0p, &s1p, &s2p));
        PROF("unpack_pk", (void)0, unpack_pk(zeta, &t1p, pk_buf));
        PROF("unpack_sk", (void)0, unpack_sk(zeta, tr, key, &t0p, &s1p, &s2p, sk_buf));
    }

    {
        uint8_t sig_buf[CRYPTO_BYTES];
        uint8_t c_buf[SEEDBYTES];
        poly zp, hp;

        randombytes(c_buf, SEEDBYTES);
        memset(hp.coeffs, 0, sizeof(hp.coeffs));
        for (int i = 0; i < N; i++)
            zp.coeffs[i] = ((uint32_t)a.coeffs[i]) % (2 * GAMMA1);

        pack_sig(sig_buf, c_buf, &zp, &hp);

        PROF("pack_sig", (void)0, pack_sig(sig_buf, c_buf, &zp, &hp));
        PROF("unpack_sig", (void)0, unpack_sig(c_buf, &zp, &hp, sig_buf));
    }

    {
        uint8_t w1buf[POLYW1_PACKEDBYTES];
        PROF("polyw1_pack", (void)0, polyw1_pack(w1buf, &a));
    }

    /* === Polynomial arithmetic === */
    PROF("poly_add", (void)0, poly_add(&c_poly, &a, &b));
    PROF("poly_sub", (void)0, poly_sub(&c_poly, &a, &b));

    {
        poly tmp;
        PROF("poly_reduce",
             memcpy(&tmp, &a, sizeof(poly)),
             poly_reduce(&tmp));
    }

    {
        poly tmp;
        PROF("poly_caddq",
             memcpy(&tmp, &a, sizeof(poly)),
             poly_caddq(&tmp));
    }

    PROF("poly_power2round", (void)0, poly_power2round(&a, &b, &c_poly));
    PROF("poly_decompose",   (void)0, poly_decompose(&a, &b, &c_poly));
    PROF("poly_make_hint",   (void)0, poly_make_hint(&c_poly, &a, &b));
    PROF("poly_use_hint",    (void)0, poly_use_hint(&c_poly, &a, &b));

    {
        /* Use small coefficients so chknorm does full scan */
        poly small;
        for (int i = 0; i < N; i++)
            small.coeffs[i] = i % 100;
        PROF("poly_chknorm", (void)0, poly_chknorm(&small, GAMMA1));
    }

    {
        poly tmp;
        PROF("poly_shiftl",
             memcpy(&tmp, &a, sizeof(poly)),
             poly_shiftl(&tmp));
    }
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
#if defined(__aarch64__)
    setup_rdtsc();
#endif

    const char *outfile = (argc > 1) ? argv[1] : "results_m1pro_final.csv";

    /* Append mode: first process writes header */
    int needs_header = 0;
    {
        FILE *test = fopen(outfile, "r");
        if (!test)
            needs_header = 1;
        else
            fclose(test);
    }

    csv_fp = fopen(outfile, "a");
    if (!csv_fp) {
        perror(outfile);
        return 1;
    }
    if (needs_header)
        fprintf(csv_fp, "param,build,operation,metric,set,iteration,cycles\n");

    fprintf(stderr, "[%s/%s] Warming up (%d iters)...\n",
            PARAM_NAME, BUILD_NAME, WARMUP);
    warmup_run();
    g_attempt_idx = 0;   /* reset after warmup */

    fprintf(stderr, "[%s/%s] KeyGen (%d sets x %d)...\n",
            PARAM_NAME, BUILD_NAME, BENCH_SETS, BENCH_LOOP);
    bench_keygen();

    fprintf(stderr, "[%s/%s] Sign (%d sets x %d)...\n",
            PARAM_NAME, BUILD_NAME, BENCH_SETS, BENCH_LOOP);
    bench_sign();

    fprintf(stderr, "[%s/%s] Verify (%d sets x %d)...\n",
            PARAM_NAME, BUILD_NAME, BENCH_SETS, BENCH_LOOP);
    bench_verify();

    fprintf(stderr, "[%s/%s] Profile (%d iters)...\n",
            PARAM_NAME, BUILD_NAME, PROFILE_LOOP);
    bench_profile();

    fclose(csv_fp);
    fprintf(stderr, "[%s/%s] Done. Results -> %s\n",
            PARAM_NAME, BUILD_NAME, outfile);
    return 0;
}
