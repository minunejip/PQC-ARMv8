/*
 * dudect constant-time leakage detection for NCC-Sign.
 *
 * Test design: fixed-random vs random-random
 *   Class 0: one fixed random input (generated once, reused)
 *   Class 1: fresh random input each time
 * A constant-time function must take the same time regardless of input,
 * so there should be no statistical difference between the two classes.
 *
 * Tests:
 *   1. NTT (forward)
 *   2. INTT (inverse NTT)
 *   3. Pointwise multiplication (poly_base_mul)
 *   4. poly_chknorm (norm check)
 *   5. unpack_sk + NTT(s1)
 *   6. Full crypto_sign (fixed msg vs random msg, same SK)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* NCC-Sign headers */
#include "params.h"
#include "sign.h"
#include "poly.h"
#include "packing.h"
#include "randombytes.h"
#include "cpucycles.h"
#include "config.h"

/* dudect */
#define DUDECT_IMPLEMENTATION
#include "dudect.h"

/* ------------------------------------------------------------------ */
/* Test selection (set via -DDUDECT_TEST_ID=N at compile time)         */
/* ------------------------------------------------------------------ */
#ifndef DUDECT_TEST_ID
#define DUDECT_TEST_ID 1
#endif

#define DUDECT_NUM_MEASUREMENTS 100000
#define DUDECT_MAX_ITERATIONS   300

/* ------------------------------------------------------------------ */
/* Helper: generate a fixed random input once                          */
/* ------------------------------------------------------------------ */
static uint8_t g_fixed_input[16384];  /* large enough for any chunk */
static int g_fixed_initialized = 0;

static void ensure_fixed_input(size_t chunk_size) {
    if (!g_fixed_initialized) {
        dudect_randombytes(g_fixed_input, chunk_size);
        g_fixed_initialized = 1;
    }
}

/* ------------------------------------------------------------------ */
/* Helper: reduce int32 coefficients to valid range                    */
/* ------------------------------------------------------------------ */
static void reduce_coeffs(int32_t *coeffs, int count) {
    for (int j = 0; j < count; j++) {
        /* Map to [-Q/2, Q/2] range for realistic NTT domain values */
        coeffs[j] = ((coeffs[j] % Q) + Q) % Q;
        if (coeffs[j] > Q/2) coeffs[j] -= Q;
    }
}

/* ------------------------------------------------------------------ */
/* Test 1: Forward NTT                                                 */
/*   Class 0: fixed random polynomial                                  */
/*   Class 1: fresh random polynomial                                  */
/* ------------------------------------------------------------------ */
#if DUDECT_TEST_ID == 1
#define TEST_NAME "NTT (forward) [fixed-rand vs rand]"
#define CHUNK_SIZE (N * sizeof(int32_t))

uint8_t do_one_computation(uint8_t *data) {
    poly *a = (poly *)data;
    poly out;
    ntt(out.coeffs, a->coeffs);
    return (uint8_t)out.coeffs[0];
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    ensure_fixed_input(c->chunk_size);
    /* Reduce fixed input coefficients (once) */
    static int fixed_reduced = 0;
    if (!fixed_reduced) {
        reduce_coeffs((int32_t *)g_fixed_input, N);
        fixed_reduced = 1;
    }

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = dudect_randombit();
        uint8_t *ptr = input_data + i * c->chunk_size;
        if (classes[i] == 0) {
            memcpy(ptr, g_fixed_input, c->chunk_size);
        } else {
            dudect_randombytes(ptr, c->chunk_size);
            reduce_coeffs((int32_t *)ptr, N);
        }
    }
}
#endif

/* ------------------------------------------------------------------ */
/* Test 2: Inverse NTT                                                 */
/* ------------------------------------------------------------------ */
#if DUDECT_TEST_ID == 2
#define TEST_NAME "INTT (inverse) [fixed-rand vs rand]"
#define CHUNK_SIZE (N * sizeof(int32_t))

uint8_t do_one_computation(uint8_t *data) {
    poly *a = (poly *)data;
    poly out;
    invntt_tomont(out.coeffs, a->coeffs);
    return (uint8_t)out.coeffs[0];
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    ensure_fixed_input(c->chunk_size);
    static int fixed_reduced = 0;
    if (!fixed_reduced) {
        reduce_coeffs((int32_t *)g_fixed_input, N);
        fixed_reduced = 1;
    }

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = dudect_randombit();
        uint8_t *ptr = input_data + i * c->chunk_size;
        if (classes[i] == 0) {
            memcpy(ptr, g_fixed_input, c->chunk_size);
        } else {
            dudect_randombytes(ptr, c->chunk_size);
            reduce_coeffs((int32_t *)ptr, N);
        }
    }
}
#endif

/* ------------------------------------------------------------------ */
/* Test 3: Pointwise multiplication                                    */
/*   Class 0: fixed random (a, b) pair                                 */
/*   Class 1: fresh random (a, b) pair                                 */
/* ------------------------------------------------------------------ */
#if DUDECT_TEST_ID == 3
#define TEST_NAME "Pointwise multiply [fixed-rand vs rand]"
#define CHUNK_SIZE (2 * N * sizeof(int32_t))

uint8_t do_one_computation(uint8_t *data) {
    poly *a = (poly *)data;
    poly *b = (poly *)(data + N * sizeof(int32_t));
    poly c;
    poly_base_mul(&c, a, b);
    return (uint8_t)c.coeffs[0];
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    ensure_fixed_input(c->chunk_size);
    static int fixed_reduced = 0;
    if (!fixed_reduced) {
        reduce_coeffs((int32_t *)g_fixed_input, 2 * N);
        fixed_reduced = 1;
    }

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = dudect_randombit();
        uint8_t *ptr = input_data + i * c->chunk_size;
        if (classes[i] == 0) {
            memcpy(ptr, g_fixed_input, c->chunk_size);
        } else {
            dudect_randombytes(ptr, c->chunk_size);
            reduce_coeffs((int32_t *)ptr, 2 * N);
        }
    }
}
#endif

/* ------------------------------------------------------------------ */
/* Test 4: poly_chknorm                                                */
/*   Class 0: fixed random polynomial (realistic range)                */
/*   Class 1: fresh random polynomial (realistic range)                */
/* ------------------------------------------------------------------ */
#if DUDECT_TEST_ID == 4
#define TEST_NAME "poly_chknorm [fixed-rand vs rand]"
#define CHUNK_SIZE (N * sizeof(int32_t))

uint8_t do_one_computation(uint8_t *data) {
    poly *a = (poly *)data;
    int ret = poly_chknorm(a, GAMMA1 - BETA);
    return (uint8_t)ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    ensure_fixed_input(c->chunk_size);
    static int fixed_reduced = 0;
    if (!fixed_reduced) {
        reduce_coeffs((int32_t *)g_fixed_input, N);
        fixed_reduced = 1;
    }

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = dudect_randombit();
        int32_t *coeffs = (int32_t *)(input_data + i * c->chunk_size);
        if (classes[i] == 0) {
            memcpy(coeffs, g_fixed_input, c->chunk_size);
        } else {
            dudect_randombytes((uint8_t *)coeffs, c->chunk_size);
            reduce_coeffs(coeffs, N);
        }
    }
}
#endif

/* ------------------------------------------------------------------ */
/* Test 5: unpack_sk + NTT(s1)                                         */
/*   Class 0: fixed valid SK                                            */
/*   Class 1: different valid SK each time                              */
/* ------------------------------------------------------------------ */
#if DUDECT_TEST_ID == 5
#define TEST_NAME "unpack_sk + NTT(s1) [fixed-rand vs rand]"
#define CHUNK_SIZE NCC_CRYPTO_SECRETKEYBYTES

uint8_t do_one_computation(uint8_t *data) {
    uint8_t zeta[SEEDBYTES], tr[SEEDBYTES], key[SEEDBYTES];
    poly t0, s1, s2;
    unpack_sk(zeta, tr, key, &t0, &s1, &s2, data);
    ntt(s1.coeffs, s1.coeffs);
    return (uint8_t)s1.coeffs[0];
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    /* Generate fixed SK */
    static uint8_t fixed_sk[16384];
    static int sk_initialized = 0;
    if (!sk_initialized) {
        uint8_t pk[NCC_CRYPTO_PUBLICKEYBYTES];
        crypto_sign_keypair(pk, fixed_sk);
        sk_initialized = 1;
    }

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = dudect_randombit();
        uint8_t *ptr = input_data + i * c->chunk_size;
        if (classes[i] == 0) {
            memcpy(ptr, fixed_sk, c->chunk_size);
        } else {
            uint8_t pk2[NCC_CRYPTO_PUBLICKEYBYTES];
            crypto_sign_keypair(pk2, ptr);
        }
    }
}
#endif

/* ------------------------------------------------------------------ */
/* Test 6: Full crypto_sign                                            */
/*   Same SK for both classes.                                         */
/*   Class 0: fixed random message                                     */
/*   Class 1: fresh random message                                     */
/* ------------------------------------------------------------------ */
#if DUDECT_TEST_ID == 6
#define TEST_NAME "crypto_sign [fixed-msg vs rand-msg]"
#define SIGN_MLEN 32
#define CHUNK_SIZE SIGN_MLEN

static unsigned char g_sign_pk[NCC_CRYPTO_PUBLICKEYBYTES];
static unsigned char g_sign_sk[NCC_CRYPTO_SECRETKEYBYTES];
static int g_sign_keys_initialized = 0;

uint8_t do_one_computation(uint8_t *data) {
    if (!g_sign_keys_initialized) {
        crypto_sign_keypair(g_sign_pk, g_sign_sk);
        g_sign_keys_initialized = 1;
    }
    unsigned char sm[SIGN_MLEN + NCC_CRYPTO_BYTES];
    unsigned long long smlen;
    crypto_sign(sm, &smlen, data, SIGN_MLEN, g_sign_sk);
    return sm[0];
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    /* Fixed message for class 0 */
    static uint8_t fixed_msg[SIGN_MLEN];
    static int msg_initialized = 0;
    if (!msg_initialized) {
        dudect_randombytes(fixed_msg, SIGN_MLEN);
        msg_initialized = 1;
    }

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = dudect_randombit();
        uint8_t *ptr = input_data + i * c->chunk_size;
        if (classes[i] == 0) {
            memcpy(ptr, fixed_msg, SIGN_MLEN);
        } else {
            dudect_randombytes(ptr, SIGN_MLEN);
        }
    }
}
#endif

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */
int main(void) {
#if defined(__aarch64__)
    setup_rdtsc();
#endif

    printf("=== dudect constant-time test ===\n");
    printf("Algorithm: %s (N=%d)\n", CRYPTO_ALGNAME, N);
    printf("Test: %s (ID=%d)\n", TEST_NAME, DUDECT_TEST_ID);
    printf("Measurements/batch: %d, Max iterations: %d\n",
           DUDECT_NUM_MEASUREMENTS, DUDECT_MAX_ITERATIONS);
    printf("Input design: fixed-random vs random-random\n");
    printf("\n");

    dudect_config_t config = {
        .chunk_size = CHUNK_SIZE,
        .number_measurements = DUDECT_NUM_MEASUREMENTS,
    };

    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    int iteration = 0;

    while (iteration < DUDECT_MAX_ITERATIONS) {
        state = dudect_main(&ctx);
        iteration++;

        if (state == DUDECT_LEAKAGE_FOUND) {
            printf("\n*** LEAKAGE FOUND at iteration %d ***\n", iteration);
            break;
        }

        if (iteration % 10 == 0) {
            printf("  [%d/%d] no leakage evidence yet\n",
                   iteration, DUDECT_MAX_ITERATIONS);
            fflush(stdout);
        }
    }

    if (state != DUDECT_LEAKAGE_FOUND) {
        printf("\n=== PASS: No leakage detected after %d iterations "
               "(%.1fM measurements) ===\n",
               iteration,
               (double)iteration * DUDECT_NUM_MEASUREMENTS / 1e6);
    }

    dudect_free(&ctx);
    return (state == DUDECT_LEAKAGE_FOUND) ? 1 : 0;
}
