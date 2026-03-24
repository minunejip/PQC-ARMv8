/*
 * Rejection rate test: counts average sign calls per signing operation.
 * Uses KpqC_bench approach: just measures average cycles as a proxy.
 * Also tests if we can round-trip sign→verify consistently.
 */
#include <stdio.h>
#include <string.h>
#include "api.h"
#include "cpucycles.h"
#include "randombytes.h"

#define TEST_LOOP 10000
#define MLEN 24

int main(void) {
#if defined(__aarch64__)
    setup_rdtsc();
#endif

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char m[MLEN + CRYPTO_BYTES];
    unsigned char m2[MLEN + CRYPTO_BYTES];
    unsigned char sm[MLEN + CRYPTO_BYTES];
    unsigned long long mlen;
    unsigned long long smlen;

    randombytes(m, MLEN);
    mlen = MLEN;

    printf("CRYPTO_ALGNAME: %s\n", CRYPTO_ALGNAME);

    /* KeyGen */
    uint64_t kcycles = 0;
    for (int i = 0; i < TEST_LOOP; i++) {
        uint64_t c1 = cpucycles();
        crypto_sign_keypair(pk, sk);
        uint64_t c2 = cpucycles();
        kcycles += c2 - c1;
    }
    printf("KeyGen avg: %llu cycles\n", (unsigned long long)(kcycles / TEST_LOOP));

    /* Sign — measure distribution */
    crypto_sign_keypair(pk, sk);
    uint64_t sign_cycles[TEST_LOOP];
    uint64_t total_sign = 0;
    int verify_failures = 0;
    for (int i = 0; i < TEST_LOOP; i++) {
        uint64_t c1 = cpucycles();
        crypto_sign(sm, &smlen, m, mlen, sk);
        uint64_t c2 = cpucycles();
        sign_cycles[i] = c2 - c1;
        total_sign += sign_cycles[i];

        /* Verify */
        int ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
        if (ret != 0) verify_failures++;
    }

    /* Sort for percentile analysis */
    for (int i = 0; i < TEST_LOOP - 1; i++)
        for (int j = i + 1; j < TEST_LOOP; j++)
            if (sign_cycles[i] > sign_cycles[j]) {
                uint64_t tmp = sign_cycles[i];
                sign_cycles[i] = sign_cycles[j];
                sign_cycles[j] = tmp;
            }

    printf("Sign avg: %llu cycles\n", (unsigned long long)(total_sign / TEST_LOOP));
    printf("Sign median: %llu cycles\n", (unsigned long long)sign_cycles[TEST_LOOP / 2]);
    printf("Sign p10: %llu cycles\n", (unsigned long long)sign_cycles[TEST_LOOP / 10]);
    printf("Sign p90: %llu cycles\n", (unsigned long long)sign_cycles[TEST_LOOP * 9 / 10]);
    printf("Sign min: %llu cycles\n", (unsigned long long)sign_cycles[0]);
    printf("Sign max: %llu cycles\n", (unsigned long long)sign_cycles[TEST_LOOP - 1]);
    printf("Verify failures: %d/%d\n", verify_failures, TEST_LOOP);

    /* Verify benchmark */
    crypto_sign(sm, &smlen, m, mlen, sk);
    kcycles = 0;
    for (int i = 0; i < TEST_LOOP; i++) {
        uint64_t c1 = cpucycles();
        crypto_sign_open(m2, &mlen, sm, smlen, pk);
        uint64_t c2 = cpucycles();
        kcycles += c2 - c1;
    }
    printf("Verify avg: %llu cycles\n", (unsigned long long)(kcycles / TEST_LOOP));

    return 0;
}
