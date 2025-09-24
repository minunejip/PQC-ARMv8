#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"
#include "stdio.h"
#include <stdlib.h>
#define NTT 1
uint64_t mask_ar[4]={~(0UL)};

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
	uint8_t zeta[SEEDBYTES];
	uint8_t seedbuf[3 * SEEDBYTES];
	uint8_t tr[SEEDBYTES];
	const uint8_t *xi_1, *xi_2, *key;

	poly mat;
	poly s1, s1hat, s2, t1, t0;
	//poly ms1, mt;

	randombytes(zeta, SEEDBYTES);
	randombytes(seedbuf, SEEDBYTES);
	shake256(seedbuf, 3 * SEEDBYTES, seedbuf, SEEDBYTES);
	xi_1 = seedbuf;
	xi_2 = seedbuf + SEEDBYTES;
	key = seedbuf + 2 * SEEDBYTES;

	poly_uniform(&mat, zeta, 0);
	poly_uniform_eta(&s1, xi_1, 0);
	poly_uniform_eta(&s2, xi_2, 0);

#if NTT==0
	poly_mul_schoolbook(&t1, &s1, &mat);
#elif NTT==1
	ntt(s1hat.coeffs, s1.coeffs);
	poly_base_mul(&t1, &s1hat, &mat);
	invntt_tomont(t1.coeffs, t1.coeffs);
	poly_caddq(&t1);
#endif

	poly_add(&t1, &t1, &s2);
	poly_caddq(&t1);

	poly_power2round(&t1, &t0, &t1);

	pack_pk(pk, zeta, &t1);

	shake256(tr, SEEDBYTES, pk, NCC_CRYPTO_PUBLICKEYBYTES);

	pack_sk(sk, zeta, tr, key, &t0, &s1, &s2);

	return 0;
}

int crypto_sign_signature(uint8_t *sig,
                        	size_t *siglen,
                        	const uint8_t *m,
                        	size_t mlen,
                        	const uint8_t *sk)
{
	unsigned int n;
	uint8_t seedbuf[3 * SEEDBYTES + 2 * CRHBYTES];
	uint8_t *zeta, *tr, *key, *mu, *rho;
	uint16_t nonce = 0;
	poly mat, s1, y, z, t0, s2, w1, w0, h;
	poly cp;
	shake256incctx state;

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

#if NTT==1
	ntt(s1.coeffs, s1.coeffs);
	ntt(s2.coeffs, s2.coeffs);
	ntt(t0.coeffs, t0.coeffs);
#endif

rej:
	poly_uniform_gamma1(&y, rho, nonce++);
	z = y;

#if NTT==0
	poly_mul_schoolbook(&w1, &z, &mat);
#elif NTT==1
	ntt(z.coeffs, z.coeffs);
	poly_base_mul(&w1, &z, &mat);
	invntt_tomont(w1.coeffs, w1.coeffs);
	poly_caddq(&w1);
#endif

	poly_decompose(&w1, &w0, &w1);

	polyw1_pack(sig, &w1);

	shake256_inc_init(&state);
	shake256_inc_absorb(&state, mu, CRHBYTES);
	shake256_inc_absorb(&state, sig, POLYW1_PACKEDBYTES);
	shake256_inc_finalize(&state);
	shake256_inc_squeeze(sig, SEEDBYTES, &state);
	poly_challenge(&cp, sig);

#if NTT==0
	poly_mul_schoolbook(&z, &cp, &s1);
#elif NTT==1
	ntt(cp.coeffs, cp.coeffs);
	poly_base_mul(&z, &cp, &s1);
	invntt_tomont(z.coeffs, z.coeffs);
	poly_caddq(&z);
#endif
	poly_add(&z, &z, &y);
  	poly_reduce(&z);
	if (poly_chknorm(&z, GAMMA1 - BETA)){
		goto rej;
	}
#if NTT==0
	poly_mul_schoolbook(&h, &cp, &s2);
#elif NTT==1
	poly_base_mul(&h, &cp, &s2);
	invntt_tomont(h.coeffs, h.coeffs);
	poly_caddq(&h);
#endif

	poly_sub(&w0, &w0, &h);
  	poly_reduce(&w0);


	if (poly_chknorm(&w0, GAMMA2 - BETA)){
		goto rej;
	}

#if NTT==0
	poly_mul_schoolbook(&h, &cp, &t0);
#elif NTT==1
	poly_base_mul(&h, &cp, &t0);
	invntt_tomont(h.coeffs, h.coeffs);
	poly_caddq(&h);
#endif
  	poly_reduce(&h);
	if (poly_chknorm(&h, GAMMA2)){
		goto rej;
	}

	poly_add(&w0, &w0, &h);

	n = poly_make_hint(&h, &w0, &w1);

	if (n > OMEGA){
		goto rej;
	}

	pack_sig(sig, sig, &z, &h);
	*siglen = NCC_CRYPTO_BYTES;
	return 0;
}

int crypto_sign(uint8_t *sm,
              	size_t *smlen,
              	const uint8_t *m,
              	size_t mlen,
              	const uint8_t *sk)
{
	size_t i;

	for (i = 0; i < mlen; ++i)
		sm[NCC_CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
	crypto_sign_signature(sm, smlen, sm + NCC_CRYPTO_BYTES, mlen, sk);
	*smlen += mlen;
	return 0;
}

int crypto_sign_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk)
{
	unsigned int i;
	uint8_t buf[POLYW1_PACKEDBYTES];
	uint8_t zeta[SEEDBYTES];
	uint8_t mu[CRHBYTES];
	uint8_t c[SEEDBYTES];
	uint8_t c2[SEEDBYTES];

	poly cp, mat, z, t1, t11, w1, h;
	shake256incctx state;
	//poly mz, mw1, mcp, mt1, mt1_temp;

	if (siglen != NCC_CRYPTO_BYTES)
		return -1;
	unpack_pk(zeta, &t1, pk);

	if (unpack_sig(c, &z, &h, sig))
		return -1;

	if (poly_chknorm(&z, GAMMA1 - BETA))
		return -1;

	shake256(mu, SEEDBYTES, pk, NCC_CRYPTO_PUBLICKEYBYTES);
	shake256_inc_init(&state);
	shake256_inc_absorb(&state, mu, SEEDBYTES);
	shake256_inc_absorb(&state, m, mlen);
	shake256_inc_finalize(&state);
	shake256_inc_squeeze(mu, CRHBYTES, &state);
	poly_challenge(&cp, c);

	poly_uniform(&mat, zeta, 0);

#if NTT==0
	poly_mul_schoolbook(&w1, &z, &mat);
#elif NTT==1
	ntt(z.coeffs, z.coeffs);
	poly_base_mul(&w1, &z, &mat);
	invntt_tomont(w1.coeffs, w1.coeffs);
	poly_caddq(&w1);
#endif
	poly_shiftl(&t1);

#if NTT==0
	poly_mul_schoolbook(&t1, &cp, &t1);
	poly_sub(&w1, &w1, &t1);
#elif NTT==1
	ntt(t11.coeffs, t1.coeffs);
	ntt(cp.coeffs, cp.coeffs);
	poly_base_mul(&t1, &cp, &t11);
	invntt_tomont(t1.coeffs, t1.coeffs);
	poly_caddq(&t1);
	poly_sub(&w1, &w1, &t1);
	poly_caddq(&w1);
#endif

	poly_use_hint(&w1, &w1, &h);
	polyw1_pack(buf, &w1);

	shake256_inc_init(&state);
	shake256_inc_absorb(&state, mu, CRHBYTES);
	shake256_inc_absorb(&state, buf, POLYW1_PACKEDBYTES);
	shake256_inc_finalize(&state);
	shake256_inc_squeeze(c2, SEEDBYTES, &state);

	for (i = 0; i < SEEDBYTES; ++i)
		if (c[i] != c2[i])
			return -1;

	return 0;
}

int crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *pk)
{
	size_t i;

	if (smlen < NCC_CRYPTO_BYTES)
		goto badsig;

	*mlen = smlen - NCC_CRYPTO_BYTES;
	if (crypto_sign_verify(sm, NCC_CRYPTO_BYTES, sm + NCC_CRYPTO_BYTES, *mlen, pk))
		goto badsig;
	else {
		for (i = 0; i < *mlen; ++i)
			m[i] = sm[NCC_CRYPTO_BYTES + i];
		return 0;
	}

badsig:
	/* Signature verification failed */
	*mlen = -1;
	for (i = 0; i < smlen; ++i)
		m[i] = 0;

	return -1;
}
