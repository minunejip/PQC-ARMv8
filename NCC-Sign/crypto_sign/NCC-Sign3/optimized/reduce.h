#ifndef REDUCE_H
#define REDUCE_H
#endif

#include <stdint.h>
#include "params.h"
#include "config.h"

int32_t montgomery_reduce(int64_t a);
uint32_t to_mont(int32_t a);
uint32_t from_mont(int32_t a);



int32_t caddq(int32_t a);
int32_t csubq(int32_t a) ;


int32_t freeze(int32_t a);
int32_t mod_add(int32_t a, int32_t b);
int32_t mod_sub(int32_t a, int32_t b);
int32_t reduce32(int32_t a);

#if NIMS_TRI_NTT_MODE == 1
#define MONT 1781889 // 2^32 % Q
#define QINV 2245397889 // q^(-1) mod 2^32
#define R2 2742207 // 2^64 % Q

#elif NIMS_TRI_NTT_MODE == 3
#define MONT 3940353 // 2^32 % Q
#define QINV 2080628225 // q^(-1) mod 2^32
#define R2 1946999 // 2^64 % Q

#elif NIMS_TRI_NTT_MODE == 5
#define MONT 15873 // 2^32 % Q
#define QINV 260030465 // q^(-1) mod 2^32
#define R2 8207332 // 2^64 % Q

#endif
