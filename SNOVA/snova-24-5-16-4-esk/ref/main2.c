//
//  main.c
//  HAETAE2_asm
//
//  Created by 심민주 on 4/3/24.
//

#include "deriv_params.h"
#include "snova.h"
#include "util.h"

#include <time.h>
#include "m1cycles.h"

// HAETAE_MODE -> config.h

#define NTESTS 10
// #define NTESTS 10  //?
#define MLEN 32     //?

#define TIME(s) s = rdtsc();
// Result is clock cycles
#define  CALC(start, stop) (stop - start) / NTESTS;


static unsigned char m[NTESTS][MLEN];


static int test_sign(void)
{
   snova_init();
   uint8_t array_digest[64];
   uint8_t array_signature1[bytes_signature + bytes_salt];
   uint8_t array_signature2[bytes_signature + bytes_salt];

   uint8_t seed[seed_length];
   uint8_t* pt_private_key_seed;
   uint8_t* pt_public_key_seed;
   uint8_t pk[bytes_pk], sk[bytes_sk];
   uint8_t array_salt[bytes_salt];

   uint8_t entropy_input[48];
   for (int i = 0; i < 48; i++) {
       entropy_input[i] = i;
   }
   randombytes(entropy_input, 256);
   randombytes(seed, seed_length);

   pt_public_key_seed = seed;
   pt_private_key_seed = seed + seed_length_public;

   create_salt(array_salt);

   generate_keys_esk(pt_public_key_seed, pt_private_key_seed, pk, sk);
   randombytes(array_digest, 64);

   printf("private key seed (%d bytes): \n", seed_length_private);
   //print_byte(pt_private_key_seed, seed_length_private);
   printf("public key seed (%d bytes): \n", seed_length_public);
   //print_byte(pt_public_key_seed, seed_length_public);

   printf("generate_keys_pack\n");

   generate_keys_esk(pt_public_key_seed, pt_private_key_seed, pk, sk);

   printf("private key size: (%d bytes): \n", bytes_sk);
   //print_byte(sk, bytes_sk);
   printf("public key size: (%d bytes): \n", bytes_pk);
   //print_byte(pk, bytes_pk);

   printf("hash: \n");
   randombytes(array_digest, 64);
   //print_byte(array_digest, 64);
   printf("=======================\n");

   sign_digest_esk(array_signature1, array_digest, 64, array_salt, sk);

   printf("signature (%d byte): \n", bytes_signature + bytes_salt);
   //print_byte(array_signature1, bytes_signature + bytes_salt);

   int r = verify_signture(array_digest, 64, array_signature1, pk);

   if (r == 0) {
       printf("verification successful!\n");
   } else {
       printf("verification failed! err = %d\n", r);
   }

   printf("\nsign_digest_by_seed: \n");
   printf("=======================\n");
   sign_digest_ssk(array_signature2, array_digest, 64, array_salt, seed);
   printf("signature (%d byte): \n", bytes_signature + bytes_salt);
   //print_byte(array_signature2, bytes_signature + bytes_salt);

   r = verify_signture(array_digest, 64, array_signature2, pk);
   if (r == 0) {
       printf("verification successful!\n");
       return 0;
   } else {
       printf("verification failed! err = %d\n", r);
       return -1;
   }

}

//static int test_wrong_pk(void)
//{
//    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
//    unsigned char pk2[CRYPTO_PUBLICKEYBYTES];
//    unsigned char sk[CRYPTO_SECRETKEYBYTES];
//    unsigned char sm[MLEN + CRYPTO_BYTES];
//    unsigned char m[MLEN];
//
//    size_t mlen;
//    size_t smlen;
//
//    crypto_sign_keypair(pk2, sk);
//
//    crypto_sign_keypair(pk, sk);
//
//    randombytes(m, MLEN);
//    crypto_sign(sm, &smlen, m, MLEN, sk);
//
//    // By relying on m == sm we prevent having to allocate CRYPTO_BYTES twice
//    if (crypto_sign_open(sm, &mlen, sm, smlen, pk2)){
//        return 0;
//    }
//    printf("ERROR Signature did verify correctly under wrong public key!\n");
//    return -1;
//}

int test_SNOVA(void){
   unsigned int i;
   int r;

   for(i=0;i<NTESTS;i++) {
     r  = test_sign();
//      r |= test_wrong_pk();
     if(r)
       return 1;
   }

//    printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
//    printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
//    printf("Test successful\n");

   return 0;
}


void test_speed(void){

   unsigned int i;

//    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
//    unsigned char sk[CRYPTO_SECRETKEYBYTES];
//    unsigned char sm[MLEN + CRYPTO_BYTES];

   uint8_t array_digest[64];
   uint8_t array_signature1[bytes_signature + bytes_salt];
   uint8_t array_signature2[bytes_signature + bytes_salt];

   uint8_t seed[seed_length];
   uint8_t* pt_private_key_seed;
   uint8_t* pt_public_key_seed;
   uint8_t pk[bytes_pk], sk[bytes_sk];
   uint8_t array_salt[bytes_salt];

   uint8_t entropy_input[48];
   for (int i = 0; i < 48; i++) {
       entropy_input[i] = i;
   }
   randombytes(entropy_input, 256);
   randombytes(seed, seed_length);

   pt_public_key_seed = seed;
   pt_private_key_seed = seed + seed_length_public;


   size_t mlen;
   size_t smlen;

   //   struct timespec start, stop;
     long long ns;
     long long start, stop;


   // Init performance counter
     setup_rdtsc();
   //

     TIME(start);
     for(i=0;i<NTESTS;i++) {
         generate_keys_esk(pt_public_key_seed, pt_private_key_seed, pk, sk);
     }
     TIME(stop);
     ns = CALC(start, stop);
     printf("crypto_sign_keypair: %lld\n", ns);


     for(i=0;i<NTESTS;i++){
       randombytes(m[i], MLEN);
     }

     TIME(start);
     for(i=0;i<NTESTS;i++) {
         sign_digest_esk(array_signature1, array_digest, 64, array_salt, sk);
     }
     TIME(stop);
     ns = CALC(start, stop);
     printf("crypto_sign: %lld\n", ns);

   for(i=0;i<NTESTS;i++){
     randombytes(m[i], MLEN);
   }

   TIME(start);
   for(i=0;i<NTESTS;i++) {
       int r = verify_signture(array_digest, 64, array_signature1, pk);
   }
   TIME(stop);
   ns = CALC(start, stop);
   printf("crypto_sign_verify: %lld\n", ns);

//    if (r == 0) {
//        printf("verification successful!\n");
//    } else {
//        printf("verification failed! err = %d\n", r);
//    }


//      TIME(start);
//      for(i=0;i<NTESTS;i++) {
//        crypto_sign_open(m[i], &mlen, sm, smlen, pk);
//      }
//      TIME(stop);
//      ns = CALC(start, stop);
//      printf("crypto_sign_open: %lld\n", ns);

}

int main(void)
{
   test_SNOVA();
   printf("\n====speed====\n");
   test_speed();

   return 0;
}



//
//unsigned char  m2[100 + CRYPTO_BYTES];
//
//unsigned long long mlen = 0;
//unsigned long long smlen;
//
//unsigned long long m2len;
//
//int result;
//
//printf("BENCHMARK ENVIRONMENTS  ============================= \n");
//printf("CRYPTO_PUBLICKEYBYTES: %d\n", CRYPTO_PUBLICKEYBYTES);
//printf("CRYPTO_SECRETKEYBYTES: %d\n", CRYPTO_SECRETKEYBYTES);
//printf("CRYPTO_BYTES: %d\n", CRYPTO_BYTES);
//printf("Number of loop: %d \n", TEST_LOOP);
//printf("KeyGen ////////////////////////////////////////////// \n");
//
//
//crypto_sign_signature(sm, &smlen, m, mlen, sk);
//result = crypto_sign_open(m2, &m2len, sm, smlen, pk);
