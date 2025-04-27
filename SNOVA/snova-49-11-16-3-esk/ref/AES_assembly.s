
  .text
    .align 4
    .globl aes128_ctr_multi_asm
    .globl _aes128_ctr_multi_asm

aes128_ctr_multi_asm:
_aes128_ctr_multi_asm:

    // 프로로그
    stp x29, x30, [sp, #-16]!   // 프레임 포인터와 링크 레지스터 저장
    mov x29, sp                 // 프레임 포인터 설정

    // 매개변수
    // x0: output 포인터
    // x1: length (바이트 수)
    // x2: nonce 포인터 (16 바이트)
    // x3: roundkey 포인터 (176 바이트)

    ldr q5, [x2]                // 넌스 로드

    // AES 키 로드
    ldp q6, q7, [x3]            // 라운드 키 0,1
    ldp q8, q9, [x3, #32]       // 라운드 키 2,3
    ldp q10, q11, [x3, #64]     // 라운드 키 4,5
    ldp q12, q13, [x3, #96]     // 라운드 키 6,7
    ldp q14, q15, [x3, #128]    // 라운드 키 8,9
    ldr q16, [x3, #160]         // 라운드 키 10

    // 블록 수 계산
    mov x4, #0                  // 블록 인덱스 초기화
    lsr x5, x1, #4              // 바이트 수 -> 블록 수 (16 바이트 단위)

    // 초기 카운터 값
    movi v1.16b, #0             // 모든 값 초기화
    mov w6, #1
    ins v1.b[0], w6             // 첫 번째 바이트를 1로 설정

encrypt_loop:
    cmp x4, x5                  // 블록 수 확인
    bge encrypt_done            // 처리 완료 시 종료

    // 카운터 값 암호화
    mov v0.16b, v5.16b          // v0 <- 넌스 + 카운터

    aese v0.16b, v6.16b         // 라운드 0
    aesmc v0.16b, v0.16b        // AESMC
    aese v0.16b, v7.16b         // 라운드 1
    aesmc v0.16b, v0.16b        // AESMC
    aese v0.16b, v8.16b         // 라운드 2
    aesmc v0.16b, v0.16b        // AESMC
    aese v0.16b, v9.16b         // 라운드 3
    aesmc v0.16b, v0.16b        // AESMC
    aese v0.16b, v10.16b        // 라운드 4
    aesmc v0.16b, v0.16b        // AESMC
    aese v0.16b, v11.16b        // 라운드 5
    aesmc v0.16b, v0.16b        // AESMC
    aese v0.16b, v12.16b        // 라운드 6
    aesmc v0.16b, v0.16b        // AESMC
    aese v0.16b, v13.16b        // 라운드 7
    aesmc v0.16b, v0.16b        // AESMC
    aese v0.16b, v14.16b        // 라운드 8
    aesmc v0.16b, v0.16b        // AESMC
    aese v0.16b, v15.16b        // 라운드 9
    aesmc v0.16b, v0.16b        // AESMC
    aese v0.16b, v16.16b        // 라운드 10 (마지막)

    // 암호문 저장
    str q0, [x0, x4, LSL #4]    // 암호문 블록 저장

    // 카운터 증가
    add v5.16b, v5.16b, v1.16b  // v5 += v1 (카운터 증가)

    // 다음 블록으로 이동
    add x4, x4, #1
    b encrypt_loop

encrypt_done:
    // 에필로그
    ldp x29, x30, [sp], #16
    ret