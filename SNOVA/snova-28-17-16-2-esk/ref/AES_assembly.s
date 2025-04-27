.text
.align 4
.globl aes128_ctr_multi_asm
.globl _aes128_ctr_multi_asm

aes128_ctr_multi_asm:
_aes128_ctr_multi_asm:

    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // 매개변수
    // x0: output 포인터
    // x1: length (바이트 수)
    // x2: nonce 포인터 (16 바이트)
    // x3: roundkey 포인터 (176 바이트)

    // 넌스 및 초기 카운터 로드
    ldr q16, [x2]                  // nonce + counter 초기값

    // 카운터 증가 초기화 (v17 = {0, 0, 0, 0})
    movi v17.4s, #0

    // 카운터 증가 설정 (첫 번째 요소에 1 삽입)
    mov x6, #1
    ins v17.d[0], x6               // v17.s[0] = 1

    // AES 라운드 키 로드
    ldp q6, q7, [x3]              // 라운드 키 0, 1
    ldp q8, q9, [x3, #32]         // 라운드 키 2, 3
    ldp q10, q11, [x3, #64]       // 라운드 키 4, 5
    ldp q12, q13, [x3, #96]       // 라운드 키 6, 7
    ldp q14, q15, [x3, #128]      // 라운드 키 8, 9
    ldr q18, [x3, #160]           // 라운드 키 10

    // 블록 수 계산 (16 바이트 블록 기준)
    mov x4, #0                    // 블록 인덱스 초기화
    lsr x5, x1, #4                // 바이트 수 -> 블록 수 계산

encrypt_loop:
    cmp x4, x5                    // 현재 블록 수 확인
    bge encrypt_done              // 완료 시 종료

    // 병렬 카운터 설정
    mov v0.16b, v16.16b           // v0 = 카운터 + 넌스
    mov v1.16b, v16.16b
    mov v2.16b, v16.16b
    mov v3.16b, v16.16b

    // 카운터 증가
    add v1.4s, v1.4s, v17.4s
    add v2.4s, v1.4s, v17.4s
    add v3.4s, v2.4s, v17.4s

    // 병렬 AES 암호화
    aese v0.16b, v6.16b
    aesmc v0.16b, v0.16b
    aese v1.16b, v6.16b
    aesmc v1.16b, v1.16b
    aese v2.16b, v6.16b
    aesmc v2.16b, v2.16b
    aese v3.16b, v6.16b
    aesmc v3.16b, v3.16b

    // 계속 AES 라운드 수행
    aese v0.16b, v7.16b
    aesmc v0.16b, v0.16b
    aese v1.16b, v7.16b
    aesmc v1.16b, v1.16b
    aese v2.16b, v7.16b
    aesmc v2.16b, v2.16b
    aese v3.16b, v7.16b
    aesmc v3.16b, v3.16b

    aese v0.16b, v18.16b
    aese v1.16b, v18.16b
    aese v2.16b, v18.16b
    aese v3.16b, v18.16b

    // 결과 저장 (병렬 저장)
    st4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #64

    // 카운터 업데이트
    movi v19.4s, #4              // 벡터 값 설정
    add v16.4s, v16.4s, v19.4s   // 카운터 증가

    // 다음 블록으로 이동
    add x4, x4, #4               // 다음 블록으로 이동
    b encrypt_loop

encrypt_done:
    ldp x29, x30, [sp], #16
    ret
