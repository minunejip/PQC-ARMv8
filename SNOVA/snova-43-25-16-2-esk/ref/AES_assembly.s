    .text
    .align 4
    .globl aes128_ctr_multi_asm
    .globl _aes128_ctr_multi_asm

aes128_ctr_multi_asm:
_aes128_ctr_multi_asm:

    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    // 매개변수
    // x0: output 포인터
    // x1: length (바이트 수)
    // x2: nonce 포인터 (16 바이트)
    // x3: roundkey 포인터 (176 바이트)

    ldr     q5, [x2]

    ldp     q6,  q7,  [x3]
    ldp     q8,  q9,  [x3,  #32]
    ldp     q10, q11, [x3,  #64]
    ldp     q12, q13, [x3,  #96]
    ldp     q14, q15, [x3, #128]
    ldr     q16,      [x3, #160]

    mov     x4, #0
    lsr     x5, x1, #4

    movi    v1.16b, #0
    mov     w6, #1
    ins     v1.b[0], w6

encrypt_loop:
    cmp     x4, x5
    bge     encrypt_done

    mov     v0.16b, v5.16b

    aese    v0.16b, v6.16b
    aesmc   v0.16b, v0.16b
    aese    v0.16b, v7.16b
    aesmc   v0.16b, v0.16b
    aese    v0.16b, v8.16b
    aesmc   v0.16b, v0.16b
    aese    v0.16b, v9.16b
    aesmc   v0.16b, v0.16b
    aese    v0.16b, v10.16b
    aesmc   v0.16b, v0.16b
    aese    v0.16b, v11.16b
    aesmc   v0.16b, v0.16b
    aese    v0.16b, v12.16b
    aesmc   v0.16b, v0.16b
    aese    v0.16b, v13.16b
    aesmc   v0.16b, v0.16b
    aese    v0.16b, v14.16b
    aesmc   v0.16b, v0.16b
    aese    v0.16b, v15.16b
    aesmc   v0.16b, v0.16b
    aese    v0.16b, v16.16b

    str     q0, [x0, x4, LSL #4]

    add     v5.16b, v5.16b, v1.16b

    add     x4, x4, #1
    b       encrypt_loop

encrypt_done:
    ldp     x29, x30, [sp], #16
    ret
