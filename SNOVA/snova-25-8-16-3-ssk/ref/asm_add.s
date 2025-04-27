// asm_add.s (for rank=3 case)
// x0: pointer to a
// x1: pointer to b
// x2: pointer to c
// We must XOR 9 bytes total.

.align 4
.globl asm_add
.globl _asm_add

asm_add:
_asm_add:

    // 우선 처음 8바이트를 NEON d레지스터를 통해 처리
    // d0와 d1은 64비트(8바이트) 로드/스토어 가능
    ldr     d0, [x0]      // load 8 bytes from a
    ldr     d1, [x1]      // load 8 bytes from b

    eor     v0.8b, v0.8b, v1.8b   // XOR 8바이트

    str     d0, [x2]      // store first 8 bytes result to c

    // 남은 1바이트 처리
    ldrb    w3, [x0, #8]   // load 1 byte from a+8
    ldrb    w4, [x1, #8]   // load 1 byte from b+8
    eor     w3, w3, w4     // XOR 1바이트
    strb    w3, [x2, #8]   // store the last byte to c+8

    ret
