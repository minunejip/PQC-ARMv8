// asm_add_rank2_general.s
// asm_add 함수 for rank=2 using general-purpose registers

    .align 4
    .globl asm_add
    .globl _asm_add

asm_add:
_asm_add:

    ldr w3, [x0]

    ldr w4, [x1]

    eor w5, w3, w4

    str w5, [x2]

    ret
