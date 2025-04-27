// asm_add_rank2_general.s
// asm_add 함수 for rank=2 using general-purpose registers

    .align 4
    .globl asm_add
    .globl _asm_add

asm_add:
_asm_add:

    // a 포인터(x0)로부터 4바이트를 일반 레지스터 w3에 로드
    ldr w3, [x0]

    // b 포인터(x1)로부터 4바이트를 일반 레지스터 w4에 로드
    ldr w4, [x1]

    // w3과 w4를 XOR하여 w5에 저장
    eor w5, w3, w4

    // 결과를 c 포인터(x2)에 저장
    str w5, [x2]

    // 함수 종료
    ret
