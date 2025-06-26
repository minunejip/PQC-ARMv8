
    .align 4
    .globl asm_add
    .globl _asm_add

asm_add:
_asm_add:

    ld1    {v0.16b}, [x0]       
    ld1    {v1.16b}, [x1]       
 
    eor    v2.16b, v0.16b, v1.16b

    st1    {v2.16b}, [x2]       // C[0..15] = v2
    ret


    
