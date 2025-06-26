//
//  asm_add.s
//  snova_xcode test
//
//  Created by minwoo on 2024/03/20.
//
.align 4
.globl asm_add
.globl _asm_add

asm_add:
_asm_add:

LD1.16b {v0}, [x0]
LD1.16b {v1}, [x1]

EOR.16b v1, v0, v1

ST1.16b {v1}, [x2]

RET
