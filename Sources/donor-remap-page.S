.section __TEXT,__text,regular,pure_instructions
.p2align 14

/*
 * Position-independent anonymous-page donor. The fixed worker calls offset
 * zero after copying these bytes into a debug-authorized RX mapping and stays
 * in a low-power loop. Offset 0x10 is the only entry called in SpringBoard and
 * returns the harmless integer 42.
 */
.globl _codex_donor_start
_codex_donor_start:
    .inst 0xd503245f             /* bti c */
    wfe
    b _codex_donor_start + 4
    nop

.org 0x10
.globl _codex_donor_return42
_codex_donor_return42:
    .inst 0xd503245f             /* bti c */
    mov w0, #42
    ret
    nop
