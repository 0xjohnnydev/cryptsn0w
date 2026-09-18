.section __TEXT,__text,regular,pure_instructions
.p2align 14

/*
 * Relocatable arm64 bootstrap copied into the trusted carrier process.
 * It contains no imports or absolute references. The controller fills the
 * context-pointer slot before copying the blob into the remote RX mapping.
 */

.equ CODEX_CONTEXT_DLOPEN, 0
.equ CODEX_CONTEXT_STATUS, 8
.equ CODEX_CONTEXT_HANDLE, 16
.equ CODEX_CONTEXT_PATH, 24

.globl _codex_remote_blob_start
.globl _codex_remote_stop_gate
.globl _codex_remote_entry
.globl _codex_remote_adopt_gate
.globl _codex_remote_mmap_hook
.globl _codex_remote_fcntl_hook
.globl _codex_remote_context_pointer
.globl _codex_remote_blob_end

_codex_remote_blob_start:
_codex_remote_stop_gate:
    .inst 0xd50324df             /* bti jc */
    mov x16, #20                /* getpid */
    svc #0x80
    mov x1, #17                 /* SIGSTOP */
    mov x16, #37                /* kill */
    svc #0x80
    b _codex_remote_entry

_codex_remote_entry:
    .inst 0xd50324df             /* bti jc */
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x29, sp
    adr x19, _codex_remote_context_pointer
    ldr x19, [x19]
    cbz x19, 2f
    ldr x16, [x19, #CODEX_CONTEXT_DLOPEN]
    cbz x16, 1f
    add x0, x19, #CODEX_CONTEXT_PATH
    mov w1, #10                 /* RTLD_NOW | RTLD_GLOBAL */
    blr x16
    str x0, [x19, #CODEX_CONTEXT_HANDLE]
    cbz x0, 1f
    mov w0, #1
    str w0, [x19, #CODEX_CONTEXT_STATUS]
    b 3f
1:
    mov w0, #2
    str w0, [x19, #CODEX_CONTEXT_STATUS]
2:
    nop
3:
    mov x16, #20                /* getpid */
    svc #0x80
    mov x1, #17                 /* SIGSTOP */
    mov x16, #37                /* kill */
    svc #0x80
4:
    wfe
    b 4b

.p2align 3
_codex_remote_context_pointer:
    .quad 0

.p2align 2
/*
 * Run thread_adopt_exception_handler from the target task, then stop the
 * traced process so the controller can restore the interrupted thread state.
 *
 * Inputs:
 *   x1  target-local hardened exception-port name
 *   x2  exception mask
 *   x3  exception behavior
 *   x4  thread-state flavor
 *   x14 mach_port_deallocate
 *   x15 mach_task_self
 *   x16 mach_thread_self
 *   x17 thread_adopt_exception_handler
 * Result retained across SIGSTOP in x25.
 */
_codex_remote_adopt_gate:
    .inst 0xd50324df             /* bti jc */
    mov x19, x1
    mov x20, x2
    mov x21, x3
    mov x22, x4
    mov x23, x17
    mov x26, x15
    mov x27, x14
    blr x16                     /* mach_thread_self() */
    mov x24, x0
    mov x1, x19
    mov x2, x20
    mov x3, x21
    mov x4, x22
    blr x23                     /* thread_adopt_exception_handler(...) */
    mov x25, x0
    blr x26                     /* mach_task_self() */
    mov x1, x24
    blr x27                     /* mach_port_deallocate(task, thread) */
    mov x16, #20                /* getpid */
    svc #0x80
    mov x1, #17                 /* SIGSTOP */
    mov x16, #37                /* kill */
    svc #0x80
1:
    wfe
    b 1b

.p2align 2
_codex_remote_mmap_hook:
    .inst 0xd50324df             /* bti jc */
    stp x29, x30, [sp, #-80]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    mov x29, sp
    mov x19, x0                 /* requested address */
    mov x20, x1                 /* length */
    mov w21, w2                 /* protection */
    mov w22, w3                 /* flags */
    mov w23, w4                 /* descriptor */
    mov x24, x5                 /* file offset */

    mov x16, #197               /* mmap */
    svc #0x80
    b.cc 9f

    tbnz w23, #31, 8f           /* descriptor < 0 */
    tbz w21, #2, 8f             /* !PROT_EXEC */
    mov x0, x19
    mov x1, x20
    mov w2, #3                  /* PROT_READ | PROT_WRITE */
    mov w3, #0x1002             /* MAP_ANON | MAP_PRIVATE */
    tbz w22, #4, 4f             /* MAP_FIXED */
    orr w3, w3, #0x10
4:
    mov w4, #-1
    mov x5, #0
    mov x16, #197
    svc #0x80
    b.cs 8f
    mov x25, x0                 /* anonymous mapping */
    mov x26, #0                 /* copied */
5:
    cmp x26, x20
    b.hs 6f
    mov w0, w23
    add x1, x25, x26
    sub x2, x20, x26
    add x3, x24, x26
    mov x16, #153               /* pread */
    svc #0x80
    b.cs 7f
    cbz x0, 6f
    add x26, x26, x0
    b 5b
6:
    mov x0, x25
    mov x1, x20
    mov w2, w21
    mov x16, #74                /* mprotect */
    svc #0x80
    b.cs 7f
    mov x0, x25
    b 9f
7:
    mov x0, x25
    mov x1, x20
    mov x16, #73                /* munmap */
    svc #0x80
8:
    mov x0, #-1
9:
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret

.p2align 2
_codex_remote_fcntl_hook:
    .inst 0xd50324df             /* bti jc */
    cmp w1, #97                 /* F_ADDFILESIGS_RETURN */
    b.eq 10f
    cmp w1, #98                 /* F_CHECK_LV */
    b.eq 11f
    mov x16, #92                /* fcntl */
    svc #0x80
    b.cc 12f
    mov x0, #-1
    ret
10:
    cbz x2, 11f
    mov x3, #-1
    str x3, [x2]                /* fs_file_start = -1 */
11:
    mov x0, #0
12:
    ret

.p2align 3
_codex_remote_blob_end:
