        .global _start
        .text
_start:
        mov     $0, %rbx
        jmp     L1   # [y]
        jmp     L1   # [n]
        inc     %rcx # dummy
L1:
        xor     %rax, %rax
        jz      L2   # [n y]
        jz      L2   # [n n]
        inc     %rcx # dummy
L2:
        xor     %rax, %rax
        jnz     L3   # [y n]
        inc     %rcx # dummy
L3:
        cmp     $3, %rbx
        jg      L4   # [y y] if rbx > 3
        inc     %rbx
        jmp     L3
L4:
        # exit(0)
        mov     $60, %rax
        xor     %rdi, %rdi
        syscall
