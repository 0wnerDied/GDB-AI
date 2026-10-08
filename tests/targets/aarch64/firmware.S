.global _start
.global checkpoint
.text
.type _start, %function
_start:
    mov x0, #41
    add x0, x0, #1
.type checkpoint, %function
checkpoint:
    b checkpoint
