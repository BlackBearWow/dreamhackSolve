	.file	"cdecl.c"
	.intel_syntax noprefix
	.text
	.globl	callee
	.type	callee, @function
callee:
	endbr32
	nop
	ret
	.size	callee, .-callee
	.globl	caller
	.type	caller, @function
caller:
	endbr32
	push	2
	push	1
	call	callee
	add	esp, 8
	nop
	ret
	.size	caller, .-caller
	.ident	"GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 4
	.long	 1f - 0f
	.long	 4f - 1f
	.long	 5
0:
	.string	 "GNU"
1:
	.align 4
	.long	 0xc0000002
	.long	 3f - 2f
2:
	.long	 0x3
3:
	.align 4
4:
