//Name: cdecl.c
//Compile: gcc -fno-asynchronous-unwind-tables -nostdlib -masm=intel \
//	   -fomit-frame-pointer -S cdecl.c -w -m32 -fno-pic -00
void __attribute((cdecl)) callee(int a1, int a2)
{
}

void caller()
{
	callee(1, 2);
}
