// Name: addr.c
// Compile: gcc addr.c -o addr -ldl -no-pie -fno-PIE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
    char buf_stack[0x10];
    char *buf_heap = (char *)malloc(0x10);

    printf("buf_stack addr: %p\n", buf_stack);
    printf("buf_heap addr: %p\n", buf_heap);
    printf("libc_base addr: %p\n", *(void **)dlopen("libc.so.6", RTLD_LAZY));

    printf("printf addr: %p\n", dlsym(dlopen("libc.so.6", RTLD_LAZY), "printf"));
    printf("main addr : %p\n", main);

    printf("dis= %p\n", *(void **)dlopen("libc.so.6", RTLD_LAZY) - dlsym(dlopen("libc.so.6", RTLD_LAZY), "printf"));
}