#include <stdio.h>

int main()
{
    long addr=12;
    long value=13;
    *(long *)addr = value;
    printf("%ld \n", addr);
    printf("%ld \n", value);
    return 0;
}