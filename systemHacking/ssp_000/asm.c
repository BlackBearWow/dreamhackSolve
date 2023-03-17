// gcc -o asm.out asm.c -masm=intel
__asm__(
    ".global run_sh\n"
    "run_sh:\n"
    "callq 0x004008EA\n"
);
void run_sh();
int main() { run_sh(); }