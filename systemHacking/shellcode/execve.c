//compile: gcc -o execve execve.c -masm=intel

__asm__(
	".global run_sh\n"
	"run_sh:\n"

	"mov rax, 0x68732F6E69622F\n"
	"push rax\n"
	"mov rdi, rsp\n"
	"xor rsi, rsi\n"
	"xor rdx, rdx\n"
	"mov rax, 0x3b\n"
	"syscall");

void run_sh();

int main() { run_sh(); }
