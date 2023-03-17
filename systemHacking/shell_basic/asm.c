__asm__(
    ".global run_sh\n"
    "run_sh:\n"
    "push 0x00\n"
    "mov rax, 0x676E6F6F6F6F6F6F\n"
    "push rax\n"
    "mov rax, 0x6C5F73695F656D61\n"
    "push rax\n"
    "mov rax, 0x6E5F67616C662F63\n"
    "push rax\n"
    "mov rax, 0x697361625F6C6C65\n"
    "push rax\n"
    "mov rax, 0x68732F656D6F682F\n"
    "push rax\n"
    "mov rdi, 1     # rdi = 1 ; fd = stdout\n"
    "mov rsi, rsp   # rsi = '/tmp/flag'\n"
    "mov rdx, 0x28   # rdx = \n"
    "mov rax, 1     # rax = 1 ; syscall_write\n"
    "syscall        # write(1, *buf, count)\n"
    "\n"
    "xor rdi, rdi      # rdi = 0\n"
    "mov rax, 0x3c	   # rax = sys_exit\n"
    "syscall		   # exit(0)"
);
//676E6F6F6F6F6F6F
//6C5F73695F656D61
//6E5F67616C662F63
//697361625F6C6C65
//68732F656D6F682F
void run_sh();
//"mov rax, 0x616c662f706d742f \n"
int main() { run_sh(); }