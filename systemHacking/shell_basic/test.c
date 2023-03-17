#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(void)
{
    int fd=open("/home/shell_basic/flag_name_is_loooooong", O_RDONLY);
    //int fd=open("test.c", O_RDONLY);
    char buf[0x50];
    read(fd, buf, 0x50);
    printf("%s", buf);
    //system("cat /home/shell_basic/flag_name_is_loooooong");
}