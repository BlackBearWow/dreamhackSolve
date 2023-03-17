#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main()
{
    int fd = open("save", O_RDONLY);
    char buf;
    int k;
    while(1)
    {
        k = read(fd, &buf, 1);
        if(k != 1)
            break;
        if((buf!=' ')&&(buf!='\n'))
            printf("%c", buf);
    }
    puts("");
}