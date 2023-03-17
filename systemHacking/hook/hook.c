// gcc -o init_fini_array init_fini_array.c -Wl,-z,norelro
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int main(int argc, char *argv[]) {
    long *ptr;
    size_t size;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("Size: ");
    scanf("%ld", &size);

    ptr = malloc(size);

    printf("Data: ");
    read(0, ptr, size);

    *(long *)*ptr = *(ptr+1);
    //ptr의 값에 해당되는 주소에 ptr+1의 값을 넣는다.
    //*ptr=__free_hook의 주소, ptr+1에 system의 주소를 넣으면?
    free(ptr);
    free(ptr);

    system("/bin/sh");
    return 0;
}
