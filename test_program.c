#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) int foo(int x, float b) {
    printf("the value of x is %d\n", x);
    printf("the value of b is %.2f\n", b);
    return 0;
}

int main(int argc, char* argv[]) {
    printf("this is a test program");
    while(1) {
        foo(1, 2.7);
        sleep(1);
        foo(2, 3.14);
        usleep(5000);
    }
}

