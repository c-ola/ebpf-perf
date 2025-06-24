#include <stdio.h>
#include <unistd.h>

static int some_global_var = 5;

__attribute__((noinline)) int foo(int x, float b) {
    printf("the value of x is %d\n", x);
    printf("the value of b is %.2f\n", b);
    some_global_var += 1;
    return x;
}

int main() {
    printf("this is a test program");
    int x = 0;
    usleep(500);
    for (int i = 0; i < 1; i++) {
        foo(1, 2.7);
        //x = foo(2, 3.14);
    }
    return x;
}

