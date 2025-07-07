#include <stdio.h>
#include <unistd.h>

typedef struct _astruct {
    int a;
    unsigned long b;
    float c;
    char d;
} astruct;

struct secondstruct {
    astruct haha;
};

static astruct some_global_var = {
    .a = -123,
    .b = 123,
    .c = 3.14,
    .d = 'd',
};

__attribute__((noinline)) int foo(int x, float b) {
    printf("the value of x is %d\n", x);
    printf("the value of b is %.2f\n", b);
    some_global_var.a += 20;
    return x;
}

int main(int argc, char** argv) {
    printf("this is a test program");
    int x = 0;
    usleep(500);
    for (int i = 0; i < 10; i++) {
        foo(1, 2.7);
        x = foo(2, 3.14);
    }
    return x;
}

