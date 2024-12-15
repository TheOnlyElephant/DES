#include <stdio.h>
int main() {
    int a = 0x10100010;
    int b = 0x00010010;

    printf("result = %x\n", a^b);
    return 0;
}