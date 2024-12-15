#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>


// 两个本源多项式最高都是4次的，所以寄存器的位数也是4位，分别代表x^4 x^3 x^2 x^1
#define LFSR_BITS 4
#define DATA_SIZE 16

// 第一个多项式，g1(x) = x^4 + x + 1 对应的反馈位
// 将最高位（代表x^4）提取出来与最低位（代表x^1）异或，然后循环左移一位
uint32_t feedback1(uint32_t state) {
    uint32_t bit = ((state >> 3) ^ (state >> 0)) & 1;
    return(state << 1) | bit ;
}

// // 第二个多项式，g2(x) = x^4 + x^3 + 1 对应的反馈位
// // 将最高位（代表x^4）提取出来与次高位（代表x^3）异或，然后循环左移一位
// uint32_t feedback2(uint32_t state) {
//     uint32_t bit = ((state >> 3) ^ (state >> 2)) & 1;
//     return (state << 1) | bit ;
// }

// // 状态跃迁
// void print_binary(uint32_t value, int bits) {
//     for (int i = bits - 1; i >= 0; i--) {
//         printf("%d", (value >> i) & 1);
//     }
// }

// void LFSR(uint32_t (*feedback_func)(uint32_t), uint32_t seed, int rounds) {
//     uint32_t state = seed;
//     uint32_t output_bits = 0;
//     printf("初始状态: ");
//     print_binary(state, LFSR_BITS);
//     printf("\n");

//     for (int i = 0; i < rounds; i++) {
//         uint32_t output_bit = state  & 1; // 输出最低位
        
//         state = feedback_func(state);
//         output_bits = (output_bits << 1) | output_bit; // 逆序存储输出比特

//         printf("第 %2d 次输出: 输出 bit = %u, 当前寄存器状态 = ", i + 1, output_bit);
//         print_binary(state, LFSR_BITS);
//         printf("\n");
//     }

//     printf("输出比特流为(逆序):");
//     for(int i = 0; i < 16; i++) {
//         printf("%u", output_bits&1);
//         output_bits >>= 1;
//     }
//     printf("\n");
// }

// int test() {
//     uint32_t seed = 0xF;    // 初始的种子，0b1111
//     int rounds = 16;        // 输出的轮次数，统一输出15，展现是否为m序列

//     printf("使用 g1(x) = x^4 + x + 1 的 LFSR:\n");
//     LFSR(feedback1, seed, rounds);

//     printf("\n使用 g2(x) = x^4 + x^3 + 1 的 LFSR:\n");
//     LFSR(feedback2, seed, rounds);

//     return 0;
// }


// 生成LFSR比特流
void LFSR_stream(uint32_t (*feedback_func)(uint32_t), uint32_t seed, uint8_t *stream, int bits) {
    uint32_t state = seed;
    for (int i = 0; i < bits; i++) {
        stream[i / 8] = (stream[i / 8] << 1) | (state & 1);
        state = feedback_func(state); 
    }
}

void print_hex(const char *label, uint8_t *data, int size) {
    printf("%s ", label);
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void xor(uint8_t *data, uint8_t *key_stream, uint8_t *output, int size) {
    for (int i = 0; i < size; i++) {
        output[i] = data[i] ^ key_stream[i];
    }
}

int main() {
    uint8_t data[DATA_SIZE], key_stream[DATA_SIZE] = {0}, cipher[DATA_SIZE] = {0}, decrypted[DATA_SIZE] = {0};
    uint32_t seed = 0xF; // 初始种子设置
    srand(time(NULL));

    // 以16位为一个块随机生成128-bit数据
    for (int i = 0; i < DATA_SIZE; i++) {
        data[i] = rand() % 256;
    }

    // 使用LFSR生成128-bit比特流
    LFSR_stream(feedback1, seed, key_stream, DATA_SIZE * 8);

    // 将原始数据与LFSR生成的比特流异或进行加密
    xor(data, key_stream, cipher, DATA_SIZE);

    // 将密文与LFSR生成的比特流再次异或进行解密
    xor(cipher, key_stream, decrypted, DATA_SIZE);

    // 输出结果进行比对
    printf(">> Performing correctness test...\n");
    print_hex("Original plaintext:\n", data, DATA_SIZE);
    print_hex("LFSR bitstream:\n", key_stream, DATA_SIZE);
    print_hex("Encrypted ciphertext:\n", cipher, DATA_SIZE);
    print_hex("Decrypted plaintext:\n", decrypted, DATA_SIZE);
    if(memcmp(data, decrypted, DATA_SIZE) == 0) {
        printf(">> Correctness test passed.\n");
    } else {
        printf(">> Correctness test failed.\n");
    }

    return 0;
}
