#include "zuc.h"
#include <stdio.h>
#include <string.h>

void test_zuc() {
    uint8_t key[ZUC_KEY_SIZE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t iv[ZUC_IV_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t plaintext[] = "Hello, ZUC!";
    size_t length = strlen((char *)plaintext);
    uint8_t keystream[length];
    uint8_t ciphertext[length];
    uint8_t decrypted[length];
    ZUC_State state;

    // 初始化ZUC
    zuc_initialize(key, iv, &state);

    // 生成密钥流
    zuc_generate_keystream(&state, keystream, length);

    // 加密
    zuc_crypt(plaintext, length, keystream, ciphertext);

    // 重新初始化ZUC
    zuc_initialize(key, iv, &state);

    // 生成密钥流
    zuc_generate_keystream(&state, keystream, length);

    // 解密
    zuc_crypt(ciphertext, length, keystream, decrypted);

    // 检查解密结果是否与原始明文相同
    if (memcmp(plaintext, decrypted, length) == 0) {
        printf("ZUC加解密测试通过！\n");
    } else {
        printf("ZUC加解密测试失败！\n");
    }
}

int main() {
    test_zuc();
    return 0;
}