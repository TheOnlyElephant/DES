#include "zuc.h"
#include <stdio.h>
#include <string.h>

#define ZUC_LFSR_SIZE 16      /* LFSR寄存器数 */
#define ZUC_F_R1 0x7FFFFFFF   /* F函数中的常量 */
#define ZUC_F_R2 0x3FFFFFFF   /* F函数中的常量 */

/* ZUC 内部状态 */
typedef struct {
    uint32_t LFSR[ZUC_LFSR_SIZE]; /* 16个LFSR寄存器 */
    uint32_t R1, R2;             /* F函数中的内部寄存器 */
    uint32_t X[4];               /* 线性合成模块的输出 */
} ZUC_State;

/* 密钥装载常量 */
static const uint16_t D[16] = {
    0x44D, 0x32C, 0x22B, 0x11A, 0x019, 0x98E, 0x89D, 0x76C,
    0x65B, 0x54A, 0x439, 0x328, 0x217, 0x106, 0xF15, 0xE24
};

/* 循环左移宏定义 */
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/**
 * @brief 初始化 LFSR
 */
static void LFSR_init(ZUC_State *state, const uint8_t *key, const uint8_t *iv) {
    for (int i = 0; i < ZUC_LFSR_SIZE; i++) {
        state->LFSR[i] = ((uint32_t)key[i] << 23) |
                         ((uint32_t)(D[i] & 0x7FFF) << 8) | // 处理15位的D
                         ((uint32_t)iv[i]);
    }
    state->R1 = 0;
    state->R2 = 0;
}

/**
 * @brief LFSR 工作模式
 */
static void LFSR_work(ZUC_State *state) {
    uint32_t v = (state->LFSR[0] << 8) +
                 (state->LFSR[2] >> 8) +
                 (state->LFSR[11] >> 8) +
                 state->LFSR[15];
    v = (v & ZUC_F_R1) + (v >> 31); /* 模 2^31-1 */
    for (int i = 0; i < ZUC_LFSR_SIZE - 1; i++) {
        state->LFSR[i] = state->LFSR[i + 1];
    }
    state->LFSR[ZUC_LFSR_SIZE - 1] = v & ZUC_F_R1;
}

/**
 * @brief 比特重组
 */
static void bit_reorganization(ZUC_State *state) {
    state->X[0] = ((state->LFSR[15] & 0x7FFF8000) << 1) | (state->LFSR[14] & 0xFFFF);
    state->X[1] = ((state->LFSR[11] & 0xFFFF) << 16) | (state->LFSR[9] >> 15);
    state->X[2] = ((state->LFSR[7] & 0xFFFF) << 16) | (state->LFSR[5] >> 15);
    state->X[3] = ((state->LFSR[2] & 0xFFFF) << 16) | (state->LFSR[0] >> 15);
}

/**
 * @brief F 函数
 */
static uint32_t F(ZUC_State *state) {
    uint32_t W = (state->X[0] ^ state->R1) + state->R2;
    uint32_t W1 = state->R1 + state->X[1];
    uint32_t W2 = state->R2 ^ state->X[2];
    state->R1 = ROTL(W1, 16);
    state->R2 = ROTL(W2, 8);
    return W;
}

/**
 * @brief 初始化 ZUC
 */
int zuc_initialize(const uint8_t key[ZUC_KEY_SIZE], const uint8_t iv[ZUC_IV_SIZE], void *state) {
    if (!key || !iv || !state) return 1;

    ZUC_State *zuc_state = (ZUC_State *)state;
    LFSR_init(zuc_state, key, iv);

    for (int i = 0; i < 32; i++) {
        bit_reorganization(zuc_state);
        F(zuc_state);
        LFSR_work(zuc_state);
    }
    return 0;
}

/**
 * @brief 生成密钥流
 */
int zuc_generate_keystream(void *state, uint8_t *keystream, size_t length) {
    if (!state || !keystream) return 1;

    ZUC_State *zuc_state = (ZUC_State *)state;
    for (size_t i = 0; i < length; i++) {
        bit_reorganization(zuc_state);
        uint32_t keystream_word = F(zuc_state);
        LFSR_work(zuc_state);
        keystream[i] = keystream_word & 0xFF; /* 取最低8位 */
    }
    return 0;
}

/**
 * @brief 加密/解密操作
 */
void zuc_crypt(const uint8_t *input, size_t length, const uint8_t *keystream, uint8_t *output) {
    for (size_t i = 0; i < length; i++) {
        output[i] = input[i] ^ keystream[i]; /* 输入与密钥流异或 */
    }
}

void print_bytes(const unsigned char *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main() {
    uint8_t key[ZUC_KEY_SIZE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t iv[ZUC_IV_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    uint8_t plaintext[16] =  {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t correctResult[16] =  {0xB7, 0x0D, 0xC5, 0xD5, 0xAB, 0x51, 0x95, 0xFC, 0xE5, 0xE9, 0x21, 0xF5, 0xF6, 0x91, 0xBC, 0x76};
    
    size_t length = sizeof(plaintext); // 使用sizeof获取长度
    uint8_t keystream[length];
    uint8_t ciphertext[length];
    uint8_t decrypted[length];
    
    ZUC_State state;

    printf(">> Performing correctness test...\n");

    printf("Original plaintext: ");
    print_bytes(plaintext, length);
    

    printf("Correct ciperthext: ");
    print_bytes(correctResult, length);


    // 初始化ZUC
    zuc_initialize(key, iv, &state);

    // 生成密钥流
    zuc_generate_keystream(&state, keystream, length);


    // printf("keystream: ");
    // print_bytes(keystream, length);

    // 加密
    zuc_crypt(plaintext, length, keystream, ciphertext);

    printf("Encrypted ciphertext: ");
    print_bytes(ciphertext, length);

    // 重新初始化ZUC
    zuc_initialize(key, iv, &state);

    // 生成密钥流
    zuc_generate_keystream(&state, keystream, length);

    // 解密
    zuc_crypt(ciphertext, length, keystream, decrypted);

    printf("Decrypted plaintext: ");
    print_bytes(decrypted, length);

    // 检查解密结果是否与原始明文相同
    if (memcmp(plaintext, decrypted, length) == 0) {
        printf(">> Correctness test passed.\n\n");
    } else {
        printf(">> Correctness test failed.\n\n");
    }
    return 0;
}