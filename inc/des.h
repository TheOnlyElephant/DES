#include <stdint.h>
#include <string.h>

#ifndef DES_H
#define DES_H

#ifdef __cplusplus
extern "C" {
#endif

#define DES_BLOCK_BITS 64  /* bits of DES algoithm block */
#define DES_BLOCK_SIZE 8  /* bytes of DES algoithm block */
#define DES_KEY_SIZE 8 /* bytes of DES algoithm double key */

    /**
     * @brief Generate subkeys
     * @param[in] key original key
     * @param[out] subKeys generated subkeys
     * @return 0 OK
     * @return 1 Failed
     */
    int des_make_subkeys(const unsigned char key[8], unsigned char subKeys[16][6]);

    /**
     * @brief DES encrypt single block
     * @param[in] input plaintext, [length = DES_BLOCK_SIZE]
     * @param[in] subKeys subKeys
     * @param[out] output ciphertext, [length = DES_BLOCK_SIZE]
     */
    void des_encrypt_block(const unsigned char *input, unsigned char subKeys[16][6], unsigned char *output);

    /**
     * @brief DES decrypt single block
     * @param[in] input ciphertext, [length = DES_BLOCK_SIZE]
     * @param[in] subKeys subKeys
     * @param[out] output plaintext, [length = DES_BLOCK_SIZE]
     */
    void des_decrypt_block(const unsigned char *input, unsigned char subKeys[16][6], unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif // DES_H

// Tables used for DES key scheduling and encryption/decryption
static const int PC1[56] = {
    57, 49, 41, 33, 25, 17,  9, 
     1, 58, 50, 42, 34, 26, 18, 
    10,  2, 59, 51, 43, 35, 27, 
    19, 11,  3, 60, 52, 44, 36, 
    63, 55, 47, 39, 31, 23, 15, 
     7, 62, 54, 46, 38, 30, 22, 
    14,  6, 61, 53, 45, 37, 29, 
    21, 13,  5, 28, 20, 12,  4
};

static const int PC2[48] = {
    14, 17, 11, 24,  1,  5, 
     3, 28, 15,  6, 21, 10, 
    23, 19, 12,  4, 26,  8, 
    16,  7, 27, 20, 13,  2, 
    41, 52, 31, 37, 47, 55, 
    30, 40, 51, 45, 33, 48, 
    44, 49, 39, 56, 34, 53, 
    46, 42, 50, 36, 29, 32
};

static const int rotations[16] = { 
    1, 1, 2, 2, 2, 2, 2, 2, 
    1, 2, 2, 2, 2, 2, 2, 1 
};

// DES permutation tables
static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static const int IP_INV[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

static const int E[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// S-Boxes
static const int S[8][4][16] = {
    {
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    // Repeat this for all 8 S-Boxes...
};

// P permutation table (used in the Feistel function)
static const int P[32] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

// Helper function: Permutation
static void permute(const unsigned char *input, unsigned char *output, const int *table, int n) {
    // 将输入字节数组转换为 64 位整数
    uint64_t in = 0;
    for (int i = 0; i < 8; i++) {
        in = (in << 8) | input[i];
    }

    uint64_t out = 0;

    // 使用位运算进行置换
    for (int i = 0; i < n; i++) {
        int from = table[i] - 1;
        uint64_t bit = (in >> (63 - from)) & 1ULL;
        out |= bit << (n - i - 1);
    }

    // 将结果转换回字节数组
    for (int i = 0; i < n / 8; i++) {
        output[i] = (out >> ((n / 8 - 1 - i) * 8)) & 0xFF;
    }
}

// Helper function: Left rotate
static void rotate_left(unsigned char *key, int n, int bits) {
    unsigned char temp = 0;
    for (int i = 0; i < bits; i++) {
        temp = (key[0] >> 7) & 1; // Save the leftmost bit
        for (int j = 0; j < n; j++) {
            key[j] = (key[j] << 1) | ((key[j + 1] >> 7) & 1);
        }
        key[n - 1] = (key[n - 1] << 1) | temp; // Restore the saved bit
    }
}
