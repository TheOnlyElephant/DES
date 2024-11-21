#include "../inc/des.h"
#include <string.h>


int des_make_subkeys(const unsigned char key[8], unsigned char subKeys[16][6]) {
    // 将输入的 8 字节密钥转换为 64 位整型
    uint64_t key64 = 0;
    for (int i = 0; i < 8; i++) {
        key64 |= ((uint64_t)key[i] << (56 - 8 * i));
    }

    // 应用 PC1 置换，将 64 位密钥压缩到 56 位
    uint64_t permuted_key = permute_64(key64, PC1, 56);

    // 分离左 28 位和右 28 位
    uint32_t left = (permuted_key >> 28) & 0xFFFFFFF;  // 取高 28 位
    uint32_t right = permuted_key & 0xFFFFFFF;         // 取低 28 位

    // 生成 16 个子密钥
    for (int i = 0; i < 16; i++) {
        // 左右部分分别循环左移
        left = ((left << rotations[i]) | (left >> (28 - rotations[i]))) & 0xFFFFFFF;
        right = ((right << rotations[i]) | (right >> (28 - rotations[i]))) & 0xFFFFFFF;

        // 合并左右部分为 56 位
        uint64_t combined = ((uint64_t)left << 28) | (uint64_t)right;

        // 应用 PC2 置换，将 56 位压缩到 48 位
        uint64_t subkey = permute_64(combined, PC2, 48);

        // 将生成的 48 位子密钥存储到子密钥数组
        for (int j = 0; j < 6; j++) {
            subKeys[i][j] = (subkey >> (40 - 8 * j)) & 0xFF;
        }
    }

    return 0; // 返回成功
}

// Feistel 函数
static uint32_t feistel(uint32_t right, const unsigned char *subKey) {
    uint64_t expanded = 0;

    // Step 1: 扩展置换，将 32 位扩展到 48 位
    expanded = permute_64((uint64_t)right << 32, E, 48);

    // Step 2: 与子密钥异或
    for (int i = 0; i < 6; i++) {
        expanded ^= ((uint64_t)subKey[i] << (40 - 8 * i));
    }

    // Step 3: 使用 S_P_COMBINED 查找表
    uint32_t substituted = 0;
    for (int i = 0; i < 8; i++) {
        // 提取每 6 位作为索引
        int index = (expanded >> (42 - 6 * i)) & 0x3F;
        // 从查找表中获取对应的值
        substituted |= S_P_COMBINED[i][index] << (28 - 4 * i);
    }

    // Step 4: 返回结果，P 置换已包含在查找表中
    return substituted;
}

// Helper function to split a 64-bit block into two 32-bit halves
#define SPLIT_BLOCK(block, left, right) \
    left = (block >> 32) & 0xFFFFFFFF; \
    right = block & 0xFFFFFFFF;

// Helper function to combine two 32-bit halves into a 64-bit block
#define COMBINE_BLOCK(left, right) (((uint64_t)(left) << 32) | (uint64_t)(right))

// DES Encryption
void des_encrypt_block(const unsigned char *input, unsigned char subKeys[16][6], unsigned char *output) {
    // Convert input bytes into a 64-bit block
    uint64_t block = 0;
    for (int i = 0; i < 8; i++) {
        block |= ((uint64_t)input[i] << (56 - 8 * i));
    }

    // Initial permutation
    uint64_t permuted = permute_64(block, IP, 64);  // Ensure IP and 64 are passed correctly

    // Split into left and right halves
    uint32_t left, right;
    SPLIT_BLOCK(permuted, left, right);

    // 16 rounds of DES
    for (int i = 0; i < 16; i++) {
        uint32_t temp = right;
        uint32_t feistel_result = feistel(right, subKeys[i]);
        right = left ^ feistel_result;
        left = temp;
    }

    // Combine halves with swapped order
    uint64_t preoutput = COMBINE_BLOCK(right, left);

    // Final permutation
    uint64_t final_output = permute_64(preoutput, IP_INV, 64);  // Fix: Include 64 as third argument

    // Convert the 64-bit block into output bytes
    for (int i = 0; i < 8; i++) {
        output[i] = (final_output >> (56 - 8 * i)) & 0xFF;
    }
}

// DES Decryption
void des_decrypt_block(const unsigned char *input, unsigned char subKeys[16][6], unsigned char *output) {
    // Convert input bytes into a 64-bit block
    uint64_t block = 0;
    for (int i = 0; i < 8; i++) {
        block |= ((uint64_t)input[i] << (56 - 8 * i));
    }

    // Initial permutation
    uint64_t permuted = permute_64(block, IP, 64);  // Ensure IP and 64 are passed correctly

    // Split into left and right halves
    uint32_t left, right;
    SPLIT_BLOCK(permuted, left, right);

    // 16 rounds of DES (subKeys used in reverse order)
    for (int i = 15; i >= 0; i--) {
        uint32_t temp = right;
        uint32_t feistel_result = feistel(right, subKeys[i]);
        right = left ^ feistel_result;
        left = temp;
    }

    // Combine halves with swapped order
    uint64_t preoutput = COMBINE_BLOCK(right, left);

    // Final permutation
    uint64_t final_output = permute_64(preoutput, IP_INV, 64);  // Fix: Include 64 as third argument

    // Convert the 64-bit block into output bytes
    for (int i = 0; i < 8; i++) {
        output[i] = (final_output >> (56 - 8 * i)) & 0xFF;
    }
}
