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
        uint64_t subkey = permute(combined, 56, PC2, 48);

        // 将生成的 48 位子密钥存储到子密钥数组
        for (int j = 0; j < 6; j++) {
            subKeys[i][j] = (subkey >> (40 - 8 * j)) & 0xFF;
        }
    }

    // // 调试打印生成的子密钥
    // for (int i = 0; i < 16; i++) {
    //     printf("Subkey %d: ", i + 1);
    //     for (int j = 0; j < 6; j++) {
    //         printf("%02X ", subKeys[i][j]);
    //     }
    //     printf("\n");
    // }

    return 0; // 返回成功
}

// Feistel 函数
static uint32_t feistel(uint32_t right, const unsigned char *subKey) {
    uint64_t expanded = 0;

    // 第一步：扩展置换，将 32 位扩展到 48 位
    expanded = permute((uint64_t)right << 32, 64, E, 48);
    // printf("Expanded: %012llX\n", expanded);

    // 第二步：与子密钥异或
    for (int i = 0; i < 6; i++) {
        expanded ^= ((uint64_t)subKey[i] << (40 - 8 * i));
        // printf("After XOR: %012llX\n", expanded);
    }

    // 第三步：使用 S_P_COMBINED 查找表
    uint32_t substituted = 0;
    for (int i = 0; i < 8; i++) {
        // 提取每 6 位作为索引
        int index = (expanded >> (42 - 6 * i)) & 0x3F;
        // 从查找表中获取对应的值
        substituted |= S_P_COMBINED[i][index] << (28 - 4 * i);
    }
    // printf("Substituted: %08X\n", substituted);

    // 第四步：返回结果，P 置换已包含在查找表中
    return substituted;
}

// DES 加密函数
void des_encrypt_block(const unsigned char *input, unsigned char subKeys[16][6], unsigned char *output) {
    // 将输入字节转换为 64 位块
    uint64_t block = 0;
    for (int i = 0; i < 8; i++) {
        block |= ((uint64_t)input[i] << (56 - 8 * i));
    }

    // 初始置换
    uint64_t permuted = permute(block, 64, IP, 64);

    // 分割为左、右 32 位
    uint32_t left, right;
    SPLIT_BLOCK(permuted, left, right);

    // 16 轮迭代
    for (int i = 0; i < 16; i++) {
        uint32_t temp = right;
        uint32_t feistel_result = feistel(right, subKeys[i]);
        right = left ^ feistel_result;
        left = temp;
    }

    // 合并并交换左右部分
    uint64_t preoutput = COMBINE_BLOCK(right, left);

    // 逆初始置换
    uint64_t final_output = permute(preoutput, 64, IP_INV, 64);

    // 输出结果转换为字节
    for (int i = 0; i < 8; i++) {
        output[i] = (final_output >> (56 - 8 * i)) & 0xFF;
    }
}

// DES 解密函数
void des_decrypt_block(const unsigned char *input, unsigned char subKeys[16][6], unsigned char *output) {
    // 将输入字节转换为 64 位块
    uint64_t block = 0;
    for (int i = 0; i < 8; i++) {
        block |= ((uint64_t)input[i] << (56 - 8 * i));
    }

    // 初始置换
    uint64_t permuted = permute(block, 64, IP, 64);

    // 分割为左、右 32 位
    uint32_t left, right;
    SPLIT_BLOCK(permuted, left, right);

    // 16 轮迭代（子密钥顺序相反）
    for (int i = 15; i >= 0; i--) {
        uint32_t temp = right;
        uint32_t feistel_result = feistel(right, subKeys[i]);
        right = left ^ feistel_result;
        left = temp;
    }

    // 合并并交换左右部分
    uint64_t preoutput = COMBINE_BLOCK(right, left);

    // 逆初始置换
    uint64_t final_output = permute(preoutput, 64, IP_INV, 64);

    // 输出结果转换为字节
    for (int i = 0; i < 8; i++) {
        output[i] = (final_output >> (56 - 8 * i)) & 0xFF;
    }
}