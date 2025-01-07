#include "../inc/aes.h"
#include <string.h>
#include <stdio.h>

int aes_make_enc_subkeys(const unsigned char key[AES_KEY_SIZE], unsigned char subKeys[AES_EXPANDED_KEY_BLOCK][AES_BLOCK_SIZE]) {
    unsigned int i, j;
    unsigned char temp[4];
    unsigned char expandedKey[AES_EXPANDED_KEY_SIZE];

    // 前16字节是原始密钥
    memcpy(expandedKey, key, AES_KEY_SIZE);

    // 生成其余的密钥
    for (i = AES_KEY_SIZE; i < AES_EXPANDED_KEY_SIZE; i += 4) {
        // temp = W[I-1]
        for (j = 0; j < 4; j++) {
            temp[j] = expandedKey[(i - 4) + j];
        }

        // I = Nk的整数倍
        if (i % AES_KEY_SIZE == 0) {
            // 轮常量
            unsigned char k = temp[0];
            temp[0] = S_BOX[temp[1]] ^ RCON[i / AES_KEY_SIZE];
            temp[1] = S_BOX[temp[2]];
            temp[2] = S_BOX[temp[3]];
            temp[3] = S_BOX[k];
        }

        for (j = 0; j < 4; j++) {
            expandedKey[i + j] = expandedKey[(i - AES_KEY_SIZE) + j] ^ temp[j];
        }
    }

    for(int i = 0; i < 11; i++) {
        memcpy(subKeys[i], expandedKey + i * 16, AES_BLOCK_SIZE);
    }

    // // 调试输出
    // for(int i = 0; i < 11; i++) {
    //     for(int j = 0; j < 16; j++) {
    //         printf("%02x ", subKeys[i][j]);
    //     }
    //     printf("\n");
    // }

    return 0;
}

int aes_make_dec_subkeys(const unsigned char key[AES_KEY_SIZE], unsigned char subKeys[AES_EXPANDED_KEY_BLOCK][AES_BLOCK_SIZE]) {
    unsigned int i, j;
    unsigned char temp[4];
    unsigned char expandedKey[AES_EXPANDED_KEY_SIZE];

    // 前16字节是原始密钥
    memcpy(expandedKey, key, AES_KEY_SIZE);

    // 生成加密的扩展密钥
    for (i = AES_KEY_SIZE; i < AES_EXPANDED_KEY_SIZE; i += 4) {
        // temp = W[i-1]
        for (j = 0; j < 4; j++) {
            temp[j] = expandedKey[(i - 4) + j];
        }

        // I 是 Nk 的整数倍
        if (i % AES_KEY_SIZE == 0) {
            // 轮常量
            unsigned char k = temp[0];
            temp[0] = S_BOX[temp[1]] ^ RCON[i / AES_KEY_SIZE];
            temp[1] = S_BOX[temp[2]];
            temp[2] = S_BOX[temp[3]];
            temp[3] = S_BOX[k];
        }

        for (j = 0; j < 4; j++) {
            expandedKey[i + j] = expandedKey[(i - AES_KEY_SIZE) + j] ^ temp[j];
        }
    }

    // 反向存储轮密钥
    for (i = 0; i < AES_EXPANDED_KEY_BLOCK; i++) {
        memcpy(subKeys[i], expandedKey + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }

    // 对解密的每个轮密钥（除第0轮和最后一轮）进行逆MixColumns变换
    uint64_t *state = (uint64_t *)subKeys; 
    for (i = 1; i < AES_EXPANDED_KEY_BLOCK - 1; i++) {
        inv_mix_columns(&state[2 * i]); 
    }

    // //  调试输出
    // for(int i = 0; i < 11; i++) {
    //     for(int j = 0; j < 16; j++) {
    //         printf("%02x ", subKeys[i][j]);
    //     }
    //     printf("\n");
    // }

    return 0;
}

void aes_encrypt_block(const unsigned char *input, unsigned char subKeys[AES_EXPANDED_KEY_BLOCK][AES_BLOCK_SIZE], unsigned char *output) {
    unsigned int state[4];
    unsigned int temp[4];
    int i, round;

    // 将输入转换为 32 位的列表示形式
    for (i = 0; i < 4; i++) {
        state[i] = ((unsigned int)input[i * 4] << 24) |
                   ((unsigned int)input[i * 4 + 1] << 16) |
                   ((unsigned int)input[i * 4 + 2] << 8) |
                   ((unsigned int)input[i * 4 + 3]);
        state[i] ^= ((unsigned int)subKeys[0][i * 4] << 24) |
                    ((unsigned int)subKeys[0][i * 4 + 1] << 16) |
                    ((unsigned int)subKeys[0][i * 4 + 2] << 8) |
                    ((unsigned int)subKeys[0][i * 4 + 3]);
    }

    // 主要加密轮数（9轮）
    for (round = 1; round < 10; round++) {
        for (i = 0; i < 4; i++) {
            temp[i] = Te0[(state[i] >> 24) & 0xFF] ^
                      Te1[(state[(i + 1) % 4] >> 16) & 0xFF] ^
                      Te2[(state[(i + 2) % 4] >> 8) & 0xFF] ^
                      Te3[state[(i + 3) % 4] & 0xFF];
            temp[i] ^= ((unsigned int)subKeys[round][i * 4] << 24) |
                       ((unsigned int)subKeys[round][i * 4 + 1] << 16) |
                       ((unsigned int)subKeys[round][i * 4 + 2] << 8) |
                       ((unsigned int)subKeys[round][i * 4 + 3]);
        }
        for (i = 0; i < 4; i++) {
            state[i] = temp[i];
        }

    }

    // 最后一轮（不进行 MixColumns）
    for (i = 0; i < 4; i++) {
        temp[i] = ((Te2[(state[i] >> 24) & 0xFF] & 0xFF000000) ^
                   (Te3[(state[(i + 1) % 4] >> 16) & 0xFF] & 0x00FF0000) ^
                   (Te0[(state[(i + 2) % 4] >> 8) & 0xFF] & 0x0000FF00) ^
                   (Te1[state[(i + 3) % 4] & 0xFF] & 0x000000FF));
        temp[i] ^= ((unsigned int)subKeys[10][i * 4] << 24) |
                   ((unsigned int)subKeys[10][i * 4 + 1] << 16) |
                   ((unsigned int)subKeys[10][i * 4 + 2] << 8) |
                   ((unsigned int)subKeys[10][i * 4 + 3]);
    }

    // 将结果转换回字节数组
    for (i = 0; i < 4; i++) {
        output[i * 4] = (temp[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (temp[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (temp[i] >> 8) & 0xFF;
        output[i * 4 + 3] = temp[i] & 0xFF;
    }
}

void aes_decrypt_block(const unsigned char *input, unsigned char subKeys[AES_EXPANDED_KEY_BLOCK][AES_BLOCK_SIZE], unsigned char *output) {
    unsigned int state[4];
    unsigned int temp[4];
    int i, round;

    // 将输入数据转换为 32 位列的表示形式，同时添加初始轮密钥
    for (i = 0; i < 4; i++) {
        state[i] = ((unsigned int)input[i * 4] << 24) |
                   ((unsigned int)input[i * 4 + 1] << 16) |
                   ((unsigned int)input[i * 4 + 2] << 8) |
                   ((unsigned int)input[i * 4 + 3]);
        state[i] ^= ((unsigned int)subKeys[10][i * 4] << 24) |
                    ((unsigned int)subKeys[10][i * 4 + 1] << 16) |
                    ((unsigned int)subKeys[10][i * 4 + 2] << 8) |
                    ((unsigned int)subKeys[10][i * 4 + 3]);
    }

    // 主要解密轮数（共 9 轮）
    for (round = 9; round > 0; round--) {
        for (i = 0; i < 4; i++) {
            temp[i] = Td0[(state[i] >> 24) & 0xFF] ^
                      Td1[(state[(i + 3) % 4] >> 16) & 0xFF] ^
                      Td2[(state[(i + 2) % 4] >> 8) & 0xFF] ^
                      Td3[state[(i + 1) % 4] & 0xFF];
            temp[i] ^= ((unsigned int)subKeys[round][i * 4] << 24) |
                       ((unsigned int)subKeys[round][i * 4 + 1] << 16) |
                       ((unsigned int)subKeys[round][i * 4 + 2] << 8) |
                       ((unsigned int)subKeys[round][i * 4 + 3]);
        }
        for (i = 0; i < 4; i++) {
            state[i] = temp[i];
        }

    }
    unsigned char state1[4][4];
    convert_uint_to_uchar(temp, state1);

    // 最后一轮
    inv_shift_rows(state1);
    inv_sub_bytes(state1);
    add_round_key(state1, subKeys[0]);

    // 输出状态矩阵
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            output[i * 4 + j] = state1[i][j];
        }
    }
}


// PKCS#7 填充函数
void pkcs7_pad(unsigned char *block, int data_len) {
    unsigned char pad_value = AES_BLOCK_SIZE - data_len;
    for (int i = data_len; i < AES_BLOCK_SIZE; i++) {
        block[i] = pad_value;
    }
}

// PKCS#7 去填充函数
int pkcs7_unpad(unsigned char *block) {
    unsigned char pad_value = block[AES_BLOCK_SIZE - 1];
    if (pad_value > AES_BLOCK_SIZE) {
        return -1; // 错误的填充数据
    }
    return AES_BLOCK_SIZE - pad_value;
}
// 加密接口函数
void aes_encrypt_file(const void *src, int bytes, unsigned char subKeys[AES_EXPANDED_KEY_BLOCK][AES_BLOCK_SIZE], void *va_dest) {
    const unsigned char *input = (const unsigned char *)src;
    unsigned char *dest = (unsigned char *)va_dest;

    int offset = 0;
    while (offset < bytes) {
        unsigned char block_in[AES_BLOCK_SIZE] = {0};
        unsigned char block_out[AES_BLOCK_SIZE] = {0};

        int remaining = bytes - offset;
        int to_process = remaining < AES_BLOCK_SIZE ? remaining : AES_BLOCK_SIZE;

        memcpy(block_in, input + offset, to_process);

        // 如果最后一个块不满，需要填充
        if (to_process < AES_BLOCK_SIZE) {
            pkcs7_pad(block_in, to_process);
        }

        // 调用 AES 加密函数
        aes_encrypt_block(block_in, subKeys, block_out);

        // for (int i = 0; i < AES_BLOCK_SIZE; i += 4) {
        //     unsigned char temp = block_out[i];
        //     block_out[i] = block_out[i + 3];
        //     block_out[i + 3] = temp;
        //     temp = block_out[i + 1];
        //     block_out[i + 1] = block_out[i + 2];
        //     block_out[i + 2] = temp;
        // }

        // 写回加密结果
        memcpy(dest + offset, block_out, AES_BLOCK_SIZE);

        offset += AES_BLOCK_SIZE;
    }
}

// 解密接口函数
void aes_decrypt_file(const void *src, int bytes, unsigned char subKeys[AES_EXPANDED_KEY_BLOCK][AES_BLOCK_SIZE], void *va_dest) {
    const unsigned char *input = (const unsigned char *)src;
    unsigned char *dest = (unsigned char *)va_dest;

    int offset = 0;

    // while (offset < bytes) {
        // unsigned char block_in[AES_BLOCK_SIZE] = {0};
        // unsigned char block_out[AES_BLOCK_SIZE] = {0};

        // // 复制当前块数据
        // memcpy(block_in, input + offset, AES_BLOCK_SIZE);


        // 调用 AES 解密函数
        // aes_decrypt_block(block_in, subKeys, block_out);
        aes_decrypt_block(input, subKeys, dest);

        // 如果是最后一个块，需要去掉填充
        if (offset + AES_BLOCK_SIZE > bytes) {
            // int unpadded_len = pkcs7_unpad(block_out);
            // if (unpadded_len < 0) {
            //     // 填充错误处理
            //     printl("Padding error.Return Ciphertext.\n");
            //     return;
            // }
            // memcpy(dest + offset, block_out, unpadded_len);
            // memcpy(dest + offset, block_out, AES_BLOCK_SIZE);
        } else {
            // memcpy(dest + offset, block_out, AES_BLOCK_SIZE);
        }

        // offset += AES_BLOCK_SIZE;
    // }
}
