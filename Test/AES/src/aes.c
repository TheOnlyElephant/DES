# include "../inc/aes.h"
# include <string.h>
# include <stdio.h>

// // 子密钥拓展函数
// int KeyExpansion(const unsigned char key[AES_KEY_SIZE], unsigned char expandedKey[AES_EXPANDED_KEY_SIZE]) {
//     unsigned int i, j;
//     unsigned char temp[4], k;

//     // 前16字节是原始密钥
//     memcpy(expandedKey, key, AES_KEY_SIZE);
//     // for (i = 0; i < AES_KEY_SIZE; i++) {
//     //     expandedKey[i] = key[i];
//     // }

//     // 生成其余的密钥
//     for (i = AES_KEY_SIZE; i < AES_EXPANDED_KEY_SIZE; i += 4) {
//         // temp = W[I-1]
//         for (j = 0; j < 4; j++) {
//             temp[j] = expandedKey[(i - 4) + j];
//         }

//         // I = Nk的整数倍
//         if (i % AES_KEY_SIZE == 0) {
//             // 轮常量
//             k = temp[0];
//             temp[0] = S_BOX[temp[1]] ^ RCON[i / AES_KEY_SIZE];
//             temp[1] = S_BOX[temp[2]];
//             temp[2] = S_BOX[temp[3]];
//             temp[3] = S_BOX[k];
//         }

//         for (j = 0; j < 4; j++) {
//             expandedKey[i + j] = expandedKey[(i - AES_KEY_SIZE) + j] ^ temp[j];
//         }
//     }

//     // for(int i = 0; i < 11; i++) {
//     //     for(int j = 0; j < 16; j++) {
//     //         printf("%02x ", expandedKey[i*16 + j]);
//     //     }
//     //     printf("\n");
//     // }

//     return 0;
// }

// // AES 加密函数
// void aes_encrypt_block(const unsigned char *input, const unsigned char expandedKey[AES_EXPANDED_KEY_SIZE], unsigned char *output) {
//     unsigned char state[4][4];
//     int i, j, round;

//     // 初始化状态矩阵
//     for (i = 0; i < 4; i++) {
//         for (j = 0; j < 4; j++) {
//             state[i][j] = input[i * 4 + j];
//         }
//     }

//     // 初始轮密钥加
//     add_round_key(state, expandedKey);

//     // 9 轮主要操作
//     for (round = 1; round < 10; round++) {
//         sub_bytes(state);
//         // ShiftRow输出调试
//         // printf("\nSubByte %d: \n", round);
//         // for(int i = 0; i < 4; i++) {
//         //     for(int j = 0; j < 4; j++) {
//         //         printf("%02x ", state[i][j]);
//         //     }
//         // }
//         shift_rows(state);

//         // ShiftRow输出调试
//         // printf("\nShiftRow %d: \n", round);
//         // for(int i = 0; i < 4; i++) {
//         //     for(int j = 0; j < 4; j++) {
//         //         printf("%02x ", state[i][j]);
//         //     }
//         // }
//         mix_columns(state);

//         // MixColumns输出调试
//         // printf("\nMixCol %d: \n", round);
//         // for(int i = 0; i < 4; i++) {
//         //     for(int j = 0; j < 4; j++) {
//         //         printf("%02x ", state[i][j]);
//         //     }
//         // }

//         // RoundKey输出调试
//         // printf("\nRound Key %d: \n", round);
//         // for(int i = 0; i < 4; i++) {
//         //     for(int j = 0; j < 4; j++) {
//         //         printf("%02x ", expandedKey[i*4 + j + round * 16]);
//         //     }
//         // }
//         add_round_key(state, expandedKey + round * 16);

//         // AddRoundKey输出调试
//         // printf("\nAddRoundKey %d: \n", round);
//         // for(int i = 0; i < 4; i++) {
//         //     for(int j = 0; j < 4; j++) {
//         //         printf("%02x ", state[i][j]);
//         //     }
//         // }
//     }

//     // 最后一轮
//     sub_bytes(state);
//     shift_rows(state);
//     add_round_key(state, expandedKey + 10 * 16);

//     // 将状态矩阵复制到输出
//     for (i = 0; i < 4; i++) {
//         for (j = 0; j < 4; j++) {
//             output[i * 4 + j] = state[i][j];
//         }
//     }
// }

// // AES 解密函数
// void aes_decrypt_block(const unsigned char *input, const unsigned char expandedKey[AES_EXPANDED_KEY_SIZE], unsigned char *output) {
//     unsigned char state[4][4];
//     int i, j, round;

//     // 初始化状态矩阵
//     for (i = 0; i < 4; i++) {
//         for (j = 0; j < 4; j++) {
//             state[i][j] = input[i * 4 + j];
//         }
//     }

//     // 初始轮密钥加
//     add_round_key(state, expandedKey + 10 * 16);
//     // AddRoundKey输出调试
//     printf("\nAddRoundKey %d: \n", round);
//     for(int i = 0; i < 4; i++) {
//         for(int j = 0; j < 4; j++) {
//             printf("%02x ", state[i][j]);
//         }
//     }
//     // 9 轮主要操作
//     for (round = 9; round > 0; round--) {
//         inv_shift_rows(state);
//         inv_sub_bytes(state);
//         add_round_key(state, expandedKey + round * 16);
//         inv_mix_columns(state);
//         // AddRoundKey输出调试
//         printf("\nAddRoundKey %d: \n", round);
//         for(int i = 0; i < 4; i++) {
//             for(int j = 0; j < 4; j++) {
//                 printf("%02x ", state[i][j]);
//             }
//         }
//     }

//     // 最后一轮
//     inv_shift_rows(state);
//     inv_sub_bytes(state);
//     add_round_key(state, expandedKey);

//     // AddRoundKey输出调试
//     printf("\nAddRoundKey %d: \n", round);
//     for(int i = 0; i < 4; i++) {
//         for(int j = 0; j < 4; j++) {
//             printf("%02x ", state[i][j]);
//         }
//     }

//     // 将状态矩阵复制到输出
//     for (i = 0; i < 4; i++) {
//         for (j = 0; j < 4; j++) {
//             output[i * 4 + j] = state[i][j];
//         }
//     }
// }

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
    memcpy(output, temp, 16);
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
    memcpy(output, state1, 16);
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

    while (offset < bytes) {
        unsigned char block_in[AES_BLOCK_SIZE] = {0};
        unsigned char block_out[AES_BLOCK_SIZE] = {0};

        // 复制当前块数据
        memcpy(block_in, input + offset, AES_BLOCK_SIZE);


        // 调用 AES 解密函数
        aes_decrypt_block(block_in, subKeys, block_out);

        // 如果是最后一个块，需要去掉填充
        if (offset + AES_BLOCK_SIZE > bytes) {
            // int unpadded_len = pkcs7_unpad(block_out);
            // if (unpadded_len < 0) {
            //     // 填充错误处理
            //     printl("Padding error.Return Ciphertext.\n");
            //     return;
            // }
            // memcpy(dest + offset, block_out, unpadded_len);
            memcpy(dest + offset, block_out, AES_BLOCK_SIZE);
        } else {
            memcpy(dest + offset, block_out, AES_BLOCK_SIZE);
        }

        offset += AES_BLOCK_SIZE;
    }
}

int main() {
    unsigned char key[AES_KEY_SIZE] = {0x2A, 0x1B, 0xB8, 0x91, 0xF6, 0xF7, 0x64, 0xCD, 0x82, 0x93, 0xD0, 0xC9, 0xCE, 0xEF, 0xFC, 0x85};
    unsigned char expandedKey[AES_EXPANDED_KEY_SIZE] = {0};
    expandedKey[0] = 0x2A;
    // if(KeyExpansion(key, expandedKey) == 0) {
        // printf("Key expansion success\n");
        // for(int i = 0; i < AES_EXPANDED_KEY_SIZE; i++) {
        //     printf("%02x ", expandedKey[i] );
        //     if(i % 16 == 0 && i != 0) {
        //         printf("\n");
        //     }
        // }
    // } else {
    //     // printf("Key expansion failed\n");
    // }

    unsigned char input[AES_BLOCK_SIZE] = {0x00, 0x01, 0x00, 0x01, 0x01, 0xa1, 0x98, 0xaf, 0xda, 0x78, 0x17, 0x34, 0x86, 0x15, 0x35, 0x66};
    unsigned char output[AES_BLOCK_SIZE] = {0};
    aes_encrypt_block(input, expandedKey, output);
    
    // printf("Encrypt\n");
    // for(int i = 0; i < AES_BLOCK_SIZE; i++) {
    //     printf("%02x ", output[i] );
    // }
    // printf("\n");
    
    unsigned char result[AES_BLOCK_SIZE] = {0};
    aes_decrypt_block(output, expandedKey, result);
    
    // printf("Decrypt\n");
    // for(int i = 0; i < AES_BLOCK_SIZE; i++) {
    //     printf("%02x ", result[i] );
    // }
    // printf("\n");
}