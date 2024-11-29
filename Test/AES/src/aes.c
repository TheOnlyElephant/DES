# include "../inc/aes.h"
# include <string.h>
# include <stdio.h>

// 子密钥拓展函数
int KeyExpansion(const unsigned char key[AES_KEY_SIZE], unsigned char expandedKey[AES_EXPANDED_KEY_SIZE]) {
    unsigned int i, j;
    unsigned char temp[4], k;

    // 前16字节是原始密钥
    memcpy(expandedKey, key, AES_KEY_SIZE);
    // for (i = 0; i < AES_KEY_SIZE; i++) {
    //     expandedKey[i] = key[i];
    // }

    // 生成其余的密钥
    for (i = AES_KEY_SIZE; i < AES_EXPANDED_KEY_SIZE; i += 4) {
        // temp = W[I-1]
        for (j = 0; j < 4; j++) {
            temp[j] = expandedKey[(i - 4) + j];
        }

        // I = Nk的整数倍
        if (i % AES_KEY_SIZE == 0) {
            // 轮常量
            k = temp[0];
            temp[0] = S_BOX[temp[1]] ^ RCON[i / AES_KEY_SIZE];
            temp[1] = S_BOX[temp[2]];
            temp[2] = S_BOX[temp[3]];
            temp[3] = S_BOX[k];
        }

        for (j = 0; j < 4; j++) {
            expandedKey[i + j] = expandedKey[(i - AES_KEY_SIZE) + j] ^ temp[j];
        }
    }

    // for(int i = 0; i < 11; i++) {
    //     for(int j = 0; j < 16; j++) {
    //         printf("%02x ", expandedKey[i*16 + j]);
    //     }
    //     printf("\n");
    // }

    return 0;
}

// AES 加密函数
void aes_encrypt_block(const unsigned char *input, const unsigned char expandedKey[AES_EXPANDED_KEY_SIZE], unsigned char *output) {
    unsigned char state[4][4];
    int i, j, round;

    // 初始化状态矩阵
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = input[i * 4 + j];
        }
    }

    // 初始轮密钥加
    add_round_key(state, expandedKey);

    // 9 轮主要操作
    for (round = 1; round < 10; round++) {
        sub_bytes(state);
        // ShiftRow输出调试
        // printf("\nSubByte %d: \n", round);
        // for(int i = 0; i < 4; i++) {
        //     for(int j = 0; j < 4; j++) {
        //         printf("%02x ", state[i][j]);
        //     }
        // }
        shift_rows(state);

        // ShiftRow输出调试
        // printf("\nShiftRow %d: \n", round);
        // for(int i = 0; i < 4; i++) {
        //     for(int j = 0; j < 4; j++) {
        //         printf("%02x ", state[i][j]);
        //     }
        // }
        mix_columns(state);

        // MixColumns输出调试
        // printf("\nMixCol %d: \n", round);
        // for(int i = 0; i < 4; i++) {
        //     for(int j = 0; j < 4; j++) {
        //         printf("%02x ", state[i][j]);
        //     }
        // }

        // RoundKey输出调试
        // printf("\nRound Key %d: \n", round);
        // for(int i = 0; i < 4; i++) {
        //     for(int j = 0; j < 4; j++) {
        //         printf("%02x ", expandedKey[i*4 + j + round * 16]);
        //     }
        // }
        add_round_key(state, expandedKey + round * 16);

        // AddRoundKey输出调试
        // printf("\nAddRoundKey %d: \n", round);
        // for(int i = 0; i < 4; i++) {
        //     for(int j = 0; j < 4; j++) {
        //         printf("%02x ", state[i][j]);
        //     }
        // }
    }

    // 最后一轮
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, expandedKey + 10 * 16);

    // 将状态矩阵复制到输出
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            output[i * 4 + j] = state[i][j];
        }
    }
}

// AES 解密函数
void aes_decrypt_block(const unsigned char *input, const unsigned char expandedKey[AES_EXPANDED_KEY_SIZE], unsigned char *output) {
    unsigned char state[4][4];
    int i, j, round;

    // 初始化状态矩阵
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = input[i * 4 + j];
        }
    }

    // 初始轮密钥加
    add_round_key(state, expandedKey + 10 * 16);
    // AddRoundKey输出调试
    printf("\nAddRoundKey %d: \n", round);
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            printf("%02x ", state[i][j]);
        }
    }
    // 9 轮主要操作
    for (round = 9; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, expandedKey + round * 16);
        inv_mix_columns(state);
        // AddRoundKey输出调试
        printf("\nAddRoundKey %d: \n", round);
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                printf("%02x ", state[i][j]);
            }
        }
    }

    // 最后一轮
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, expandedKey);

    // AddRoundKey输出调试
    printf("\nAddRoundKey %d: \n", round);
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            printf("%02x ", state[i][j]);
        }
    }

    // 将状态矩阵复制到输出
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            output[i * 4 + j] = state[i][j];
        }
    }
}

int main() {
    unsigned char key[AES_KEY_SIZE] = {0x00, 0x01, 0x20, 0x01, 0x71, 0x01, 0x98, 0xae, 0xda, 0x79, 0x17, 0x14, 0x60, 0x15, 0x35, 0x94};
    unsigned char expandedKey[AES_EXPANDED_KEY_SIZE] = {0};
    if(KeyExpansion(key, expandedKey) == 0) {
        // printf("Key expansion success\n");
        // for(int i = 0; i < AES_EXPANDED_KEY_SIZE; i++) {
        //     printf("%02x ", expandedKey[i] );
        //     if(i % 16 == 0 && i != 0) {
        //         printf("\n");
        //     }
        // }
    } else {
        // printf("Key expansion failed\n");
    }

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