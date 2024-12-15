#include "../inc/sm4.h"

int sm4_make_enc_subkeys(const unsigned char key[SM4_KEY_SIZE], uint32_t encSubKeys[SM4_ROUNDS]) {
    uint32_t K[4];
    for (int i = 0; i < 4; ++i) {
        K[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
               ((uint32_t)key[4 * i + 2] << 8) | (uint32_t)key[4 * i + 3];
        K[i] ^= FK[i];
    }
    for (int i = 0; i < SM4_ROUNDS; ++i) {
        encSubKeys[i] = K[0] ^ T_prime(K[1] ^ K[2] ^ K[3] ^ CK[i]);
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = encSubKeys[i];
    }

    // printf("Around Key\n");
    // for(int i = 0; i < 32; i++) {
    //     printf("%08x\n", encSubKeys[i] );
    // }

    return 0;
}

int sm4_make_dec_subkeys(const unsigned char key[SM4_KEY_SIZE], uint32_t decSubKeys[SM4_ROUNDS]) {
    uint32_t temp[SM4_ROUNDS];
    sm4_make_enc_subkeys(key, temp);
    for (int i = 0; i < SM4_ROUNDS; ++i) {
        decSubKeys[i] = temp[SM4_ROUNDS - 1 - i];
    }
    return 0;
}

void sm4_encrypt_block(const unsigned char *input, const uint32_t encSubKeys[SM4_ROUNDS], unsigned char *output) {
    uint32_t X[4];
    for (int i = 0; i < 4; ++i) {
        X[i] = ((uint32_t)input[4 * i] << 24) | ((uint32_t)input[4 * i + 1] << 16) |
               ((uint32_t)input[4 * i + 2] << 8) | (uint32_t)input[4 * i + 3];
    }

    // for(int i = 0; i < 4; i++) {
    //     printf("%08x\n", X[i]);
    // }

    for (int i = 0; i < SM4_ROUNDS; ++i) {
        uint32_t temp = X[0] ^ T(X[1] ^ X[2] ^ X[3] ^ encSubKeys[i]);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp;

    // printf("Round %d\n", i);
    // printf("%08x\n", X[3]); // 只打印 X[3]

    }
    for (int i = 0; i < 4; ++i) {
        output[4 * i]     = (X[3 - i] >> 24) & 0xFF;
        output[4 * i + 1] = (X[3 - i] >> 16) & 0xFF;
        output[4 * i + 2] = (X[3 - i] >> 8)  & 0xFF;
        output[4 * i + 3] = X[3 - i] & 0xFF;
    }
}

void sm4_decrypt_block(const unsigned char *input, const uint32_t decSubKeys[SM4_ROUNDS], unsigned char *output) {
    sm4_encrypt_block(input, decSubKeys, output);
}

