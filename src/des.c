#include "../inc/des.h"
#include <string.h>


int des_make_subkeys(const unsigned char key[8], unsigned char subKeys[16][6]) {
    unsigned char permuted_key[7] = {0};
    permute(key, permuted_key, PC1, 56); // Apply PC1 permutation

    unsigned char left[4] = {0}, right[4] = {0};
    memcpy(left, permuted_key, 3);        // Copy first 28 bits
    memcpy(right, permuted_key + 3, 4);  // Copy last 28 bits

    for (int i = 0; i < 16; i++) {
        rotate_left(left, 3, rotations[i]);  // Rotate left side
        rotate_left(right, 4, rotations[i]); // Rotate right side

        unsigned char combined[7] = {0};
        memcpy(combined, left, 3);       // Combine left part
        memcpy(combined + 3, right, 4); // Combine right part

        permute(combined, subKeys[i], PC2, 48); // Apply PC2 permutation
    }

    return 0; // Return success
}
// Helper: Feistel function
static void feistel(const unsigned char *right, const unsigned char *subKey, unsigned char *output) {
    unsigned char expanded[6] = {0};
    permute(right, expanded, E, 48);

    for (int i = 0; i < 6; i++) {
        expanded[i] ^= subKey[i];
    }

    unsigned char substituted[4] = {0};
    for (int i = 0; i < 8; i++) {
        int row = ((expanded[i / 6] & 0x20) >> 4) | (expanded[i / 6] & 0x01);
        int col = (expanded[i / 6] & 0x1E) >> 1;
        int sbox_value = S[i][row][col];
        substituted[i / 2] |= (sbox_value << (4 * (1 - (i % 2))));
    }

    permute(substituted, output, P, 32); // Apply P permutation
}

// DES Encryption
void des_encrypt_block(const unsigned char *input, unsigned char subKeys[16][6], unsigned char *output) {
    unsigned char permuted[8] = {0};
    permute(input, permuted, IP, 64);

    unsigned char left[4] = {0}, right[4] = {0};
    memcpy(left, permuted, 4);
    memcpy(right, permuted + 4, 4);

    for (int i = 0; i < 16; i++) {
        unsigned char temp[4] = {0};
        feistel(right, subKeys[i], temp);
        for (int j = 0; j < 4; j++) {
            temp[j] ^= left[j];
        }
        memcpy(left, right, 4);
        memcpy(right, temp, 4);
    }

    unsigned char preoutput[8] = {0};
    memcpy(preoutput, right, 4);
    memcpy(preoutput + 4, left, 4);

    permute(preoutput, output, IP_INV, 64);
}

// DES Decryption
void des_decrypt_block(const unsigned char *input, unsigned char subKeys[16][6], unsigned char *output) {
    unsigned char permuted[8] = {0};
    permute(input, permuted, IP, 64);

    unsigned char left[4] = {0}, right[4] = {0};
    memcpy(left, permuted, 4);
    memcpy(right, permuted + 4, 4);

    for (int i = 15; i >= 0; i--) {
        unsigned char temp[4] = {0};
        feistel(right, subKeys[i], temp);
        for (int j = 0; j < 4; j++) {
            temp[j] ^= left[j];
        }
        memcpy(left, right, 4);
        memcpy(right, temp, 4);
    }

    unsigned char preoutput[8] = {0};
    memcpy(preoutput, right, 4);
    memcpy(preoutput + 4, left, 4);

    permute(preoutput, output, IP_INV, 64);
}