#include "rc4.h"
#include <stdint.h>
#include <stddef.h>

/**
 * @brief Initialize RC4 state with the given key
 */
void rc4_initialize(const uint8_t *key, size_t key_length, RC4_State *state) {
    if (!key || !state || key_length == 0) {
        return;
    }

    /* Initialize the state array */
    for (int i = 0; i < RC4_KEY_SIZE; i++) {
        state->S[i] = i;
    }

    /* Key-scheduling algorithm (KSA) */
    uint8_t j = 0;
    for (int i = 0; i < RC4_KEY_SIZE; i++) {
        j = (j + state->S[i] + key[i % key_length]) % RC4_KEY_SIZE;
        /* Swap S[i] and S[j] */
        uint8_t temp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = temp;
    }

    /* Reset indices for the permutation generation */
    state->i = 0;
    state->j = 0;
}

/**
 * @brief Encrypt or decrypt data using RC4
 */
void rc4_crypt(RC4_State *state, const uint8_t *input, uint8_t *output, size_t length) {
    if (!state || !input || !output || length == 0) {
        return;
    }

    for (size_t n = 0; n < length; n++) {
        /* Generate the next byte of the key stream */
        state->i = (state->i + 1) % RC4_KEY_SIZE;
        state->j = (state->j + state->S[state->i]) % RC4_KEY_SIZE;

        /* Swap S[i] and S[j] */
        uint8_t temp = state->S[state->i];
        state->S[state->i] = state->S[state->j];
        state->S[state->j] = temp;

        /* Generate the key stream byte */
        uint8_t k = state->S[(state->S[state->i] + state->S[state->j]) % RC4_KEY_SIZE];

        /* Encrypt or decrypt the input byte */
        output[n] = input[n] ^ k;
    }
}
