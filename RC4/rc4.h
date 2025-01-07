#ifndef RC4_H
#define RC4_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define RC4_KEY_SIZE 256 /* Key size in bytes */

/**
 * @brief RC4 context structure
 */
typedef struct {
    uint8_t S[RC4_KEY_SIZE]; /* State array */
    uint8_t i, j;            /* Indices for permutation */
} RC4_State;

/**
 * @brief Initialize RC4 state with the given key
 * @param[in] key Input key
 * @param[in] key_length Length of the input key in bytes
 * @param[out] state Initialized RC4 state
 */
void rc4_initialize(const uint8_t *key, size_t key_length, RC4_State *state);

/**
 * @brief Encrypt or decrypt data using RC4
 * @param[in,out] state RC4 state
 * @param[in] input Input data (plaintext or ciphertext)
 * @param[out] output Output data (ciphertext or plaintext)
 * @param[in] length Length of the input data in bytes
 */
void rc4_crypt(RC4_State *state, const uint8_t *input, uint8_t *output, size_t length);

#ifdef __cplusplus
}
#endif

#endif // RC4_H
