#ifndef AES_CFB_H
#define AES_CFB_H

#include "aes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief AES-CFB加密
 * @param[in] plaintext 明文数据
 * @param[in] plaintext_len 明文长度（字节）
 * @param[in] key AES密钥
 * @param[in] iv 初始化向量 (16字节)
 * @param[out] ciphertext 密文输出缓冲区 
 * @return 0 成功
 * @return 1 失败
 */
int aes_cfb_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                   const unsigned char key[AES_KEY_SIZE],
                   const unsigned char iv[AES_BLOCK_SIZE],
                   unsigned char *ciphertext);

/**
 * @brief AES-CFB解密
 * @param[in] ciphertext 密文数据
 * @param[in] ciphertext_len 密文长度（字节）
 * @param[in] key AES密钥
 * @param[in] iv 初始化向量 (16字节)
 * @param[out] plaintext 明文输出缓冲区
 * @return 0 成功
 * @return 1 失败
 */
int aes_cfb_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                   const unsigned char key[AES_KEY_SIZE],
                   const unsigned char iv[AES_BLOCK_SIZE],
                   unsigned char *plaintext);

#ifdef __cplusplus
}
#endif

#endif // AES_CFB_H
