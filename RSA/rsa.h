#ifndef RSA_H
#define RSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/**
 * @brief 定义RSA相关参数
 * 
 * RSA的密钥长度可变（如1024, 2048, 4096位），这里以2048位为例。实际实现中可根据需要灵活设置。
 * RSA的公钥和私钥都包含一个模数N和对应的指数（公钥: e，私钥: d）。N的大小与密钥长度直接相关。
 */
#define RSA_KEY_BITS      2048
#define RSA_KEY_BYTES     (RSA_KEY_BITS / 8)

/**
 * @brief RSA公钥结构
 * 包含：
 * - n (模数)
 * - e (公钥指数)
 * 
 * n和e通常为大整数，这里用定长数组存储。实际使用时需要管理n_len和e_len表示有效长度。
 */
typedef struct {
    uint8_t n[RSA_KEY_BYTES];    /**< 模数N，大端表示 */
    uint8_t e[RSA_KEY_BYTES];    /**< 公钥指数e，大端表示 */
    size_t n_len;                /**< N的实际字节长度 */
    size_t e_len;                /**< e的实际字节长度 */
} rsa_public_key_t;

/**
 * @brief RSA私钥结构
 * 包含：
 * - n (模数)
 * - d (私钥指数)
 * 
 * 与公钥类似，用数组存储并使用n_len和d_len描述实际长度。
 */
typedef struct {
    uint8_t n[RSA_KEY_BYTES];    /**< 模数N，大端表示 */
    uint8_t d[RSA_KEY_BYTES];    /**< 私钥指数d，大端表示 */
    size_t n_len;                /**< N的实际字节长度 */
    size_t d_len;                /**< d的实际字节长度 */
} rsa_private_key_t;

/**
 * @brief 生成RSA密钥对
 * 
 * @param[in] bits 密钥长度（以位为单位），如1024或2048位
 * @param[out] pub_key 生成的RSA公钥
 * @param[out] priv_key 生成的RSA私钥
 * @return 0 成功
 * @return 1 失败
 */
int rsa_generate_key_pair(int bits, rsa_public_key_t *pub_key, rsa_private_key_t *priv_key);

/**
 * @brief 使用RSA公钥进行加密
 * 
 * 加密使用公钥(n, e)对明文进行加密处理。通常需要在加密前进行适当的填充（如PKCS#1 v1.5或OAEP）。
 * 
 * @param[in] pub_key RSA公钥
 * @param[in] plaintext 明文数据指针
 * @param[in] plaintext_len 明文长度（字节数）
 * @param[out] ciphertext 密文输出缓冲区
 * @param[out] ciphertext_len 密文长度
 * @return 0 成功
 * @return 1 失败（可能因明文过长或填充失败）
 */
int rsa_encrypt(const rsa_public_key_t *pub_key,
                const uint8_t *plaintext, size_t plaintext_len,
                uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * @brief 使用RSA私钥进行解密
 * 
 * 解密使用私钥(n, d)对密文进行解密。与加密相对应，必须能够正确解析之前使用的填充方式。
 * 
 * @param[in] priv_key RSA私钥
 * @param[in] ciphertext 密文数据指针
 * @param[in] ciphertext_len 密文长度
 * @param[out] plaintext 明文输出缓冲区
 * @param[out] plaintext_len 解密后明文长度
 * @return 0 成功
 * @return 1 失败（可能因密文不合法或填充解析失败）
 */
int rsa_decrypt(const rsa_private_key_t *priv_key,
                const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *plaintext, size_t *plaintext_len);

/**
 * @brief 使用RSA私钥对数据进行签名
 * 
 * 通常对消息hash结果（如SHA-256摘要）进行签名。签名流程同样依赖填充方式。
 * 
 * @param[in] priv_key RSA私钥
 * @param[in] message 待签名数据指针（通常是消息摘要）
 * @param[in] message_len 待签名数据长度
 * @param[out] signature 签名结果输出缓冲区
 * @param[out] signature_len 签名结果长度
 * @return 0 成功
 * @return 1 失败
 */
int rsa_sign(const rsa_private_key_t *priv_key,
             const uint8_t *message, size_t message_len,
             uint8_t *signature, size_t *signature_len);

/**
 * @brief 使用RSA公钥验证签名
 * 
 * 根据公钥(n, e)，对给定消息和签名进行验证。若填充及签名均正确，则验证成功。
 * 
 * @param[in] pub_key RSA公钥
 * @param[in] message 待验证的消息（通常是消息摘要）
 * @param[in] message_len 消息长度
 * @param[in] signature 签名数据指针
 * @param[in] signature_len 签名长度
 * @return 0 验证通过
 * @return 1 验证失败（签名无效）
 */
int rsa_verify(const rsa_public_key_t *pub_key,
               const uint8_t *message, size_t message_len,
               const uint8_t *signature, size_t signature_len);

#ifdef __cplusplus
}
#endif

#endif // RSA_H
