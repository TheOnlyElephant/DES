// rsa.c

#include "rsa.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define MAX_WORDS (RSA_KEY_BYTES / sizeof(uint32_t))

/**
 * 简单大整数结构，用于存储大端字节序转换的数值。
 * 实现时将其视为无符号大整数。
 */
typedef struct {
    uint32_t words[MAX_WORDS]; // 每个word为32bit
} bigint_t;

/* 工具函数原型声明 */
static void bigint_from_bytes(bigint_t *x, const uint8_t *buf, size_t len);
static void bigint_to_bytes(const bigint_t *x, uint8_t *buf, size_t len);
static int bigint_cmp(const bigint_t *a, const bigint_t *b);
static void bigint_set_uint(bigint_t *x, uint32_t val);
static void bigint_copy(bigint_t *dst, const bigint_t *src);
static void bigint_add(const bigint_t *a, const bigint_t *b, bigint_t *r);
static int bigint_sub(const bigint_t *a, const bigint_t *b, bigint_t *r); 
static void bigint_shift_right(const bigint_t *a, bigint_t *r);
static void bigint_mul(const bigint_t *a, const bigint_t *b, bigint_t *r);
static void bigint_mod(const bigint_t *a, const bigint_t *m, bigint_t *r);
static void bigint_modexp(const bigint_t *base, const bigint_t *exp, const bigint_t *mod, bigint_t *r);
static int is_prime(const bigint_t *x);
static void generate_random_prime(bigint_t *p, int bits);
static void bigint_from_uint(bigint_t *x, uint32_t val);
static void bigint_div_mod(const bigint_t *a, const bigint_t *b, bigint_t *quot, bigint_t *rem);

/**
 * RSA相关实现
 */

int rsa_generate_key_pair(int bits, rsa_public_key_t *pub_key, rsa_private_key_t *priv_key) {
    // 简化生成一对非常不安全的RSA密钥对
    // RSA密钥生成流程：
    // 1. 生成两个大素数p和q，位数为bits/2
    // 2. n = p*q
    // 3. phi(n) = (p-1)*(q-1)
    // 4. 选择e，通常为65537
    // 5. d = e的模phi(n)乘法逆元

    if (bits != RSA_KEY_BITS) {
        // 简化假设只能生成固定长度密钥
        return 1;
    }

    srand((unsigned)time(NULL));

    int half_bits = bits / 2;
    bigint_t p, q, n, phi, e, d;
    bigint_t p_1, q_1, phi_calc, tmp;

    // 生成p,q
    generate_random_prime(&p, half_bits);
    generate_random_prime(&q, half_bits);

    // n = p*q
    bigint_mul(&p, &q, &n);

    // phi(n) = (p-1)*(q-1)
    bigint_sub(&p, NULL, &p_1); // p-1
    bigint_sub(&p_1, NULL, &p_1); // 实现中bigint_sub(a,NULL,r)无意义，我们需要p_1 = p; p_1 = p-1:
    // 实际上应先复制p到p_1，然后对p_1减去1
    // 简化修正：为简化，我们单独实现一个函数sub_ui用于减去1
    // 这里临时hack：
    // 函数中缺少sub_ui，手动实现:
    {
        bigint_copy(&p_1, &p);
        // p_1 = p - 1
        bigint_t one; 
        bigint_from_uint(&one, 1);
        bigint_sub(&p_1, &one, &p_1);
    }

    {
        bigint_copy(&q_1, &q);
        bigint_t one; 
        bigint_from_uint(&one, 1);
        bigint_sub(&q_1, &one, &q_1);
    }

    bigint_mul(&p_1, &q_1, &phi);

    // e = 65537
    bigint_from_uint(&e, 65537);

    // 计算d = e^{-1} mod phi(n)
    // 使用扩展欧几里得算法求逆元
    // 简化实现扩展欧几里得算法
    // 实际应实现extended_gcd，这里简化
    static int extended_gcd(const bigint_t *a, const bigint_t *b, bigint_t *x, bigint_t *y);
    // 我们必须实现extended_gcd才能求逆元
    // 简化写出求逆元函数:
    bigint_t gcd, x_, y_;
    // 求gcd(a,b)与x,y满足a*x+b*y = gcd
    static void bigint_mod_inverse(const bigint_t *a, const bigint_t *m, bigint_t *inv);
    bigint_mod_inverse(&e, &phi, &d);

    // 将n,e,d导出到pub和priv
    uint8_t n_buf[RSA_KEY_BYTES], e_buf[RSA_KEY_BYTES], d_buf[RSA_KEY_BYTES];
    bigint_to_bytes(&n, n_buf, RSA_KEY_BYTES);
    bigint_to_bytes(&e, e_buf, RSA_KEY_BYTES);
    bigint_to_bytes(&d, d_buf, RSA_KEY_BYTES);

    memcpy(pub_key->n, n_buf, RSA_KEY_BYTES);
    memcpy(pub_key->e, e_buf, RSA_KEY_BYTES);
    pub_key->n_len = RSA_KEY_BYTES;
    pub_key->e_len = RSA_KEY_BYTES;

    memcpy(priv_key->n, n_buf, RSA_KEY_BYTES);
    memcpy(priv_key->d, d_buf, RSA_KEY_BYTES);
    priv_key->n_len = RSA_KEY_BYTES;
    priv_key->d_len = RSA_KEY_BYTES;

    return 0;
}

int rsa_encrypt(const rsa_public_key_t *pub_key,
                const uint8_t *plaintext, size_t plaintext_len,
                uint8_t *ciphertext, size_t *ciphertext_len) {
    // 不使用填充，假设plaintext_len <= RSA_KEY_BYTES
    if (plaintext_len > RSA_KEY_BYTES) return 1;

    bigint_t n, e, m, c;
    bigint_from_bytes(&n, pub_key->n, pub_key->n_len);
    bigint_from_bytes(&e, pub_key->e, pub_key->e_len);

    uint8_t padded[RSA_KEY_BYTES];
    memset(padded, 0, RSA_KEY_BYTES - plaintext_len);
    memcpy(padded + (RSA_KEY_BYTES - plaintext_len), plaintext, plaintext_len);

    bigint_from_bytes(&m, padded, RSA_KEY_BYTES);

    // c = m^e mod n
    bigint_modexp(&m, &e, &n, &c);

    if (*ciphertext_len < RSA_KEY_BYTES) return 1;
    bigint_to_bytes(&c, ciphertext, RSA_KEY_BYTES);
    *ciphertext_len = RSA_KEY_BYTES;
    return 0;
}

int rsa_decrypt(const rsa_private_key_t *priv_key,
                const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *plaintext, size_t *plaintext_len) {
    if (ciphertext_len != RSA_KEY_BYTES) return 1;

    bigint_t n, d, c, m;
    bigint_from_bytes(&n, priv_key->n, priv_key->n_len);
    bigint_from_bytes(&d, priv_key->d, priv_key->d_len);
    bigint_from_bytes(&c, ciphertext, ciphertext_len);

    // m = c^d mod n
    bigint_modexp(&c, &d, &n, &m);

    uint8_t buf[RSA_KEY_BYTES];
    bigint_to_bytes(&m, buf, RSA_KEY_BYTES);

    // 去除前导0
    size_t offset = 0;
    while (offset < RSA_KEY_BYTES && buf[offset] == 0) offset++;
    size_t msg_len = RSA_KEY_BYTES - offset;
    if (msg_len > *plaintext_len) return 1;

    memcpy(plaintext, buf + offset, msg_len);
    *plaintext_len = msg_len;
    return 0;
}

int rsa_sign(const rsa_private_key_t *priv_key,
             const uint8_t *message, size_t message_len,
             uint8_t *signature, size_t *signature_len) {
    // 签名与解密类似：sig = m^d mod n
    if (message_len > RSA_KEY_BYTES) return 1;

    bigint_t n, d, m, s;
    bigint_from_bytes(&n, priv_key->n, priv_key->n_len);
    bigint_from_bytes(&d, priv_key->d, priv_key->d_len);

    uint8_t padded[RSA_KEY_BYTES];
    memset(padded, 0, RSA_KEY_BYTES - message_len);
    memcpy(padded + (RSA_KEY_BYTES - message_len), message, message_len);
    bigint_from_bytes(&m, padded, RSA_KEY_BYTES);

    bigint_modexp(&m, &d, &n, &s);

    if (*signature_len < RSA_KEY_BYTES) return 1;
    bigint_to_bytes(&s, signature, RSA_KEY_BYTES);
    *signature_len = RSA_KEY_BYTES;
    return 0;
}

int rsa_verify(const rsa_public_key_t *pub_key,
               const uint8_t *message, size_t message_len,
               const uint8_t *signature, size_t signature_len) {
    // 验证与加密类似：m' = sig^e mod n，比较m'与message
    if (signature_len != RSA_KEY_BYTES) return 1;

    bigint_t n, e, s, m_;
    bigint_from_bytes(&n, pub_key->n, pub_key->n_len);
    bigint_from_bytes(&e, pub_key->e, pub_key->e_len);
    bigint_from_bytes(&s, signature, signature_len);

    bigint_modexp(&s, &e, &n, &m_);

    uint8_t buf[RSA_KEY_BYTES];
    bigint_to_bytes(&m_, buf, RSA_KEY_BYTES);

    // 去除前导0比较
    size_t offset = 0;
    while (offset < RSA_KEY_BYTES && buf[offset] == 0) offset++;
    size_t recovered_len = RSA_KEY_BYTES - offset;

    uint8_t padded_m[RSA_KEY_BYTES];
    memset(padded_m, 0, RSA_KEY_BYTES - message_len);
    memcpy(padded_m + (RSA_KEY_BYTES - message_len), message, message_len);

    if (recovered_len == message_len && memcmp(buf + offset, message, message_len) == 0) {
        return 0; // 验证通过
    }

    return 1; // 验证失败
}

/**************************************************************************
 * 以下为极其简化且低效的大整数及素数运算函数实现
 * 只实现必要功能，不具有完整的安全性和正确性保证
 **************************************************************************/

/* 将字节数组转为bigint_t(大端) */
static void bigint_from_bytes(bigint_t *x, const uint8_t *buf, size_t len) {
    memset(x, 0, sizeof(*x));
    // 假设len == RSA_KEY_BYTES
    // 将大端字节转换为内部以words为单位的形式(仍保持大端在x->words[0]是最高位)
    for (size_t i = 0; i < len; i++) {
        size_t word_index = i / 4;
        x->words[word_index] = (x->words[word_index] << 8) | buf[i];
    }
}

/* bigint_t转字节数组(大端) */
static void bigint_to_bytes(const bigint_t *x, uint8_t *buf, size_t len) {
    memset(buf, 0, len);
    // 逆向还原
    // 因words中存放时，words[0]含最高位，但已在内存中是本机字节序，因此我们需要谨慎
    // 简化：认为本机字节序和处理方式固定。
    // 我们将整个位数统一存储为大端:
    uint32_t temp[MAX_WORDS];
    for (int i = 0; i < MAX_WORDS; i++) {
        temp[i] = x->words[i];
    }
    // 每次取word的最高字节先放入buf
    size_t pos = 0;
    for (int i = 0; i < MAX_WORDS; i++) {
        uint32_t w = temp[i];
        buf[pos++] = (uint8_t)((w >> 24) & 0xFF);
        buf[pos++] = (uint8_t)((w >> 16) & 0xFF);
        buf[pos++] = (uint8_t)((w >> 8) & 0xFF);
        buf[pos++] = (uint8_t)(w & 0xFF);
    }
}

/* 比较大小 a< b返回<0, a==b返回0, a>b返回>0 */
static int bigint_cmp(const bigint_t *a, const bigint_t *b) {
    for (int i = 0; i < MAX_WORDS; i++) {
        if (a->words[i] < b->words[i]) return -1;
        if (a->words[i] > b->words[i]) return 1;
    }
    return 0;
}

static void bigint_copy(bigint_t *dst, const bigint_t *src) {
    memcpy(dst->words, src->words, sizeof(dst->words));
}

static void bigint_set_uint(bigint_t *x, uint32_t val) {
    memset(x, 0, sizeof(*x));
    x->words[MAX_WORDS-1] = val;
}

static void bigint_from_uint(bigint_t *x, uint32_t val) {
    memset(x, 0, sizeof(*x));
    x->words[MAX_WORDS-1] = val;
}

/* 加法 r = a+b */
static void bigint_add(const bigint_t *a, const bigint_t *b, bigint_t *r) {
    uint64_t carry = 0;
    for (int i = MAX_WORDS - 1; i >= 0; i--) {
        uint64_t sum = (uint64_t)a->words[i] + b->words[i] + carry;
        r->words[i] = (uint32_t)(sum & 0xFFFFFFFF);
        carry = sum >> 32;
    }
}

/* 减法 r = a-b，要求a>=b */
static int bigint_sub(const bigint_t *a, const bigint_t *b, bigint_t *r) {
    bigint_t zero;
    memset(&zero,0,sizeof(zero));
    if (b == NULL) { 
        // 特例：a-NULL无意义，这里返回a-1
        bigint_t one;
        bigint_from_uint(&one,1);
        return bigint_sub(a,&one,r);
    }
    if (bigint_cmp(a,b)<0) return 1; 
    uint64_t borrow = 0;
    for (int i = MAX_WORDS - 1; i >= 0; i--) {
        uint64_t diff = (uint64_t)a->words[i] - b->words[i] - borrow;
        r->words[i] = (uint32_t)(diff & 0xFFFFFFFF);
        borrow = (diff >> 32) & 1;
    }
    return 0;
}

/* 乘法 r = a*b (简化版) */
static void bigint_mul(const bigint_t *a, const bigint_t *b, bigint_t *r) {
    uint64_t temp[2*MAX_WORDS];
    memset(temp,0,sizeof(temp));
    for (int i = MAX_WORDS - 1; i >= 0; i--) {
        uint64_t carry = 0;
        for (int j = MAX_WORDS - 1; j >= 0; j--) {
            uint64_t mul = (uint64_t)a->words[i]*(uint64_t)b->words[j] + temp[i+j+1-(MAX_WORDS)] + carry;
            temp[i+j+1-(MAX_WORDS)] = (uint32_t)(mul & 0xFFFFFFFF);
            carry = mul >> 32;
        }
    }
    // 结果只取MAX_WORDS（高溢出不处理）
    // 简化：只取后MAX_WORDS位
    for (int i=0;i<MAX_WORDS;i++){
        r->words[i]= (uint32_t)temp[i+(2*MAX_WORDS - MAX_WORDS)];
    }
}

/* 模运算: r = a mod m (简化使用试商法) */
static void bigint_div_mod(const bigint_t *a, const bigint_t *b, bigint_t *quot, bigint_t *rem) {
    // 极其简化的除法，仅为示例，效率极低
    bigint_t zero; memset(&zero,0,sizeof(zero));
    bigint_copy(rem, a);
    memset(quot,0,sizeof(*quot));

    while (bigint_cmp(rem,b)>=0) {
        // quot++
        // rem = rem - b
        bigint_t tmp;
        bigint_sub(rem,b,&tmp);
        bigint_copy(rem,&tmp);

        bigint_t one; bigint_from_uint(&one,1);
        bigint_t qtmp;
        bigint_add(quot,&one,&qtmp);
        bigint_copy(quot,&qtmp);
    }
}

static void bigint_mod(const bigint_t *a, const bigint_t *m, bigint_t *r) {
    bigint_t quot;
    bigint_div_mod(a,m,&quot,r);
}

/* 模幂运算 r = base^exp mod mod (快速平方取余) */
static void bigint_modexp(const bigint_t *base, const bigint_t *exp, const bigint_t *m, bigint_t *r) {
    bigint_t result; 
    bigint_from_uint(&result,1);
    bigint_t b;
    bigint_copy(&b,base);

    bigint_t e;
    bigint_copy(&e,exp);

    // 使用平方法
    for (;;) {
        // 检查e是否为0
        bigint_t zero;memset(&zero,0,sizeof(zero));
        if (bigint_cmp(&e,&zero)==0) break;

        // 若e为奇数,result = (result*b) mod m
        // 简化判奇数：看最低word最低bit
        if (e.words[MAX_WORDS-1] & 1) {
            bigint_t rb;
            bigint_mul(&result,&b,&rb);
            bigint_mod(&rb,m,&result);
        }

        // b = b*b mod m
        bigint_t bb;
        bigint_mul(&b,&b,&bb);
        bigint_mod(&bb,m,&b);

        // e = e/2 (右移)
        // 简化为移位操作:
        // 低效实现右移
        uint64_t carry = 0;
        for (int i=0;i<MAX_WORDS;i++){
            uint64_t val = e.words[i];
            uint64_t new_val = (carry << 32) | val;
            e.words[i] = (uint32_t)(new_val >> 1);
            carry = new_val & 1;
        }
    }

    bigint_copy(r,&result);
}

/* 简易素数测试(试除法) */
static int is_prime(const bigint_t *x) {
    // 试除法：从小素数开始
    bigint_t one; bigint_from_uint(&one,1);
    bigint_t two; bigint_from_uint(&two,2);
    if (bigint_cmp(x,&two)<0) return 0;
    // 简单判断x是否为偶数
    if ((x->words[MAX_WORDS-1] & 1)==0) return 0;

    // 尝试除以小数字
    for (uint32_t i=3; i<10000; i+=2) {
        bigint_t divisor; bigint_from_uint(&divisor,i);
        bigint_t rem,q;
        bigint_div_mod(x,&divisor,&q,&rem);
        bigint_t zero;memset(&zero,0,sizeof(zero));
        if (bigint_cmp(&rem,&zero)==0 && bigint_cmp(x,&divisor)>0) {
            return 0;
        }
    }

    return 1;
}

/* 生成随机素数(非常不安全) */
static void generate_random_prime(bigint_t *p, int bits) {
    // 将p设置为随机odd数并重复测试直到为素数
    for (;;) {
        memset(p,0,sizeof(*p));
        // 随机填充
        for (int i=0;i<MAX_WORDS;i++){
            p->words[i] = (uint32_t)rand();
        }
        // 确保最高位bits有效, 简化：只确保最高bit有置位
        // 以2048位为例
        // 简化起见，不严格确保bits长度
        p->words[0] |= 0x80000000;
        // 确保奇数
        p->words[MAX_WORDS-1] |= 1;

        if (is_prime(p)) break;
    }
}

/* 扩展欧几里得算法求逆(略微简化) */
static bigint_t gcd_x,gcd_y,gcd_d;
static void extended_euclid(const bigint_t *a, const bigint_t *b, bigint_t *d, bigint_t *x, bigint_t *y) {
    bigint_t zero; memset(&zero,0,sizeof(zero));
    if (bigint_cmp(b,&zero)==0) {
        bigint_copy(d,a);
        bigint_t one; bigint_from_uint(&one,1);
        bigint_copy(x,&one);
        memset(y,0,sizeof(*y));
        return;
    }
    bigint_t q,r;
    bigint_div_mod(a,b,&q,&r);
    bigint_t x1,y1;
    extended_euclid(b,&r,d,&x1,&y1);
    // x = y1
    bigint_copy(x,&y1);
    // y = x1 - q*y1
    bigint_t qy1; 
    bigint_mul(&q,&y1,&qy1);
    bigint_t t;
    bigint_sub(&x1,&qy1,&t);
    bigint_copy(y,&t);
}

static void bigint_mod_inverse(const bigint_t *a, const bigint_t *m, bigint_t *inv) {
    bigint_t d,x,y;
    extended_euclid(a,m,&d,&x,&y);
    // 若d=1，则x即为逆元模m
    // 可能x为负数，需要x mod m
    bigint_t zero;memset(&zero,0,sizeof(zero));
    bigint_t modx;
    bigint_mod(&x,m,&modx);
    bigint_copy(inv,&modx);
}

