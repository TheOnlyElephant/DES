#include "../inc/sm4.h"

//循环左移n位
static uint32_t rotl(uint32_t a, uint8_t n)
{
    return (a << n) | (a >> (32 - n));
}

// 输入：b[4]，n
// 作用：将一个4字节的数组转换为一个32位的无符号整数
static uint32_t load_u32_be(const uint8_t *b, uint32_t n)
{
    return ((uint32_t)b[4 * n] << 24) |
           ((uint32_t)b[4 * n + 1] << 16) |
           ((uint32_t)b[4 * n + 2] << 8) |
           ((uint32_t)b[4 * n + 3]);
}

// 输入：v，b[4]
// 作用：将一个32位的无符号整数转换为一个4字节的数组
static void store_u32_be(uint32_t v, uint8_t *b)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

static uint32_t SM4_T_non_lin_sub(uint32_t X)
{
    uint32_t t = 0;

    t |= ((uint32_t)SM4_S[(uint8_t)(X >> 24)] && 0xFF) << 24;
    t |= ((uint32_t)SM4_S[(uint8_t)(X >> 16)] && 0xFF) << 16;
    t |= ((uint32_t)SM4_S[(uint8_t)(X >> 8)] && 0xFF) << 8;
    t |= SM4_S[(uint8_t)X];

    return t;
}

static uint32_t SM4_T_slow(uint32_t X)
{
    uint32_t t = SM4_T_non_lin_sub(X);

    /*
     * L linear transform
     */
    return t ^ rotl(t, 2) ^ rotl(t, 10) ^ rotl(t, 18) ^ rotl(t, 24);
}

static uint32_t SM4_T(uint32_t X)
{
    return SM4_SBOX_T0[(uint8_t)(X >> 24)] ^
           SM4_SBOX_T1[(uint8_t)(X >> 16)] ^
           SM4_SBOX_T2[(uint8_t)(X >> 8)] ^
           SM4_SBOX_T3[(uint8_t)X];
}

static uint32_t SM4_key_sub(uint32_t X)
{
    uint32_t t = SM4_T_non_lin_sub(X);

    return t ^ rotl(t, 13) ^ rotl(t, 23);
}


int ossl_sm4_set_key(const uint8_t *key, SM4_KEY *ks) {
    /*
     * Family Key
     */
    static const uint32_t FK[4] = {
        0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
    };

    /*
     * Constant Key
     */
    static const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    unsigned char roundKeys[32][4];
    uint32_t K[4], rk[32];
    for (int i = 0; i < 4; ++i) {
        K[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
               ((uint32_t)key[4 * i + 2] << 8) | (uint32_t)key[4 * i + 3];
        K[i] ^= FK[i];
    }
    for (int i = 0; i < 32; ++i) {
        rk[i] = K[0] ^ T_prime(K[1] ^ K[2] ^ K[3] ^ CK[i]);
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = rk[i];
        for (int j = 0; j < 4; ++j) {
            roundKeys[i][j] = (rk[i] >> (24 - 8 * j)) & 0xFF;
        }
    }

    // for(int i = 0; i < 32; i++) {
    //     printf("%02x %02x %02x %02x\n", roundKeys[i][0], roundKeys[i][1], roundKeys[i][2], roundKeys[i][3]);
    // }

    for(int i = 0; i < 32; i++) {
        uint32_t temp = 0;
        load_u32_be(roundKeys[i], temp);
        ks->rk[i] = roundKeys[i];
    }
    return 0;

    // uint32_t K[36];
    // int i;

    // K[0] = load_u32_be(key, 0) ^ FK[0];
    // K[1] = load_u32_be(key, 1) ^ FK[1];
    // K[2] = load_u32_be(key, 2) ^ FK[2];
    // K[3] = load_u32_be(key, 3) ^ FK[3];

    // printf("%x %x %x\n", load_u32_be(key, 0), FK[0], K[0]);

    // for(int i = 0; i < 4; i++) {
    //     printf("%02x ", load_u32_be(key, i));
    // }
    // printf("\n");

    // for (i = 0; i < SM4_KEY_SCHEDULE; i = i + 4) {
    //     K[i+0] ^= SM4_key_sub(K[1] ^ K[2] ^ K[3] ^ CK[i]);
    //     K[i+1] ^= SM4_key_sub(K[2] ^ K[3] ^ K[0] ^ CK[i + 1]);
    //     K[i+2] ^= SM4_key_sub(K[3] ^ K[0] ^ K[1] ^ CK[i + 2]);
    //     K[i+3] ^= SM4_key_sub(K[0] ^ K[1] ^ K[2] ^ CK[i + 3]);
    //     ks->rk[i    ] = K[0];
    //     ks->rk[i + 1] = K[1];
    //     ks->rk[i + 2] = K[2];
    //     ks->rk[i + 3] = K[3];
    // }

    // for (i = 0; i < 32; i++) {
    //     K[i+4] ^= SM4_key_sub(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]);
    //     // K[i+1] ^= SM4_key_sub(K[2] ^ K[3] ^ K[0] ^ CK[i + 1]);
    //     // K[i+2] ^= SM4_key_sub(K[3] ^ K[0] ^ K[1] ^ CK[i + 2]);
    //     // K[i+3] ^= SM4_key_sub(K[0] ^ K[1] ^ K[2] ^ CK[i + 3]);
    //     ks->rk[i] = K[i+4];
    //     // ks->rk[i + 1] = K[1];
    //     // ks->rk[i + 2] = K[2];
    //     // ks->rk[i + 3] = K[3];
    // }

    // for(int i = 0; i < 36; i++) {
    //     printf("%02x ", K[i] );
    // }
    // printf("\n");

    // return 1;
}

#define SM4_RNDS(k0, k1, k2, k3, F)          \
      do {                                   \
         B0 ^= F(B1 ^ B2 ^ B3 ^ ks->rk[k0]); \
         B1 ^= F(B0 ^ B2 ^ B3 ^ ks->rk[k1]); \
         B2 ^= F(B0 ^ B1 ^ B3 ^ ks->rk[k2]); \
         B3 ^= F(B0 ^ B1 ^ B2 ^ ks->rk[k3]); \
      } while(0)

void ossl_sm4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)
{
    uint32_t B0 = load_u32_be(in, 0);
    uint32_t B1 = load_u32_be(in, 1);
    uint32_t B2 = load_u32_be(in, 2);
    uint32_t B3 = load_u32_be(in, 3);

    /*
     * Uses byte-wise sbox in the first and last rounds to provide some
     * protection from cache based side channels.
     */
    SM4_RNDS( 0,  1,  2,  3, SM4_T_slow);
    SM4_RNDS( 4,  5,  6,  7, SM4_T);
    SM4_RNDS( 8,  9, 10, 11, SM4_T);
    SM4_RNDS(12, 13, 14, 15, SM4_T);
    SM4_RNDS(16, 17, 18, 19, SM4_T);
    SM4_RNDS(20, 21, 22, 23, SM4_T);
    SM4_RNDS(24, 25, 26, 27, SM4_T);
    SM4_RNDS(28, 29, 30, 31, SM4_T_slow);

    store_u32_be(B3, out);
    store_u32_be(B2, out + 4);
    store_u32_be(B1, out + 8);
    store_u32_be(B0, out + 12);
}

void ossl_sm4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)
{
    uint32_t B0 = load_u32_be(in, 0);
    uint32_t B1 = load_u32_be(in, 1);
    uint32_t B2 = load_u32_be(in, 2);
    uint32_t B3 = load_u32_be(in, 3);

    SM4_RNDS(31, 30, 29, 28, SM4_T_slow);
    SM4_RNDS(27, 26, 25, 24, SM4_T);
    SM4_RNDS(23, 22, 21, 20, SM4_T);
    SM4_RNDS(19, 18, 17, 16, SM4_T);
    SM4_RNDS(15, 14, 13, 12, SM4_T);
    SM4_RNDS(11, 10,  9,  8, SM4_T);
    SM4_RNDS( 7,  6,  5,  4, SM4_T);
    SM4_RNDS( 3,  2,  1,  0, SM4_T_slow);

    store_u32_be(B3, out);
    store_u32_be(B2, out + 4);
    store_u32_be(B1, out + 8);
    store_u32_be(B0, out + 12);
}

int main() {
    unsigned char key[4][4] = {
        {0x01, 0x23, 0x45, 0x67}, 
        {0x89, 0xab, 0xcd, 0xef}, 
        {0xfe, 0xdc, 0xba, 0x98}, 
        {0x76, 0x54, 0x32, 0x10} };
    SM4_KEY expandedKey;
    if(ossl_sm4_set_key(key, &expandedKey) == 0) {
        // printf("Around Key\n");
        // for(int i = 0; i < 32; i++) {
        //     printf("%02x ", expandedKey.rk[i] );
        // }
    } else {
        // printf("Around Key\n");
        // for(int i = 0; i < 32; i++) {
        //     printf("%02x ", expandedKey.rk[i] );
        // }
    }

    expandedKey.rk = {
        0xf12186f9,
        0x41662b61,
        0x5a6ab19a,
        0x7ba92077,
        0x367360f4,
        0x776a0c61,
        0xb6bb89b3,
        0x24763151,
        0xa520307c,
        0xb7584dbd,
        0xc30753ed,
        0x7ee55b57,
        0x6988608c,
        0x30d895b7,
        0x44ba14af,
        0x104495a1,
        0xd120b428,
        0x73b55fa3,
        0xcc874966,
        0x92244439,
        0xe89e641f,
        0x98ca015a,
        0xc7159060,
        0x99e1fd2e,
        0xb79bd80c,
        0x1d2115b0,
        0x0e228aeb,
        0xf1780c81,
        0x428d3654,
        0x62293496,
        0x01cf72e5,
        0x9124a012
    };
    printf("Around Key\n");
    for(int i = 0; i < 32; i++) {
        printf("%08x\n", expandedKey.rk[i] );
    }

    unsigned char input[4][4] = {
        {0x01, 0x23, 0x45, 0x67}, 
        {0x89, 0xab, 0xcd, 0xef}, 
        {0xfe, 0xdc, 0xba, 0x98}, 
        {0x76, 0x54, 0x32, 0x10} };
    unsigned char output[4][4] = {0};
    ossl_sm4_encrypt(input, output, &expandedKey);
    
    printf("Encrypt\n");
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            printf("%02x ", output[i][j]);
        }
        printf("\n");
    }
    
    unsigned char result[4][4] = {0};
    ossl_sm4_decrypt(output, result, &expandedKey);
    
    printf("Decrypt\n");
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            printf("%02x ", result[i][j]);
        }
        printf("\n");
    }
}