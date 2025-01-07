#include "aes.h"
#include "benchmark.h"

#define BENCHS 10
#define ROUNDS 1

// Print bytes in hexadecimal format
void print_bytes(const unsigned char *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}


// Correctness test function
void test_aes_correctness()
{
    // Fixed example key  0x00012001710198aeda79171460153594  
    // unsigned char key[AES_KEY_SIZE] = {0x00, 0x01, 0x20, 0x01, 0x71, 0x01, 0x98, 0xae, 
    // 0xda, 0x79, 0x17, 0x14, 0x60, 0x15, 0x35, 0x94};
    unsigned char key[AES_KEY_SIZE] = {0x2A, 0x1B, 0xB8, 0x91, 0xF6, 0xF7, 0x64, 0xCD, 
    0x82, 0x93, 0xD0, 0xC9, 0xCE, 0xEF, 0xFC, 0x85};
    // Fixed example plaintext 0x0001000101a198afda78173486153566 
    // unsigned char plaintext[AES_BLOCK_SIZE] = {0x00, 0x01, 0x00, 0x01, 0x01, 0xa1, 0x98, 0xaf,
    // 0xda, 0x78, 0x17, 0x34, 0x86, 0x15, 0x35, 0x66};
    unsigned char plaintext[AES_BLOCK_SIZE] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33};

    // Corresponding ciphertext 0x6cdd596b8f5642cbd23b47981a65422a
    unsigned char correctResult[AES_BLOCK_SIZE] = {0xf8, 0x65, 0x55, 0x55, 0x3a, 0x78, 0xb0, 0x45,
     0x9c, 0xbc, 0x41, 0x19, 0x47, 0x2a, 0x4c, 0xe2};

    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char decrypted[AES_BLOCK_SIZE];

    unsigned char encSubKeys[11][16];
    unsigned char decSubKeys[11][16];

    // Generate encryption subkeys
    if (aes_make_enc_subkeys(key, encSubKeys) != 0)
    {
        printf("Failed to generate encryption subkeys.\n");
        return;
    }
    // Generate decryption subkeys
    if (aes_make_dec_subkeys(key, decSubKeys) != 0)
    {
        printf("Failed to generate decryption subkeys.\n");
        return;
    }

    printf("Original plaintext: ");
    print_bytes(plaintext, AES_BLOCK_SIZE);

    printf("Correct ciphertext: ");
    print_bytes(correctResult, AES_BLOCK_SIZE);

    // Encrypt
    aes_encrypt_file(plaintext,  // 源地址
        16,                               // 数据长度
        encSubKeys,                         // 加密子密钥
        ciphertext); // 加密后的数据写回原地址
    // aes_encrypt_block(plaintext, encSubKeys, ciphertext);
    printf("Encrypted ciphertext: ");
    print_bytes(ciphertext, AES_BLOCK_SIZE);

    // unsigned char ciphertext1[AES_BLOCK_SIZE]= {0x55, 0x55, 0x65, 0xF8, 0x45, 0xB0, 0x78, 0x3A, 0x19, 0x41, 0xBC, 0x9C, 0xE2, 0x4C, 0x2A, 0x47};

    // Decrypt
    aes_decrypt_file(ciphertext,  // 源地址
        16,                               // 数据长度
        decSubKeys,                         // 加密子密钥
        decrypted); // 加密后的数据写回原地址
    // aes_decrypt_block(ciphertext, decSubKeys, decrypted);
    printf("Decrypted plaintext: ");
    print_bytes(decrypted, AES_BLOCK_SIZE);

    // Verify encryption result
    if ((memcmp(ciphertext, correctResult, AES_BLOCK_SIZE) == 0) && (memcmp(plaintext, decrypted, AES_BLOCK_SIZE) == 0))
    {
        printf(">> Correctness test passed.\n\n");
    }
    else
    {
        printf(">> Correctness test failed.\n\n");
    }
}

// Performance test function
void test_aes_performance()
{
    srand((unsigned int)time(NULL));
    // random key
    unsigned char key[AES_KEY_SIZE];
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        key[i] = rand() & 0xFF;
    }
    // random plaintext
    unsigned char plaintext[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        plaintext[i] = rand() & 0xFF;
    }

    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char decrypted[AES_BLOCK_SIZE];
    
    unsigned char encSubKeys[11][16];
    unsigned char decSubKeys[11][16];

    // Generate encryption subkeys
    if (aes_make_enc_subkeys(key, encSubKeys) != 0)
    {
        printf("Failed to generate encryption subkeys.\n");
        return;
    }
    // Generate decryption subkeys
    if (aes_make_dec_subkeys(key, decSubKeys) != 0)
    {
        printf("Failed to generate decryption subkeys.\n");
        return;
    }

    // Perform performance test
    BPS_BENCH_START("AES encryption", BENCHS);
    BPS_BENCH_ITEM(aes_encrypt_block(plaintext, encSubKeys, ciphertext), ROUNDS);
    BPS_BENCH_FINAL(AES_BLOCK_BITS);

    BPS_BENCH_START("AES decryption", BENCHS);
    BPS_BENCH_ITEM(aes_decrypt_block(ciphertext, decSubKeys, decrypted), ROUNDS);
    BPS_BENCH_FINAL(AES_BLOCK_BITS);
}


int main()
{
    // Perform correctness test
    printf(">> Performing correctness test...\n");
    test_aes_correctness();

    // // Perform performance test
    // printf(">> Performing performance test...\n");
    // test_aes_performance();

    return 0;
}


