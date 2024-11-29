#include "../inc/aes.h"
#include "../inc/benchmark.h"

#define BENCHS 10
#define ROUNDS 10000
// #define ROUNDS 1

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
    // Fixed example plaintext 4e45565251554954 
    unsigned char plaintext[AES_BLOCK_SIZE] = {0x00, 0x01, 0x00, 0x01, 0x01, 0xa1, 0x98, 0xaf, 0xda, 0x78, 0x17, 0x34, 0x86, 0x15, 0x35, 0x66};
    // Fixed example key  4b41534849534142  
    unsigned char key[AES_KEY_SIZE] = { 0x00, 0x01, 0x20, 0x01, 0x71, 0x01, 0x98, 0xae, 0xda, 0x79, 0x17, 0x14, 0x60, 0x15, 0x35, 0x94 };
    unsigned char subKeys[16][6];
    // Corresponding ciphertext 763549d38b570c0e
    unsigned char correctResult[AES_BLOCK_SIZE] = { 0x6c,0xdd,0x59,0x6b,0x8f,0x56,0x42,0xcb,0xd2,0x3b,0x47,0x98,0x1a,0x65,0x42,0x2a };

    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char decrypted[AES_BLOCK_SIZE];

    // Generate subkeys
    if (aes_make_subkeys(key, subKeys) != 0)
    {
        printf("Failed to generate subkeys.\n");
        return;
    }

    printf("Original plaintext: ");
    print_bytes(plaintext, AES_BLOCK_SIZE);

    printf("Correct ciphertext: ");
    print_bytes(correctResult, AES_BLOCK_SIZE);

    // Encrypt
    aes_encrypt_block(plaintext, subKeys, ciphertext);
    printf("Encrypted ciphertext: ");
    print_bytes(ciphertext, AES_BLOCK_SIZE);

    // Decrypt
    aes_decrypt_block(ciphertext, subKeys, decrypted);

    // Verify encryption result
    if (memcmp(ciphertext, correctResult, AES_BLOCK_SIZE) == 0)
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
    // Fixed example plaintext 4e45565251554954 
    unsigned char plaintext[AES_BLOCK_SIZE] = { 0x00, 0x01, 0x00, 0x01, 0x01, 0xa1, 0x98, 0xaf, 0xda, 0x78, 0x17, 0x34, 0x86, 0x15, 0x35, 0x66 };
    // Fixed example key  4b41534849534142  
    unsigned char key[AES_KEY_SIZE] = { 0x00, 0x01, 0x20, 0x01, 0x71, 0x01, 0x98, 0xae, 0xda, 0x79, 0x17, 0x14, 0x60, 0x15, 0x35, 0x94 };
    unsigned char subKeys[16][6];

    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char decrypted[AES_BLOCK_SIZE];

    // Generate subkeys
    if (aes_make_subkeys(key, subKeys) != 0)
    {
        printf("Failed to generate subkeys.\n");
        return;
    }

    // Perform performance test
    BPS_BENCH_START("AES encryption", BENCHS);
    BPS_BENCH_ITEM(aes_encrypt_block(plaintext, subKeys, ciphertext), ROUNDS);
    BPS_BENCH_FINAL(AES_BLOCK_BITS);

    BPS_BENCH_START("AES decryption", BENCHS);
    BPS_BENCH_ITEM(aes_decrypt_block(ciphertext, subKeys, decrypted), ROUNDS);
    BPS_BENCH_FINAL(AES_BLOCK_BITS);
}


int main()
{
    // Perform correctness test
    printf(">> Performing correctness test...\n");
    test_aes_correctness();

    // Perform performance test
    printf(">> Performing performance test...\n");
    test_aes_performance();

    return 0;
}
// #include "../inc/des.h"
// #include "../inc/benchmark.h"

// #define BENCHS 100
// #define ROUNDS 100

// // Print bytes in hexadecimal format
// void print_bytes(const unsigned char *data, size_t size)
// {
//     for (size_t i = 0; i < size; i++)
//     {
//         printf("%02X ", data[i]);
//     }
//     printf("\n");
// }


// // Correctness test function
// void test_des_correctness()
// {
//     unsigned char key[DES_KEY_SIZE] = { 0x0E,0x32,0x92,0x32,0xEA,0x6D,0x0D,0x73 }; // Fixed example key 
//     unsigned char plaintext[DES_BLOCK_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }; // Fixed example plaintext
//     unsigned char subKeys[16][6];
//     unsigned char ciphertext[DES_BLOCK_SIZE];
//     unsigned char decrypted[DES_BLOCK_SIZE];

//     // Generate subkeys
//     if (des_make_subkeys(key, subKeys) != 0)
//     {
//         printf("Failed to generate subkeys.\n");
//         return;
//     }

//     printf("Original plaintext: ");
//     print_bytes(plaintext, DES_BLOCK_SIZE);

//     // Encrypt
//     des_encrypt_block(plaintext, subKeys, ciphertext);
//     printf("Encrypted ciphertext: ");
//     print_bytes(ciphertext, DES_BLOCK_SIZE);

//     // Decrypt
//     des_decrypt_block(ciphertext, subKeys, decrypted);
//     printf("Decrypted plaintext: ");
//     print_bytes(decrypted, DES_BLOCK_SIZE);

//     // Verify decryption result
//     if (memcmp(plaintext, decrypted, DES_BLOCK_SIZE) == 0)
//     {
//         printf("Correctness test passed: Decryption matches the original plaintext.\n\n");
//     }
//     else
//     {
//         printf("Correctness test failed: Decryption does not match the original plaintext.\n\n");
//     }
// }

// // Performance test function
// void test_des_performance()
// {
//     unsigned char key[DES_KEY_SIZE] = { 0x0E,0x32,0x92,0x32,0xEA,0x6D,0x0D,0x73 }; // Fixed example key 
//     unsigned char plaintext[DES_BLOCK_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }; // Fixed example plaintext
//     unsigned char subKeys[16][6];
//     unsigned char ciphertext[DES_BLOCK_SIZE];
//     unsigned char decrypted[DES_BLOCK_SIZE];

//     // Generate subkeys
//     if (des_make_subkeys(key, subKeys) != 0)
//     {
//         printf("Failed to generate subkeys.\n");
//         return;
//     }

//     // Perform performance test
//     BPS_BENCH_START("DES encryption", BENCHS);
//     BPS_BENCH_ITEM(des_encrypt_block(plaintext, subKeys, ciphertext), ROUNDS);
//     BPS_BENCH_FINAL(DES_BLOCK_BITS);

//     BPS_BENCH_START("DES decryption", BENCHS);
//     BPS_BENCH_ITEM(des_decrypt_block(ciphertext, subKeys, decrypted), ROUNDS);
//     BPS_BENCH_FINAL(DES_BLOCK_BITS);
// }


// int main()
// {
//     // Perform correctness test
//     printf(">> Performing correctness test...\n");
//     test_des_correctness();

//     // Perform performance test
//     printf(">> Performing performance test...\n");
//     test_des_performance();

//     return 0;
// }
