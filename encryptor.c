#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_SIZE 8
#define AES_KEY_SIZE 32 // 256 bits
#define AES_BLOCK_SIZE 16

void derive_key_and_iv(const char *password, unsigned char *salt, unsigned char *key, unsigned char *iv) {
    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (unsigned char *)password, strlen(password), 1, key, iv)) {
        fprintf(stderr, "Key derivation failed.\n");
    }
}

void generate_random_salt(unsigned char *salt) {
    if (!RAND_bytes(salt, SALT_SIZE)) {
        fprintf(stderr, "Failed to generate random salt.\n");
    }
}

__attribute__((visibility("default"))) int Encrypt(const char *file_path, const char *password) {
    FILE *input_file = fopen(file_path, "rb");
    if (!input_file) {
        perror("Error opening input file");
        return 1;
    }

    char output_file_path[256];
    snprintf(output_file_path, sizeof(output_file_path), "%s.enc", file_path);
    FILE *output_file = fopen(output_file_path, "wb");
    if (!output_file) {
        perror("Error opening output file");
        fclose(input_file);
        return 1;
    }
    unsigned char salt[SALT_SIZE];
    generate_random_salt(salt);

    fwrite(salt, 1, SALT_SIZE, output_file);

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    derive_key_and_iv(password, salt, key, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer_in[AES_BLOCK_SIZE];
    unsigned char buffer_out[AES_BLOCK_SIZE + AES_BLOCK_SIZE];
    int len_in, len_out;

    while ((len_in = fread(buffer_in, 1, AES_BLOCK_SIZE, input_file)) > 0) {
        EVP_EncryptUpdate(ctx, buffer_out, &len_out, buffer_in, len_in);
        fwrite(buffer_out, 1, len_out, output_file);
    }

    EVP_EncryptFinal_ex(ctx, buffer_out, &len_out);
    fwrite(buffer_out, 1, len_out, output_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(output_file);

    return 0;
}

__attribute__((visibility("default"))) int Decrypt(const char *file_path, const char *password) {
    FILE *input_file = fopen(file_path, "rb");
    if (!input_file) {
        perror("Error opening input file");
        return 1;
    }

    char output_file_path[256];
    snprintf(output_file_path, sizeof(output_file_path), "%s.dec", file_path);
    FILE *output_file = fopen(output_file_path, "wb");
    if (!output_file) {
        perror("Error opening output file");
        fclose(input_file);
        return 1;
    }

    unsigned char salt[SALT_SIZE];
    if (fread(salt, 1, SALT_SIZE, input_file) != SALT_SIZE) {
        fprintf(stderr, "Failed to read salt from file.\n");
        fclose(input_file);
        fclose(output_file);
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    derive_key_and_iv(password, salt, key, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer_in[AES_BLOCK_SIZE];
    unsigned char buffer_out[AES_BLOCK_SIZE + AES_BLOCK_SIZE];
    int len_in, len_out;

    while ((len_in = fread(buffer_in, 1, AES_BLOCK_SIZE, input_file)) > 0) {
        EVP_DecryptUpdate(ctx, buffer_out, &len_out, buffer_in, len_in);
        fwrite(buffer_out, 1, len_out, output_file);
    }

    EVP_DecryptFinal_ex(ctx, buffer_out, &len_out);
    fwrite(buffer_out, 1, len_out, output_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(output_file);

    return 0;
}


