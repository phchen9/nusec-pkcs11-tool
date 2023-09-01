#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

CK_RV aes_cbc_sample(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, FILE *input_file) {
    CK_RV rv;

    CK_BYTE_PTR plaintext;
    CK_ULONG plaintext_length;
    CK_BYTE_PTR ciphertext;
    CK_ULONG ciphertext_length = 0;
    int length;

    fseek(input_file, 0, SEEK_END);
    length = ftell(input_file);
    if (length < 0) {
        perror("ftell");
        rv = CKR_GENERAL_ERROR;
        return rv;
    }
    plaintext_length = (CK_ULONG) length;

    printf("Plaintext length: %lu\n", plaintext_length);

    plaintext = malloc(plaintext_length);
    if (plaintext == NULL) {
        printf("Could not allocate memory for plaintext\n");
        rv = CKR_HOST_MEMORY;
        return rv;
    }

    fseek(input_file, 0, SEEK_SET);
    length = fread(plaintext, 1, plaintext_length, input_file);
    if (length != plaintext_length) {
        perror("fread");
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    // Prepare the mechanism 
    // The IV is hardcoded to all 0x01 bytes for this example.
    CK_BYTE iv[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    CK_MECHANISM mech = {CKM_AES_CBC_PAD, iv, 16};

    //**********************************************************************************************
    // Encrypt
    //**********************************************************************************************    

    rv = funcs->C_EncryptInit(session, &mech, key);
    if (CKR_OK != rv) {
        printf("Encryption Init failed: %lu\n", rv);
        goto done;
    }

    // Determine how much memory will be required to hold the ciphertext.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, NULL, &ciphertext_length);
    if (CKR_OK != rv) {
        printf("Encryption failed: %lu\n", rv);
        goto done;
    }

    // Allocate the required memory.
    ciphertext = malloc(ciphertext_length);
    if (NULL == ciphertext) {
        printf("Could not allocate memory for ciphertext\n");
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    memset(ciphertext, 0, ciphertext_length);

    // Encrypt the data.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, ciphertext, &ciphertext_length);
    if (CKR_OK != rv) {
        printf("Encryption failed: %lu\n", rv);
        goto done;
    }

    // Print just the ciphertext in hex format
    printf("Ciphertext: ");
    print_bytes_as_hex(ciphertext, ciphertext_length);
    printf("Ciphertext length: %lu\n", ciphertext_length);

done:
    if (NULL != plaintext) {
        free(plaintext);
    }

    if (NULL != ciphertext) {
        free(ciphertext);
    }
    return rv;
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;

    struct pkcs_arguments args = {0};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return EXIT_FAILURE;
    }

    rv = pkcs11_initialize(args.library);
    if (CKR_OK != rv) {
        return EXIT_FAILURE;
    }
    rv = pkcs11_open_session(args.pin, &session);
    if (CKR_OK != rv) {
        return EXIT_FAILURE;
    }

    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_BYTE *id = NULL;
    CK_ULONG id_len = 0;

    if (hexstring_to_bytes(args.object_id, &id, &id_len) < 0) {
        return EXIT_FAILURE;
    }

    CK_ULONG count = 0;
    CK_OBJECT_HANDLE *found_objects = NULL;
    CK_ATTRIBUTE attr[] = {
            {CKA_CLASS, &class, sizeof(CK_OBJECT_CLASS)},
            {CKA_ID, id, id_len},
    };

    rv = pkcs11_find_by_attr(session, attr, sizeof(attr)/sizeof(attr[0]), &count, &found_objects);
    if ((CKR_OK != rv) || (count == 0)) {
        fprintf(stderr, "Could not find object\n");
        return EXIT_FAILURE;
    } else {
        printf("count=[%lu]\n", count);
        printf("Found object with handle [%lu]\n", found_objects[0]);
    }

    printf("\nEncrypt/Decrypt with AES CBC\n");
    rv = aes_cbc_sample(session, found_objects[0], args.input_file);
    if (CKR_OK != rv) {
        return EXIT_FAILURE;
    }

    pkcs11_finalize_session(session);

    if (args.input_file) {
        fclose(args.input_file);
    }

    return 0;
}