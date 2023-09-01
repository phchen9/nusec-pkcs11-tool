#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "common.h"

CK_RV generate_ecdh_derive_key(CK_SESSION_HANDLE session,
                               CK_ULONG key_id_len,
                               CK_BYTE *key_id,
                               CK_OBJECT_HANDLE_PTR ec_base_private_key,
                               CK_ULONG ec_peer_public_key_len,
                               CK_BYTE *ec_peer_public_key,
                               CK_OBJECT_HANDLE_PTR derived_key)
{
    CK_RV rv = CKR_OK;

    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG aesKeyLen = 32;
    CK_ECDH1_DERIVE_PARAMS params = { CKD_NULL, 0, NULL, ec_peer_public_key_len, ec_peer_public_key };
    CK_MECHANISM derive_mechanism = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    CK_UTF8CHAR key_label[] = "shared-secret";

    CK_ATTRIBUTE derivekey_template[] = {
          { CKA_CLASS, &keyClass, sizeof(keyClass) },
          { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
          { CKA_ENCRYPT, &true_val, sizeof(CK_BBOOL) },
          { CKA_DECRYPT, &true_val, sizeof(CK_BBOOL) },
          { CKA_VALUE_LEN, &aesKeyLen, sizeof(aesKeyLen) },
          { CKA_TOKEN, &true_val, sizeof(CK_BBOOL) },
          { CKA_LABEL, key_label, (unsigned long)strlen(key_label) },
          { CKA_ID, key_id, key_id_len },
          { CKA_EXTRACTABLE, &true_val, sizeof(CK_BBOOL) }, // for debug
    };

    rv = funcs->C_DeriveKey(session,
                            &derive_mechanism,
                            *ec_base_private_key,
                            derivekey_template,
                            sizeof(derivekey_template) / sizeof(CK_ATTRIBUTE),
                            derived_key);

    return rv;
}

int main(int argc, char **argv)
{
    CK_SESSION_HANDLE session;
    CK_RV rv;

    struct pkcs_arguments args = {0};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return EXIT_FAILURE;
    }

    if (CKR_OK != pkcs11_initialize(args.library)) {
        return EXIT_FAILURE;
    }

    if (CKR_OK != pkcs11_open_session(args.pin, &session)) {
        fprintf(stderr, "Could not open session\n");
        return EXIT_FAILURE;
    }

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_BYTE label[] = "shared-secret";
    CK_BYTE *id = NULL;
    CK_ULONG id_len = 0;

    if (hexstring_to_bytes(args.object_id, &id, &id_len) < 0) {
        return EXIT_FAILURE;
    }

    CK_ULONG count = 0;
    CK_OBJECT_HANDLE *found_objects = NULL;
    CK_ATTRIBUTE attr[] = {
            {CKA_CLASS, &class, sizeof(CK_OBJECT_CLASS)},
            {CKA_LABEL, label, (CK_ULONG) strlen((char *)label)},
            {CKA_ID, id, id_len},
    };

    rv = pkcs11_find_by_attr(session, attr, sizeof(attr)/sizeof(attr[0]), &count, &found_objects);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not find object\n");
        return EXIT_FAILURE;
    } else {
        printf("Found object with handle [%lu]\n", found_objects[0]);
    }

    CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
    CK_BYTE *peer_pub_key = NULL;
    CK_ULONG peer_pub_key_len = 0;

    if (hexstring_to_bytes(args.raw_peer_pub_key, &peer_pub_key, &peer_pub_key_len) < 0) {
        return EXIT_FAILURE;
    }

    rv = generate_ecdh_derive_key(session, id_len, id, &found_objects[0],
                                  peer_pub_key_len, peer_pub_key, &derived_key);

    if (peer_pub_key) {
        free(peer_pub_key);
        peer_pub_key = NULL;
    }

    if (found_objects) {
        free(found_objects);
        found_objects = NULL;
    }

    if (id) {
        free(id);
        id = NULL;
    }

    pkcs11_finalize_session(session);

    return 0;
}
