/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>

#include "gopt.h"
#include "common.h"

#define DEFAULT_PKCS11_LIBRARY_PATH "/opt/softhsm2/lib/softhsm/libsofthsm2.so"

CK_BBOOL true_val = TRUE;
CK_BBOOL false_val = FALSE;

static void show_help(void) {
    printf("\n\t--pin <password>\n\t[--library <path/to/pkcs11>]\n");
}

int get_pkcs_args(int argc, char** argv, struct pkcs_arguments* args) {
    if (!args || !argv || argc == 0) {
        return -1;
    }

    struct option options[6];

    options[0].long_name  = "pin";
    options[0].short_name = 0;
    options[0].flags      = GOPT_ARGUMENT_REQUIRED;

    options[1].long_name  = "library";
    options[1].short_name = 0;
    options[1].flags      = GOPT_ARGUMENT_REQUIRED;

    options[2].long_name  = "raw-peer-pub-key";
    options[2].short_name = 0;
    options[2].flags      = GOPT_ARGUMENT_REQUIRED;

    options[3].long_name  = "object-id";
    options[3].short_name = 0;
    options[3].flags      = GOPT_ARGUMENT_REQUIRED;

    options[4].long_name  = "input-filename";
    options[4].short_name = 0;
    options[4].flags      = GOPT_ARGUMENT_REQUIRED;

    options[5].flags      = GOPT_LAST;

    gopt (argv, options);

    // Check for required argument, pin.
    if (options[0].count != 1) {
        show_help();
        return -1;
    }

    args->pin = options[0].argument;
    args->library = options[1].argument;

    if (!args->library) {
        args->library = DEFAULT_PKCS11_LIBRARY_PATH;
    }

    if (options[2].argument) {
        args->raw_peer_pub_key = options[2].argument;
    }

    if (options[3].argument) {
        args->object_id = options[3].argument;
    }

    if (options[4].argument) {
        args->input_file = fopen(options[4].argument, "rb");

        if (!args->input_file) {
            perror(options[4].argument);
            return -1;
        }
    }

    return 0;
}

int hexstring_to_bytes(char *hexstring, CK_BYTE **bytes, CK_ULONG *bytes_len) 
{
    size_t len;
    char *pos = hexstring;
    size_t i;

    if (!hexstring || !bytes || !bytes_len) {
        return -1;
    }

    len = strlen(hexstring);
    if (len % 2 != 0) {
        fprintf(stderr, "The length of hexstring is odd number\n");
        return -1;
    }

    len = len / 2;
    *bytes_len = len;

    *bytes = malloc(len * sizeof(CK_BYTE));
    if (!(*bytes)) {
        return -1;
    }
    
    for (i = 0; i < len; i++) {
        sscanf(pos, "%2hhx", &(*bytes)[i]);
        pos += 2;
    }

    return 0;
}

/**
 * Converts a byte array to a hex string.
 * This function will allocate the appropriate memory for the hex string.
 * If a valid pointer is passed, that pointer will be reallocated. This
 * allows the caller to reuse the same pointer through multiple calls.
 * @param bytes
 * @param bytes_len
 * @param hex
 * @return
 */
int bytes_to_new_hexstring(char *bytes, size_t bytes_len, unsigned char **hex_array) {
    if (!bytes || !hex_array) {
        return -1;
    }

    unsigned char *tmp = realloc(*hex_array, bytes_len * 2 + 1);
    if (!tmp) {
        if (*hex_array) {
            free(*hex_array);
        }
        return -1;
    }
    *hex_array = tmp;
    memset(*hex_array, 0, bytes_len * 2 + 1);

    char values[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    for (size_t i = 0, j = 0; i < bytes_len; i++, j += 2) {
        *((*hex_array) + j) = values[bytes[i] >> 4 & 0x0f];
        *((*hex_array) + j + 1) = values[bytes[i] & 0x0f];
    }

    return 0;
}

/**
 * Prints a byte array as a hex string.
 * @param bytes
 * @param bytes_len
 * @return
 */
int print_bytes_as_hex(char *bytes, size_t bytes_len) {
    if (!bytes || bytes_len < 1) {
        return -1;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        printf("0x%02X, ", bytes[i]);
    }
    printf("\n");

    return 0;
}
