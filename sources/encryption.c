#include "ransom.h"
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/utils.h>
#include <sodium/randombytes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
** Here, you have to open both files with different permissions : think of what you want to
** to do with each file. Don't forget to check the return values of your syscalls !
*/
bool init_encryption(FILE **to_encrypt, FILE **encrypted,
    const char *filepath, const char *optfilepath)
{
    if (!to_encrypt || !encrypted || !filepath || !optfilepath)
        return false;

    if (sodium_init() < 0) {
        return false;
    }

    *to_encrypt = fopen(filepath, "rb");
    if (!*to_encrypt) {
        perror("fopen (to_encrypt)");
        return false;
    }

    *encrypted = fopen(optfilepath, "wb");
    if (!*encrypted) {
        perror("fopen (encrypted)");
        fclose(*to_encrypt);
        *to_encrypt = NULL;
        return false;
    }

    return true;
}

/*
** I strongly advise to code near the sources/decryption.c code : it is the opposite process.
** Here, you have to initialize the header, then write it in the encrypted file.
*/
int write_header(unsigned char *generated_key, FILE **to_encrypt,
    FILE **encrypted, crypto_secretstream_xchacha20poly1305_state *st)
{
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (!generated_key || !to_encrypt || !encrypted || !*encrypted || !st)
        return EXIT_FAILURE;

    randombytes_buf(generated_key, MAX_KEY_LEN);

    if (crypto_secretstream_xchacha20poly1305_init_push(st, header, generated_key) != 0) {
        fprintf(stderr, "crypto_secretstream_xchacha20poly1305_init_push failed\n");
        return EXIT_FAILURE;
    }

    if (fwrite(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, *encrypted)
            != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        perror("fwrite (header)");
        return EXIT_FAILURE;
    }

    fflush(*encrypted);
    return EXIT_SUCCESS;
}

/*
** The encryption loop really looks the same than the decryption one.
** In decryption_loop, the crypto_secretstream_xchacha20poly1305_pull is used to retrieve data.
** Think of the opposite of "pull" things... The link provided in the README.md about libsodium
** should really help you.
*/
int encryption_loop(FILE *to_encrypt, FILE *encrypted,
    crypto_secretstream_xchacha20poly1305_state st)
{
    if (!to_encrypt || !encrypted)
        return EXIT_FAILURE;

    unsigned char inbuf[CHUNK_SIZE];
    unsigned char outbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t rlen;
    unsigned long long clen;
    int ret = EXIT_SUCCESS;

    while (1) {
        rlen = fread(inbuf, 1, CHUNK_SIZE, to_encrypt);
        if (ferror(to_encrypt)) {
            perror("fread");
            ret = EXIT_FAILURE;
            break;
        }
        int tag = 0;
        if (rlen < CHUNK_SIZE && feof(to_encrypt)) {
            tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        }

        if (rlen == 0) {
            if (feof(to_encrypt)) {
                unsigned long long zero_clen = 0;
                if (crypto_secretstream_xchacha20poly1305_push(&st,
                        outbuf, &zero_clen,
                        NULL, 0,
                        NULL, 0,
                        crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0) {
                    fprintf(stderr, "crypto_secretstream_xchacha20poly1305_push (final empty) failed\n");
                    ret = EXIT_FAILURE;
                } else {
                    if (fwrite(outbuf, 1, (size_t)zero_clen, encrypted) != (size_t)zero_clen) {
                        perror("fwrite (final empty)");
                        ret = EXIT_FAILURE;
                    }
                }
                break;
            } else {
                fprintf(stderr, "fread returned 0 without EOF\n");
                ret = EXIT_FAILURE;
                break;
            }
        } else {
            if (crypto_secretstream_xchacha20poly1305_push(&st,
                    outbuf, &clen,
                    inbuf, (unsigned long long)rlen,
                    NULL, 0,
                    tag) != 0) {
                fprintf(stderr, "crypto_secretstream_xchacha20poly1305_push failed\n");
                ret = EXIT_FAILURE;
                break;
            }

            if (fwrite(outbuf, 1, (size_t)clen, encrypted) != (size_t)clen) {
                perror("fwrite (ciphertext)");
                ret = EXIT_FAILURE;
                break;
            }

            if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
                break;
        }
    }

    fflush(encrypted);
    return ret;
}
