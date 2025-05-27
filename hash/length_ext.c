/*
 * gcc length_ext.c -o length_ext -lcrypto
 *
 * Usage
 * -----
 * ./length_ext <sha256(M)_hex> <len_padded_bytes> <extension_hex>
 *
 * where
 * sha256(M)_hex – 64 hex chars (digest of M‖pad(M) we stole)
 * len_padded_bytes – multiple of 64 (length of padded bytes used to create the hash of M)
 * extension_hex – *even‑length* hex string for the bytes you want to append (e.g. "4578747261206d7367" == "Extra msg")
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h> /* htole32 */
#include <openssl/sha.h>

/* ---------- portable htole32 ------------------------------------------- */
#ifndef htole32
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define htole32(x) (x)
# else
# define htole32(x) __builtin_bswap32((x))
# endif
#endif

/* ---------- helpers ---------------------------------------------------- */
static int hex_to_state(const char *hex, uint32_t *st)
{
    if (strlen(hex) != 64) return -1;
    for (int i = 0; i < 8; i++) {
        unsigned int w;
        if (sscanf(hex + 8*i, "%8x", &w) != 1) return -1;
        st[i] = htole32(w); /* OpenSSL keeps words LE‑in‑mem */
    }
    return 0;
}

static int hex_to_bytes(const char *hex, unsigned char **out, size_t *outlen)
{
    size_t n = strlen(hex);
    if (n & 1) return -1; /* must be even number of chars */
    *outlen = n / 2;
    *out = malloc(*outlen);
    if (!*out) return -1;
    for (size_t i = 0; i < *outlen; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) {
            free(*out);
            return -1;
        }
        (*out)[i] = (unsigned char)byte;
    }
    return 0;
}

/* ---------- main ------------------------------------------------------- */
int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr,
                "Usage: %s <sha256(M)_hex> <len_padded_bytes> <extension_hex>\n",
                argv[0]);
        return 1;
    }

    /* -- 1. parse the stolen digest ------------------------------------ */
    uint32_t state[8];
    if (hex_to_state(argv[1], state) != 0) {
        fprintf(stderr, "sha256(M) must be exactly 64 hexadecimal characters\n");
        return 1;
    }

    /* -- 2. parse length of M‖pad(M) in bytes -------------------------- */
    size_t len_padded = strtoul(argv[2], NULL, 10);
    if (len_padded == 0 || (len_padded % 64)) {
        fprintf(stderr,
                "len_padded_bytes must be a positive multiple of 64 (got %zu)\n",
                len_padded);
        return 1;
    }

    /* -- 3. decode attacker‑controlled extension ----------------------- */
    unsigned char *ext = NULL;
    size_t ext_len = 0;
    if (hex_to_bytes(argv[3], &ext, &ext_len) != 0) {
        fprintf(stderr, "extension_hex must be valid even‑length hex\n");
        return 1;
    }

    /* -- 4. normal SHA‑256 init --------------------------------------- */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    /* -- 5. advance bit‑counter by hashing dummy bytes ---------------- */
    for (size_t i = 0; i < len_padded; i++)
        SHA256_Update(&ctx, "*", 1); /* content irrelevant */

    /* -- 6. overwrite chaining variables ------------------------------ */
    for (int i = 0; i < 8; i++)
        ctx.h[i] = state[i];

    /* -- 7. append extension ------------------------------------------ */
    SHA256_Update(&ctx, ext, ext_len);

    /* -- 8. final digest ---------------------------------------------- */
    unsigned char out[SHA256_DIGEST_LENGTH];
    SHA256_Final(out, &ctx);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", out[i]);
    putchar('\n');

    free(ext);
    return 0;
}