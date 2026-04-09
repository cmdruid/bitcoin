// Standalone SPHINCS+ signer tool for functional testing.
// Reads commands from stdin, writes results to stdout.
// Commands:
//   KEYGEN <sk_seed_hex> <sk_prf_hex> <pk_seed_hex>
//     -> SK <sk_hex> PK <pk_hex>
//   SIGN <sk_hex> <msg_hex>
//     -> SIG <sig_hex>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// Include the SPHINCS+ library directly
extern "C" {
#include "crypto/sphincsplus/slh_dsa.h"
}

static void hex_encode(const uint8_t* data, size_t len, char* out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i] = hex[data[i] >> 4];
        out[2*i+1] = hex[data[i] & 0xf];
    }
    out[2*len] = '\0';
}

static size_t hex_decode(const char* hex_str, uint8_t* out, size_t max_len) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) return 0;
    size_t byte_len = len / 2;
    if (byte_len > max_len) return 0;
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex_str + 2*i, "%2x", &byte) != 1) return 0;
        out[i] = (uint8_t)byte;
    }
    return byte_len;
}

int main() {
    char line[65536];
    while (fgets(line, sizeof(line), stdin)) {
        // Strip newline
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strncmp(line, "KEYGEN ", 7) == 0) {
            // Parse: KEYGEN <sk_seed_hex> <sk_prf_hex> <pk_seed_hex>
            char sk_seed_hex[256], sk_prf_hex[256], pk_seed_hex[256];
            if (sscanf(line + 7, "%255s %255s %255s", sk_seed_hex, sk_prf_hex, pk_seed_hex) != 3) {
                printf("ERR bad keygen args\n");
                fflush(stdout);
                continue;
            }
            uint8_t sk_seed[16], sk_prf[16], pk_seed[16];
            hex_decode(sk_seed_hex, sk_seed, 16);
            hex_decode(sk_prf_hex, sk_prf, 16);
            hex_decode(pk_seed_hex, pk_seed, 16);

            uint8_t sk[64], pk[32];
            slh_keygen_internal(sk, pk, sk_seed, sk_prf, pk_seed, &slh_dsa_bitcoin);

            char sk_hex[129], pk_hex[65];
            hex_encode(sk, 64, sk_hex);
            hex_encode(pk, 32, pk_hex);
            printf("SK %s PK %s\n", sk_hex, pk_hex);
            fflush(stdout);

        } else if (strncmp(line, "SIGN ", 5) == 0) {
            // Parse: SIGN <sk_hex> <msg_hex>
            char sk_hex[256], msg_hex[256];
            if (sscanf(line + 5, "%255s %255s", sk_hex, msg_hex) != 2) {
                printf("ERR bad sign args\n");
                fflush(stdout);
                continue;
            }
            uint8_t sk[64], msg[256];
            size_t sk_len = hex_decode(sk_hex, sk, 64);
            size_t msg_len = hex_decode(msg_hex, msg, 256);
            if (sk_len != 64) {
                printf("ERR bad sk length %zu\n", sk_len);
                fflush(stdout);
                continue;
            }

            uint8_t sig[8192]; // large enough for any param set
            size_t sig_len = slh_sign_internal(sig, msg, msg_len, sk, NULL, &slh_dsa_bitcoin);

            char* sig_hex = (char*)malloc(sig_len * 2 + 1);
            hex_encode(sig, sig_len, sig_hex);
            printf("SIG %s\n", sig_hex);
            fflush(stdout);
            free(sig_hex);

        } else if (strncmp(line, "QUIT", 4) == 0) {
            break;
        } else {
            printf("ERR unknown command\n");
            fflush(stdout);
        }
    }
    return 0;
}
