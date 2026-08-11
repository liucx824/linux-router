#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct sha256_ctx {
    uint32_t state[8];
    uint64_t bitlen;   /* 已处理的比特数 */
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256_hex(const uint8_t hash[32], char out[65]);

#endif /* SHA256_H */
