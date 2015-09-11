/**
 * File: dtsp.c
 *
 * Optimised ANSI C code for Data Transfer Security Protocol (DTSP).
 *
 * @author Alexander Lokhman <alex.lokhman@gmail.com>
 *
 * Copyright (c) 2015 Alexander Lokhman
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Created on August 2015
 */

#include "dtsp.h"

#define UINT32_PUT(u8, u32) {           \
    (u8)[0] = (uint8_t) ((u32) >> 24);  \
    (u8)[1] = (uint8_t) ((u32) >> 16);  \
    (u8)[2] = (uint8_t) ((u32) >>  8);  \
    (u8)[3] = (uint8_t) ( u32       );  }

static void dtsp_copy(uint8_t *out, const uint32_t *in, size_t n) {
    size_t i;

    for (i = 0; i < n; i++) {
        UINT32_PUT(out, in[i]);
        out += 4;
    }
}

static void dtsp_hash(uint8_t out[16], const uint8_t *in, size_t n) {
    md5_ctx_t ctx;

    md5_init(&ctx);
    md5_update(&ctx, in, n);
    md5_finish(&ctx, out);
}

static void dtsp_key(isaac_ctx_t *key_ctx, uint8_t key[32]) {
    // first 8 32-bit key numbers
    dtsp_copy(key, key_ctx->r, 8);
}

static void dtsp_iv(isaac_ctx_t *key_ctx, uint8_t iv[16], uint8_t sync) {
    // (32+sync) 4 32-bit key numbers
    dtsp_copy(iv, key_ctx->r + 32 + sync, 4);
}

static void dtsp_mac(isaac_ctx_t *key_ctx, uint8_t mac[16], uint8_t udid[16], uint8_t sync, uint32_t crc) {
    uint8_t r[48];

    memcpy(r, udid, 16);
    // (128+sync) 7 32-bit key numbers
    dtsp_copy(r + 16, key_ctx->r + 128 + sync, 7);
    UINT32_PUT(r + 44, crc);

    dtsp_hash(mac, r, 48);
}

static void dtsp_udid(dtsp_ctx_t *ctx, uint8_t udid[16]) {
    uint32_t rk = isaac_rand(&ctx->udid_ctx);
    uint32_t t = (uint32_t) time(0);
    uint8_t r[24 /* 16+4+4 */];

    memcpy(r, ctx->udid, 16);
    memcpy(r + 16, &rk, 4);
    memcpy(r + 20, &t, 4);

    dtsp_hash(udid, r, 24);
}

static int dtsp_udid_compare(const void *a, const void *b) {
    return memcmp(a, b, 16);
}

static uint8_t dtsp_update(dtsp_ctx_t *ctx) {
    uint32_t t = (uint32_t) time(0), _t /* previous time */;
    uint8_t *ptr, sync = t % DTSP_INTERVAL;
    size_t n = ctx->seed.n + 4;

    if (t - sync == ctx->time)
        return sync;

    ptr = (uint8_t *) malloc(n);
    memcpy(ptr + 4, ctx->seed.buf, ctx->seed.n);

    t -= sync;
    _t = t - DTSP_INTERVAL;

    if (_t == ctx->time) {
        memcpy(&ctx->_key_ctx, &ctx->key_ctx, sizeof(isaac_ctx_t));
        memcpy(ctx->_key, ctx->key, 32);
    } else {
        UINT32_PUT(ptr, _t);
        isaac_seed(&ctx->_key_ctx, ptr, n);
        dtsp_key(&ctx->_key_ctx, ctx->_key);
    }

    ctx->time = t;

    UINT32_PUT(ptr, t);
    isaac_seed(&ctx->key_ctx, ptr, n);
    dtsp_key(&ctx->key_ctx, ctx->key);

    tdestroy(ctx->cache, free);
    free(ptr);

    return sync;
}

/**
 * Initialise DTSP context structure.
 *
 * @param ctx   DTSP context
 * @param seed  Strictly defined seed
 * @param udid  Unique device identifier
 *
 * @return void
 */
void dtsp_init(dtsp_ctx_t *ctx, const dtsp_buf_t *seed, const dtsp_buf_t *udid) {
    uint8_t *ptr;
    size_t n;

    assert(seed != 0);
    assert(udid != 0);

    // clear context
    memset(ctx, 0, sizeof(dtsp_ctx_t));

    // copy seed
    ctx->seed = *seed;

    // generate UDID hash
    n = udid->n + seed->n;
    ptr = (uint8_t *) malloc(n);
    memcpy(ptr, udid->buf, udid->n);
    memcpy(ptr + udid->n, seed->buf, seed->n);
    dtsp_hash(ctx->udid, ptr, n);
    free(ptr);

    // seed UDID context
    isaac_seed(&ctx->udid_ctx, ctx->udid, 16);
}

/**
 * DTSP encryption routine.
 *
 *  4    1 16               N+(16)                 16
 * |HDR.|S|UDID............|CIPHER................|MAC.............|
 *
 * @param ctx   DTSP context
 * @param out   Output buffer
 * @param in    Input buffer
 * @param n     Input length
 *
 * @return (N+[DTSP_PADDING])
 */
size_t dtsp_encrypt_bytes(dtsp_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t n) {
    uint8_t sync, iv[16], *ptr = out;
    aes_ctx_t aes_ctx;

    // header [BE 4 bytes]
    UINT32_PUT(out, DTSP_HEADER);
    out += 4;

    // sync value [1 byte]
    sync = dtsp_update(ctx);
    memcpy(out, &sync, 1);
    out += 1;

    // UDID [16 bytes]
    dtsp_udid(ctx, out);
    out += 16;

    // AES [n+16? bytes]
    dtsp_iv(&ctx->key_ctx, iv, sync);
    aes_init(&aes_ctx, DTSP_AES, ctx->key, iv);
    out += aes_encrypt(&aes_ctx, out, in, n);

    // MAC [16 bytes]
    dtsp_mac(&ctx->key_ctx, out, ptr + 5, sync, crc32(ptr, out - ptr));

    return out + 16 - ptr;
}

/**
 * DTSP decryption routine.
 *
 * @param ctx   DTSP context
 * @param out   Output buffer
 * @param in    Input buffer
 * @param n     Input length
 *
 * @return (N-[DTSP_PADDING]) or dtsp_status_t
 */
ssize_t dtsp_decrypt_bytes(dtsp_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t n) {
    uint8_t *key, *udid, mac[16], iv[16];
    isaac_ctx_t *key_ctx;
    aes_ctx_t aes_ctx;

    if (n < DTSP_PADDING)
        return DTSP_STATUS_NODATA;

    // header [BE 4 bytes]
    if (in[0] != ((DTSP_HEADER >> 24) & 0xFF) ||
        in[1] != ((DTSP_HEADER >> 16) & 0xFF) ||
        in[2] != ((DTSP_HEADER >>  8) & 0xFF) ||
        in[3] != ((DTSP_HEADER      ) & 0xFF))
        return DTSP_STATUS_BADHEADER;

    // UDID [16 bytes]
    if (tfind(&in[5], (void *) &ctx->cache, dtsp_udid_compare) != 0)
        return DTSP_STATUS_DUPLICATE;

    // sync value [1 byte]
    if (in[4] > dtsp_update(ctx)) {
        key_ctx = &ctx->_key_ctx;
        key = ctx->_key;
    } else {
        key_ctx = &ctx->key_ctx;
        key = ctx->key;
    }

    // MAC [16 bytes]
    dtsp_mac(key_ctx, mac, (uint8_t *) &in[5], in[4], crc32(in, n - 16));
    if (memcmp(in + n - 16, mac, 16) != 0)
        return DTSP_STATUS_BADMAC;

    // UDID -> cache
    udid = (uint8_t *) malloc(16);
    memcpy(udid, (uint8_t *) &in[5], 16);
    if (tsearch(udid, (void *) &ctx->cache, dtsp_udid_compare) == 0)
        return DTSP_STATUS_FULL;

    // AES [n+16? bytes]
    dtsp_iv(key_ctx, iv, in[4]);
    aes_init(&aes_ctx, DTSP_AES, key, iv);

    // cipher from (0 + 4+1+16) to (n - 4+1+16+16)
    return aes_decrypt(&aes_ctx, out, in + 21, n - 37);
}

/**
 * Free memory used by DTSP context structure.
 *
 * @param ctx   DTSP context
 *
 * @return void
 */
void dtsp_free(dtsp_ctx_t *ctx) {
    tdestroy(ctx->cache, free);
}
