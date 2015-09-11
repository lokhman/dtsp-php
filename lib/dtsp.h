/**
 * File: dtsp.h
 *
 * Data Transfer Security Protocol (DTSP).
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

#ifndef DTSP_H
#define	DTSP_H

#include <stdint.h>
#include <assert.h>
#include <time.h>

#include "dtsp/md5.h"
#include "dtsp/aes.h"
#include "dtsp/crc32.h"
#include "dtsp/isaac.h"
#include "dtsp/tsearch.h"

#define DTSP_HEADER     0xFAF0F0E4U     /* KOI8-R BE */
#define DTSP_PADDING    53U             /* 4+1+16+16+16 */
#define DTSP_INTERVAL   15U             /* INTERVAL > TIMEOUT <= 60! */
#define DTSP_AES        AES_256

/** Macro for encrypting dtsp_buf_t structure as input */
#define dtsp_encrypt(ctx, out, in) dtsp_encrypt_bytes(ctx, out, (in)->buf, (in)->n)

/** Macro for decrypting dtsp_buf_t structure as input */
#define dtsp_decrypt(ctx, out, in) dtsp_decrypt_bytes(ctx, out, (in)->buf, (in)->n)

#ifdef	__cplusplus
extern "C" {
#endif

    typedef struct {
        const uint8_t *buf;
        size_t n;
    } dtsp_buf_t;

    typedef struct {
        uint32_t time;
        dtsp_buf_t seed;
        uint8_t _key[32];
        uint8_t  key[32];
        uint8_t udid[16];
        isaac_ctx_t _key_ctx;
        isaac_ctx_t  key_ctx;
        isaac_ctx_t udid_ctx;
        uint8_t *cache;
    } dtsp_ctx_t;

    typedef enum {
        DTSP_STATUS_NODATA = -0x0F,
        DTSP_STATUS_BADHEADER,
        DTSP_STATUS_DUPLICATE,
        DTSP_STATUS_BADMAC,
        DTSP_STATUS_FULL,
    } dtsp_status_t;

    /**
     * Initialise DTSP context structure.
     *
     * @param ctx   DTSP context
     * @param seed  Strictly defined seed
     * @param udid  Unique device identifier
     *
     * @return void
     */
    void dtsp_init(dtsp_ctx_t *ctx, const dtsp_buf_t *seed, const dtsp_buf_t *udid);

    /**
     * DTSP encryption routine.
     *
     * @param ctx   DTSP context
     * @param out   Output buffer
     * @param in    Input buffer
     * @param n     Input length
     *
     * @return (N+[DTSP_PADDING])
     */
    size_t dtsp_encrypt_bytes(dtsp_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t n);

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
    ssize_t dtsp_decrypt_bytes(dtsp_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t n);

    /**
     * Free memory used by DTSP context structure.
     *
     * @param ctx   DTSP context
     *
     * @return void
     */
    void dtsp_free(dtsp_ctx_t *ctx);

#ifdef	__cplusplus
}
#endif

#endif	/* DTSP_H */
