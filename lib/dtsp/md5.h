/**
 * File: md5.h
 *
 * This code is part of Data Transfer Security Protocol (DTSP) library.
 *
 * Optimised ANSI C code for MD5 Message-Digest Algorithm (RFC 1321).
 *
 * @author Alexander Peslyak <solar@openwall.com>
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

#ifndef MD5_H
#define	MD5_H

#include <stdint.h>
#include <string.h>

#ifdef	__cplusplus
extern "C" {
#endif

    typedef struct {
        uint32_t lo, hi;
        uint32_t a, b, c, d;
        uint32_t block[16];
        uint8_t buf[64];
    } md5_ctx_t;

    /**
     * Initialise MD5 context structure.
     *
     * @param ctx   MD5 context
     *
     * @return void
     */
    void md5_init(md5_ctx_t *ctx);

    /**
     * Update MD5 context with new buffer.
     *
     * @param ctx   MD5 context
     * @param in    Input buffer
     * @param n     Input length
     *
     * @return void
     */
    void md5_update(md5_ctx_t *ctx, const uint8_t *in, size_t n);

    /**
     * Output MD5 digest from the given context.
     *
     * @param ctx   MD5 context
     * @param out   Output buffer
     *
     * @return void
     */
    void md5_finish(md5_ctx_t *ctx, uint8_t *out);

#ifdef	__cplusplus
}
#endif

#endif	/* MD5_H */
