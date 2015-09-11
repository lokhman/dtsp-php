/**
 * File: isaac.c
 *
 * This code is part of Data Transfer Security Protocol (DTSP) library.
 *
 * Optimised ANSI C code for ISAAC secure pseudorandom number generator.
 *
 * @author Robert Jenkins <bob_jenkins@burtleburtle.net>
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

#include "isaac.h"

#define index(mm, x) ((mm)[(x >> 2) & (ISAAC_SIZE - 1)])

#define step(mix, a, b, mm, m, m2, r, x) {                 \
    x = *m;                                                \
    a = ((a ^ (mix)) + *(m2++));                           \
    *(m++) = y = (index(mm, x     ) + a + b);              \
    *(r++) = b = (index(mm, y >> 8) + x    ) & 0xffffffff; }

#define mix(a, b, c, d, e, f, g, h) {            \
    a ^=  b               << 11; d += a; b += c; \
    b ^= (c & 0xffffffff) >>  2; e += b; c += d; \
    c ^=  d               <<  8; f += c; d += e; \
    d ^= (e & 0xffffffff) >> 16; g += d; e += f; \
    e ^=  f               << 10; h += e; f += g; \
    f ^= (g & 0xffffffff) >>  4; a += f; g += h; \
    g ^=  h               <<  8; b += g; h += a; \
    h ^= (a & 0xffffffff) >>  9; c += h; a += b; }

static void isaac_update(isaac_ctx_t *ctx) {
   register uint32_t a, b, x, y, *m, *mm, *m2, *r, *mend;

   mm = ctx->m;
   r = ctx->r;
   a = ctx->a;
   b = ctx->b + (++ctx->c);

   for (m = mm, mend = m2 = m + ISAAC_SIZE / 2; m < mend; ) {
      step( a               << 13, a, b, mm, m, m2, r, x);
      step((a & 0xffffffff) >>  6, a, b, mm, m, m2, r, x);
      step( a               <<  2, a, b, mm, m, m2, r, x);
      step((a & 0xffffffff) >> 16, a, b, mm, m, m2, r, x);
   }

   for (m2 = mm; m2 < mend; ) {
      step( a               << 13, a, b, mm, m, m2, r, x);
      step((a & 0xffffffff) >>  6, a, b, mm, m, m2, r, x);
      step( a               <<  2, a, b, mm, m, m2, r, x);
      step((a & 0xffffffff) >> 16, a, b, mm, m, m2, r, x);
   }

   ctx->n = ISAAC_SIZE;
   ctx->b = b;
   ctx->a = a;
}

/**
 * Seed pseudorandom sequence.
 *
 * @param ctx   ISAAC context
 * @param seed  Seed buffer
 * @param n     Seed length
 *
 * @return void
 */
void isaac_seed(isaac_ctx_t *ctx, const uint8_t *seed, size_t n) {
    uint32_t a, b, c, d, e, f, g, h, *m, *r;
    int i;

    memset(ctx, 0, sizeof(isaac_ctx_t));
    memcpy(ctx->r, seed, n);

    m = ctx->m;
    r = ctx->r;

    a = b = c = d = e = f = g = h = 0x9e3779b9;

    for (i = 0; i < 4; i++)
        mix(a, b, c, d, e, f, g, h);

    for (i = 0; i < ISAAC_SIZE; i += 8) {
        a += r[i    ]; b += r[i + 1]; c += r[i + 2]; d += r[i + 3];
        e += r[i + 4]; f += r[i + 5]; g += r[i + 6]; h += r[i + 7];

        mix(a, b, c, d, e, f, g, h);

        m[i    ] = a; m[i + 1] = b; m[i + 2] = c; m[i + 3] = d;
        m[i + 4] = e; m[i + 5] = f; m[i + 6] = g; m[i + 7] = h;
    }

    for (i = 0; i < ISAAC_SIZE; i += 8) {
        a += m[i    ]; b += m[i + 1]; c += m[i + 2]; d += m[i + 3];
        e += m[i + 4]; f += m[i + 5]; g += m[i + 6]; h += m[i + 7];

        mix(a, b, c, d, e, f, g, h);

        m[i    ] = a; m[i + 1] = b; m[i + 2] = c; m[i + 3] = d;
        m[i + 4] = e; m[i + 5] = f; m[i + 6] = g; m[i + 7] = h;
    }

    isaac_update(ctx);
}

/**
 * Generate 32-bit pseudorandom integer.
 *
 * @param ctx   ISAAC context
 *
 * @return 32-bit pseudorandom integer
 */
uint32_t isaac_rand(isaac_ctx_t *ctx) {
    if (ctx->n == 0)
        isaac_update(ctx);

    return ctx->r[--ctx->n];
}
