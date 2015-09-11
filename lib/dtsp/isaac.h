/**
 * File: isaac.h
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

#ifndef ISAAC_H
#define	ISAAC_H

#include <stdint.h>
#include <string.h>

#define ISAAC_SIZE 256U

#ifdef	__cplusplus
extern "C" {
#endif

    typedef struct {
        uint16_t n;
        uint32_t a;
        uint32_t b;
        uint32_t c;
        uint32_t r[ISAAC_SIZE];
        uint32_t m[ISAAC_SIZE];
    } isaac_ctx_t;

    /**
     * Seed pseudorandom sequence.
     *
     * @param ctx   ISAAC context
     * @param seed  Seed buffer
     * @param n     Seed length
     *
     * @return void
     */
    void isaac_seed(isaac_ctx_t *ctx, const uint8_t *seed, size_t n);

    /**
     * Generate 32-bit pseudorandom integer.
     *
     * @param ctx   ISAAC context
     *
     * @return 32-bit pseudorandom integer
     */
    uint32_t isaac_rand(isaac_ctx_t *ctx);

#ifdef	__cplusplus
}
#endif

#endif	/* ISAAC_H */
