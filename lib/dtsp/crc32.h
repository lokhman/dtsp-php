/**
 * File: crc32.h
 *
 * This code is part of Data Transfer Security Protocol (DTSP) library.
 *
 * Optimised ANSI C code for CRC32C Cyclic Redundancy-Check Code.
 *
 * @author Gary S. Brown
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

#ifndef CRC32_H
#define	CRC32_H

#include <stdint.h>
#include <string.h>

/** Macro for generating CRC32C checksum */
#define crc32(buf, n) crc32_update(0U, buf, n)

#ifdef	__cplusplus
extern "C" {
#endif

    /**
     * Generate CRC32C checksum based on initial value.
     *
     * @param crc32 Initial checksum
     * @param buf   Input buffer
     * @param n     Input length
     *
     * @return 32-bit checksum
     */
    uint32_t crc32_update(register uint32_t crc32, const uint8_t *buf, size_t n);

#ifdef	__cplusplus
}
#endif

#endif	/* CRC32_H */
