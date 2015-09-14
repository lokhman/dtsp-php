/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2015 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Alexander Lokhman <alex.lokhman@gmail.com>                   |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_DTSP_H
#define PHP_DTSP_H

#include "lib/src/dtsp.h"

extern zend_module_entry dtsp_module_entry;
#define phpext_dtsp_ptr &dtsp_module_entry

#define PHP_DTSP_VERSION "1.0.0"
#define PHP_DTSP_EXTNAME "DTSP"

#ifdef PHP_WIN32
# define PHP_DTSP_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
# define PHP_DTSP_API __attribute__ ((visibility("default")))
#else
# define PHP_DTSP_API
#endif

#ifdef ZTS
# include "TSRM.h"
#endif

ZEND_BEGIN_MODULE_GLOBALS(dtsp)
dtsp_ctx_t ctx;
ZEND_END_MODULE_GLOBALS(dtsp)

#ifdef ZTS
# define DTSP_G(v) TSRMG(dtsp_globals_id, zend_dtsp_globals *, v)
#else
# define DTSP_G(v) (dtsp_globals.v)
#endif

#endif	/* PHP_DTSP_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
