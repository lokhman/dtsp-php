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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "zend_exceptions.h"
#include "ext/standard/info.h"
#include "php_dtsp.h"

ZEND_DECLARE_MODULE_GLOBALS(dtsp)

/* {{{ PHP_INI */
PHP_INI_BEGIN()
PHP_INI_ENTRY("dtsp.seed",    "", PHP_INI_SYSTEM, NULL)
PHP_INI_ENTRY("dtsp.udid", "PHP", PHP_INI_SYSTEM, NULL)
PHP_INI_END()
/* }}} */

/* {{{ proto string dtsp_encrypt(string data) */
PHP_FUNCTION(dtsp_encrypt) {
    int argc = ZEND_NUM_ARGS();
    uint8_t *in = NULL, *out;
    size_t n = 0, len;

    if (zend_parse_parameters(argc TSRMLS_CC, "s", &in, &n) == FAILURE)
        return;

    out = (uint8_t *) emalloc(n + DTSP_PADDING + 1);
    len = dtsp_encrypt_bytes(&DTSP_G(ctx), out, in, n);
    out[len] = '\0';

    RETURN_STRINGL(out, len, 0);
}
/* }}} */

/* {{{ proto dtsp_decrypt(string data) */
PHP_FUNCTION(dtsp_decrypt) {
    int argc = ZEND_NUM_ARGS();
    uint8_t *in = NULL, *out;
    size_t n = 0;
    ssize_t len;

    if (zend_parse_parameters(argc TSRMLS_CC, "s", &in, &n) == FAILURE)
        return;

    out = (uint8_t *) emalloc(n + 1);
    len = dtsp_decrypt_bytes(&DTSP_G(ctx), out, in, n);
    switch (len) {
        case DTSP_STATUS_NODATA:
            php_error(E_WARNING, "dtsp_decrypt: no data to decrypt");
            RETURN_LONG(len);
        case DTSP_STATUS_BADHEADER:
        case DTSP_STATUS_BADMAC:
            php_error(E_WARNING, "dtsp_decrypt: data has incorrect format");
            RETURN_LONG(len);
        case DTSP_STATUS_DUPLICATE:
            php_error(E_WARNING, "dtsp_decrypt: given data was already decrypted");
            RETURN_LONG(len);
        case DTSP_STATUS_FULL:
            zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Not enough memory to register new data", 0 TSRMLS_CC);
            return;
    }
    out[len] = '\0';

    RETURN_STRINGL(out, len, 0);
}
/* }}} */

/* {{{ php_dtsp_init_globals */
static void php_dtsp_init_globals(zend_dtsp_globals *dtsp_globals) {
    dtsp_buf_t seed, udid;

    seed.buf = INI_STR("dtsp.seed");
    seed.n = strlen(seed.buf);
    udid.buf = INI_STR("dtsp.udid");
    udid.n = strlen(udid.buf);

    dtsp_init(&dtsp_globals->ctx, &seed, &udid);
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(dtsp) {
    REGISTER_INI_ENTRIES();

    REGISTER_LONG_CONSTANT("DTSP_STATUS_NODATA", DTSP_STATUS_NODATA, CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("DTSP_STATUS_BADHEADER", DTSP_STATUS_BADHEADER, CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("DTSP_STATUS_DUPLICATE", DTSP_STATUS_DUPLICATE, CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("DTSP_STATUS_BADMAC", DTSP_STATUS_BADMAC, CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("DTSP_STATUS_FULL", DTSP_STATUS_FULL, CONST_CS|CONST_PERSISTENT);

    ZEND_INIT_MODULE_GLOBALS(dtsp, php_dtsp_init_globals, NULL);

    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION */
PHP_MSHUTDOWN_FUNCTION(dtsp) {
    UNREGISTER_INI_ENTRIES();

    dtsp_free(&DTSP_G(ctx));

    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION */
PHP_MINFO_FUNCTION(dtsp) {
    php_info_print_table_start();
    php_info_print_table_header(2, "DTSP support", "enabled");
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}
/* }}} */

/* {{{ dtsp_functions[] */
const zend_function_entry dtsp_functions[] = {
    PHP_FE(dtsp_encrypt, NULL)
    PHP_FE(dtsp_decrypt, NULL)
    PHP_FE_END
};
/* }}} */

/* {{{ dtsp_module_entry */
zend_module_entry dtsp_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_DTSP_EXTNAME,
    dtsp_functions,
    PHP_MINIT(dtsp),
    PHP_MSHUTDOWN(dtsp),
    NULL,
    NULL,
    PHP_MINFO(dtsp),
    PHP_DTSP_VERSION,
    STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_DTSP
ZEND_GET_MODULE(dtsp)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
