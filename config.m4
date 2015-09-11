dnl $Id$
dnl config.m4 for extension dtsp

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(dtsp, for dtsp support,
dnl Make sure that the comment is aligned:
dnl [  --with-dtsp             Include dtsp support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(dtsp, whether to enable dtsp support,
dnl Make sure that the comment is aligned:
[  --enable-dtsp           Enable dtsp support])

if test "$PHP_DTSP" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-dtsp -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/dtsp.h"  # you most likely want to change this
  dnl if test -r $PHP_DTSP/$SEARCH_FOR; then # path given as parameter
  dnl   DTSP_DIR=$PHP_DTSP
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for dtsp files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       DTSP_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$DTSP_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the dtsp distribution])
  dnl fi

  dnl # --with-dtsp -> add include path
  dnl PHP_ADD_INCLUDE($DTSP_DIR/include)

  dnl # --with-dtsp -> check for lib and symbol presence
  dnl LIBNAME=dtsp # you may want to change this
  dnl LIBSYMBOL=dtsp # you most likely want to change this

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $DTSP_DIR/$PHP_LIBDIR, DTSP_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_DTSPLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong dtsp lib version or lib not found])
  dnl ],[
  dnl   -L$DTSP_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(DTSP_SHARED_LIBADD)

  PHP_NEW_EXTENSION(dtsp, dtsp.c lib/dtsp.c lib/dtsp/aes.c lib/dtsp/crc32.c lib/dtsp/isaac.c lib/dtsp/md5.c lib/dtsp/tsearch.c, $ext_shared)
  PHP_ADD_BUILD_DIR($ext_builddir/lib, 1)
  PHP_ADD_INCLUDE([$ext_srcdir/lib])
fi
