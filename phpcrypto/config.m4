dnl $Id$
dnl config.m4 for extension phpcrypto

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(phpcrypto, for phpcrypto support,
dnl Make sure that the comment is aligned:
dnl [  --with-phpcrypto             Include phpcrypto support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(phpcrypto, whether to enable phpcrypto support,
dnl Make sure that the comment is aligned:
[  --enable-phpcrypto           Enable phpcrypto support])

if test "$PHP_PHPCRYPTO" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-phpcrypto -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/phpcrypto.h"  # you most likely want to change this
  dnl if test -r $PHP_PHPCRYPTO/$SEARCH_FOR; then # path given as parameter
  dnl   PHPCRYPTO_DIR=$PHP_PHPCRYPTO
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for phpcrypto files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       PHPCRYPTO_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$PHPCRYPTO_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the phpcrypto distribution])
  dnl fi

  dnl # --with-phpcrypto -> add include path
  dnl PHP_ADD_INCLUDE($PHPCRYPTO_DIR/include)

  dnl # --with-phpcrypto -> check for lib and symbol presence
  dnl LIBNAME=phpcrypto # you may want to change this
  dnl LIBSYMBOL=phpcrypto # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $PHPCRYPTO_DIR/$PHP_LIBDIR, PHPCRYPTO_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_PHPCRYPTOLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong phpcrypto lib version or lib not found])
  dnl ],[
  dnl   -L$PHPCRYPTO_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(PHPCRYPTO_SHARED_LIBADD)

  PHP_NEW_EXTENSION(phpcrypto, phpcrypto.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
