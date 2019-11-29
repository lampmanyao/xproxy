AC_INIT([btgfw], [0.5.3], [lampmanyao@gmail.com])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_LANG(C)

AC_PROG_CC

AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADERS(m4_normalize([
  stdio.h
  stdlib.h
  unistd.h
  errno.h
  assert.h
  string.h
  strings.h
  signal.h
  fcntl.h
  netdb.h
  poll.h
  pthread.h
  sys/time.h
  sys/types.h
  sys/socket.h
  sys/resource.h
  netinet/in.h
  arpa/inet.h
]), [], [AC_MSG_ERROR([Missing required header file.])])

AC_CHECK_FUNCS([getaddrinfo getnameinfo inet_ntop inet_ntoa])

AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug],
               [enable debugging, default: no]),
               [case "${enableval}" in
                 yes) debug=true ;;
                 no)  debug=false ;;
                 *)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
               esac],
               [debug=false])


AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")
AS_IF([test x"$debug" = x"true"],
      [CFLAGS="-g3 -O0"],
      [CFLAGS="-O2"])

AC_ARG_WITH([openssl-header],
	    [AS_HELP_STRING([--with-openssl-header], [Location of OpenSSL header folder, defaults to /usr/include])],
	    [openssl_header_dir="$withval"],
	    [openssl_header_dir="/usr/include"])

AC_ARG_WITH([openssl-lib],
	    [AS_HELP_STRING([--with-openssl-lib], [Location of OpenSSL lib folder, defaults to /usr/lib])],
	    [openssl_lib_dir="$withval"],
	    [openssl_lib_dir="/usr/lib"])

CFLAGS="$CFLAGS -I$openssl_header_dir/include \
	-std=c99 -Wall -Wpointer-arith -fno-omit-frame-pointer \
	-Wsign-compare -Wno-unused-result -Wno-unused-function \
	-Wextra -Wshadow -Wconversion -funroll-loops -fPIC -pipe"
CPPFLAGS="-D_GNU_SOURCE -D_POSIX_SOURCE -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE -D_REENTRANT -DOPEN_PRINT"
LDFLAGS="$LDFLAGS -L$openssl_lib_dir/lib"
LIBS="-lpthread -lssl -lcrypto"

AC_CHECK_HEADERS([openssl/md5.h openssl/ssl.h openssl/evp.h openssl/err.h],[],[AC_MSG_ERROR([OpenSSL headers required])])

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([ === Configuration results ===])
AC_MSG_NOTICE([Version:             $PACKAGE_VERSION])
AC_MSG_NOTICE([c compiler:          $CC])
AC_MSG_NOTICE([Enable debug:        $debug])
AC_MSG_NOTICE([CPPFLAGS:            $CPPFLAGS])
AC_MSG_NOTICE([ =============================])

