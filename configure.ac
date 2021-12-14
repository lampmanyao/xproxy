AC_INIT([xproxy], [0.6.1], [lampmanyao@gmail.com])

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

AC_ARG_ENABLE([static_openssl],
		AS_HELP_STRING([--enable-static-openssl], [Compile with static openssl libs.]),
		[static_openssl="yes"], #
		[static_openssl="no"])

AM_CONDITIONAL(DEBUG, test x"$static_openssl" = x"yes")
AS_IF([test x"$static_openssl" = x"yes"],
      [LDFLAGS="/usr/local/lib/libssl.a /usr/local/lib/libcrypto.a" LIBS="-lpthread -ldl"],
      [LIBS="-lpthread -ldl -lssl -lcrypto"])

AC_ARG_ENABLE([debug],
AS_HELP_STRING([--enable-debug=yes|no], [Enable debugging, default is disabled.]),
	      [debug="$enableval"],
              [debug="no"])

AM_CONDITIONAL(DEBUG, test x"$debug" = x"yes")
AS_IF([test x"$debug" = x"yes"],
      [CFLAGS="-g3 -O0 -fsanitize=address"],
      [CFLAGS="-O2"])


CFLAGS="$CFLAGS \
	-std=c99 -Wall -Wpointer-arith -fno-omit-frame-pointer \
	-Wsign-compare -Wno-unused-result -Wno-unused-function \
	-Wextra -Wshadow -Wconversion -funroll-loops -fPIC -pipe"

CPPFLAGS="-D_GNU_SOURCE -D_POSIX_SOURCE -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE -D_REENTRANT -DOPEN_PRINT"

AC_CHECK_HEADERS([openssl/md5.h openssl/ssl.h openssl/evp.h openssl/err.h],[],[AC_MSG_ERROR([OpenSSL headers required])])

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([ === Configuration results ===])
AC_MSG_NOTICE([Version:             $PACKAGE_VERSION])
AC_MSG_NOTICE([c compiler:          $CC])
AC_MSG_NOTICE([CPPFLAGS:            $CPPFLAGS])
AC_MSG_NOTICE([CLAGS:               $CFLAGS])
AC_MSG_NOTICE([LDFLAGS:             $LDFLAGS])
AC_MSG_NOTICE([Enable debug:        $debug])
AC_MSG_NOTICE([Compile with static openssl libs: $static_openssl])
AC_MSG_NOTICE([ =============================])

