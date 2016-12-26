#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([mitm-ssl], [0.1], [kaz.kanso@gmail.com])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Check for pthread
m4_include([m4/ax_pthread.m4])
AX_PTHREAD

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
PKG_CHECK_MODULES([ssl], [libcrypto >= 1.0.1 , libssl >= 1.0.1])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

# Setup global CFLAGS
CFLAGS="${CFLAGS} -Wall -Wpedantic -Werror -std=c99"

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
