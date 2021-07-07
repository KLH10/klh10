#                                               -*- Autoconf -*-
# Process this file with autogen.sh to produce a configure script.

dnl This configure.ac script was created for Autoconf 2.69, but I
dnl tried it with one as old as 2.61, and that seemed to work fine.

AC_PREREQ([2.69])
AC_INIT([klh10], [2.0l], [https://github.com/PDP-10/klh10],
	[], [https://github.com/PDP-10/klh10])
AC_CONFIG_SRCDIR([src/klh10.h])
AC_CONFIG_HEADERS([src/config.h])

# Check that we're using a build directory, and are not building in
# between the source. It is cleaner that way.
# Configure has already set up $srcdir to be equal to . if it detected
# an in-tree build.

if test "$srcdir" = "."
then
    AC_MSG_ERROR(
[Please create a temporary (sub)directory to build in.
You can call this configure script using a absolute or relative
path from there.])
fi

# Filter CFLAGS; the default is something like -g -O2 and we want -g3 -O3.
NEWCFLAGS=""
for cf in $CFLAGS
do
    case "$cf" in
	-O*)					;;
	-g*)					;;
	*)	NEWCFLAGS="$NEWCFLAGS $cf"	;;
    esac
done
CFLAGS="$NEWCFLAGS -g3 -O3"

# -------------------------------------------------------------------------
# Check whether we want LIGHTS support
# -------------------------------------------------------------------------

AC_ARG_ENABLE(lights,
    AS_HELP_STRING([--enable-lights],[enable Panda lights (which requires libusb-1.0)]))

case "${enable_lights}" in
    yes)
        AC_MSG_NOTICE([Compiling with Panda lights support])
        AC_DEFINE(KLH10_DEV_LITES, 1, [Set to 1 to enable Panda lights])
        need_libusb=yes
        ;;
    no | "")
        AC_DEFINE(KLH10_DEV_LITES, 0, [Set to 0 to disable Panda lights])
        ;;
    *)  AC_MSG_ERROR([bad value ${enable_lights} for --enable-lights]) ;;
esac

# -------------------------------------------------------------------------
# Check whether we want LNX support
# -------------------------------------------------------------------------

AC_ARG_ENABLE(lnx,
    AS_HELP_STRING([--enable-lnx],[enable lnx networking (default on) when it cannot be found]))

case "${with_lnx}" in
    yes | "") 
	 AC_DEFINE(KLH10_NET_LNX, 1, [Set to 0 to enable LNX networking])
	 AC_MSG_NOTICE([Compiling with LNX support]) ;;
    no)  AC_DEFINE(KLH10_NET_LNX, 0, [Set to 0 to disable LNX networking])
	 AC_MSG_NOTICE([Compiling without LNX support]) ;;
    *)   AC_MSG_ERROR([bad value ${enable_lnx} for --enable-lnx]) ;;
esac

# -------------------------------------------------------------------------
# Check whether we want VDE support
# -------------------------------------------------------------------------

AC_ARG_WITH(vde,
    AS_HELP_STRING([--with-vde=PATH],[enable vde networking (default on) when it cannot be found]))

case "${with_vde}" in
    yes | "") ;;
    no)  AC_DEFINE(KLH10_NET_VDE, 0, [Set to 0 to disable VDE networking])
	 AC_MSG_NOTICE([Compiling without VDE support]) ;;
    /*)  CPPFLAGS="$CPPFLAGS -I ${with_vde}/include"
         LDFLAGS="$LDFLAGS -L ${with_vde}/lib" ;;
    *)   AC_MSG_ERROR([bad value ${with_vde} for --with-vde]) ;;
esac

# -------------------------------------------------------------------------
# Check whether we want bridge support
# -------------------------------------------------------------------------

AC_ARG_ENABLE(bridge,
    AS_HELP_STRING([--disable-bridge],[disable bridge networking]))

case "${enable_bridge}" in
    yes | "") ;;
    no)  AC_DEFINE(KLH10_NET_BRIDGE, 0, [Set to 0 to disable bridge networking])
         AC_MSG_NOTICE([Compiling without bridge support]) ;;
    *)   AC_MSG_ERROR([bad value ${enable_bridge} for --enable-bridge]) ;;
esac

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

# Checks for libraries.
# They may be needed for Solaris:
# -lsocket and -lnsl are needed only for osdnet.c.
# -lrt is needed for nanosleep().
# FIXME: Check if -lnsl is actually still needed for anything
dnl AC_CHECK_LIB([nsl], [main])
AC_CHECK_FUNC([nanosleep],
    [],
    [
	AC_CHECK_LIB([rt], [nanosleep])
    ])

case "${need_libusb}" in
    yes)
        # Check if libusb-1.0 is present, otherwise fail.
        PKG_CHECK_MODULES([libusb], [libusb-1.0],
                          [AC_DEFINE([HAVE_LIBUSB_1_0], [1],
                                     [Define if you have libusb-1.0.])],
                          [AC_MSG_ERROR([Lights require libusb-1.0, which I could not find.])])
        ;;
esac

# -lsocket, -lpcap and -lvdeplug should go into NETLIBS.
# NETLIBS is for libraries only needed by programs doing networking.
SAVE_LIBS="$LIBS"
LIBS=""
AC_CHECK_LIB([socket], [if_nameindex])
AC_CHECK_LIB([pcap], [pcap_findalldevs])
# Not all libpcap versions seem to have pcap_set_immediate_mode().
AC_CHECK_LIB([pcap], [pcap_set_immediate_mode],
	     [AC_DEFINE(HAVE_PCAP_SET_IMMEDIATE_MODE, 1, [Set to 1 if we have pcap_set_immediate_mode])]
)
AC_CHECK_LIB([vdeplug], [vde_send])
NETLIBS="$LIBS"
LIBS="$SAVE_LIBS"

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h errno.h fcntl.h limits.h netinet/in.h sgtty.h \
		  stddef.h stdlib.h string.h sys/file.h sys/ioctl.h \
		  sys/socket.h sys/time.h termios.h unistd.h net/if_tun.h \
		  linux/if_tun.h linux/if_packet.h net/if_tap.h sys/mtio.h \
		  net/nit.h sys/dlpi.h net/if_dl.h net/if_types.h \
		  sys/io.h libvdeplug.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm dup2 gettimeofday localtime_r memset socket strcasecmp \
		strchr strcspn strerror strncasecmp strpbrk strrchr strtol \
		getifaddrs if_nameindex sigaction nanosleep \
		gettimeofday getrusage setitimer tcsetattr mlockall \
		setpriority])

# Check for CPU.
# This requires install-sh, config.sub, config.guess from automake.
AC_CANONICAL_TARGET
AC_DEFINE_UNQUOTED([KLH10S_CENV_CPU_], "$target_cpu", [String form of the CPU name])
AC_DEFINE_UNQUOTED([KLH10S_CENV_SYS_], "$target_vendor-$target_os", [String form of the host OS])

AC_SUBST([KLH10S_CENV_CPU_], [$target_cpu])
AC_SUBST([KLH10S_CENV_SYS_], [$target_vendor-$target_os])

AC_C_BIGENDIAN([
    AC_DEFINE(CENV_CPUF_BIGEND, 1, [])
    AC_DEFINE(CENV_CPUF_LILEND, 0, [])
],[
    AC_DEFINE(CENV_CPUF_BIGEND, 0, [Set to 1 for big-endian CPU])
    AC_DEFINE(CENV_CPUF_LILEND, 1, [Set to 1 for little-endian CPU])
])

# This test and auxiliary file is needed to get around a bug in the NetBSD
# /usr/include files.  <stdio.h> includes <sys/types.h> which includes
# <machine/types.h> which incorrectly exposes a typedef of vaddr_t (normally
# a kernel only type), thus conflicting with KLH10's vaddr_t.
# By including this file ahead of any other source files (see the -include
# in CENVFLAGS) we can nullify the typedef.
# And while we're at it, blast paddr_t for the same reason.
# As of NetBSD 7.0, the problem has moved to <stdlib.h>.

AC_MSG_CHECKING([whether vaddr_t escapes from <std*.h>])
AC_LANG([C])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
/* see if this defines vaddr_t to something different than before */
typedef char vaddr_t;
]])],
[
    # Compiles ok: nothing to do.
    AC_MSG_RESULT([no (all ok)])
],
[
    # Compile error: we need to hide vaddr_t.
    AC_MSG_RESULT([yes (will patch it)])
    CENVFLAGS="$CENVFLAGS -include vaddr-sucks.h"
])

# -------------------------------------------------------------------------
# Check how to replace strerror() if needed.
# -------------------------------------------------------------------------

AC_MSG_CHECKING([whether sys_errlist exists])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_ERRNO_H
# include <errno.h>
#endif
#include <stdlib.h>
#include <stdio.h>
]], [[
     return sys_errlist[sys_nerr-1];
]])],
[
    # Compiles ok
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_SYS_ERRLIST], [1], [Define if  char *sys_errlist[] exists])
],
[
    # Compile error; try another variation
    AC_MSG_RESULT([no])

    AC_MSG_CHECKING([whether sys_errlist exists but needs a declaration])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #if HAVE_ERRNO_H
    # include <errno.h>
    #endif
    #include <stdlib.h>
    #include <stdio.h>
    extern int sys_nerr;
    extern char *sys_errlist[];
    ]], [[
	 return sys_errlist[sys_nerr-1];
    ]])],
    [
	# Compiles ok
	AC_MSG_RESULT([yes])
	AC_DEFINE([HAVE_SYS_ERRLIST], [1], [Define if char *sys_errlist[] exists])
	AC_DEFINE([DECL_SYS_ERRLIST], [1], [Define if char *sys_errlist[] must be declared])
    ],
    [
	# Compile error
	AC_MSG_RESULT([no?])
    ])
])

# -------------------------------------------------------------------------
# Check large file support and the sizes of related types.
# -------------------------------------------------------------------------

AC_SYS_LARGEFILE

AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
# Only try to find the size of off_t if it really exists
if test "x$ac_cv_type_off_t" = xyes
then
    AC_CHECK_SIZEOF(off_t)
else
    AC_DEFINE([SIZEOF_OFF_T], [0])
fi

# -------------------------------------------------------------------------
# Output section. State which @VARIABLES@ are going to be substituted.
# -------------------------------------------------------------------------

AH_TOP([
#ifndef CONFIG_H_INCLUDED
#define CONFIG_H_INCLUDED
])

AH_BOTTOM([
#endif /* CONFIG_H_INCLUDED */
])

AC_SUBST([CC])
AC_SUBST([CFLAGS])
AC_SUBST([CPPFLAGS])
AC_SUBST([DESTDIR])
AC_SUBST([PREFIX])
AC_SUBST([LIBS])
AC_SUBST([CPULIBS])
AC_SUBST([NETLIBS])
AC_SUBST([MAKEFILE], [Makefile])
AC_SUBST([CENVFLAGS])
AC_SUBST([libusb_CFLAGS])
AC_SUBST([libusb_LIBS])

# -------------------------------------------------------------------------
# Output section. State which files are going to be constructed.
# -------------------------------------------------------------------------

AC_CONFIG_FILES([bld-kl/Makefile:mk/top.mk:mk/top-kl.mk:src/Makefile.mk
                 bld-ks/Makefile:mk/top.mk:mk/top-ks.mk:src/Makefile.mk
                 bld-ks-its/Makefile:mk/top.mk:mk/top-ks-its.mk:src/Makefile.mk
		 Makefile:mk/bld.mk
		])

AC_OUTPUT
