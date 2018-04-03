AC_ARG_ENABLE([gcc-vcheck],
[AS_HELP_STRING([--disable-gcc-vcheck], [do not check for buggy gcc version])],
gcc_check=$enableval, gcc_check="yes")

msg_gcc_check="use --disable-gcc-vcheck to disable this check. Before reporting any bugs check with a supported version of gcc"
VERSION_SUFFIX=
dnl Check for gcc-4.1.0
if test "$gcc_check" = "yes"; then
	if test "x$ac_compiler_gnu" = "xyes"; then
		AC_MSG_CHECKING([for a supported version of gcc])
		gcc_version=`${CC} -dumpversion`
		case "${gcc_version}" in
			4.1.0*)
				AC_MSG_RESULT([no (${gcc_version})])
				AC_MSG_ERROR([gcc 4.1.0 is known to incorrectly compile upx.c. Upgrade your compiler to at least 4.1.1/4.1.2)])
				;;
			*)
				AC_MSG_RESULT([ok (${gcc_version})])
				;;
		esac
		case "${gcc_version}" in
		    [[56789]].* | 4.[[3456789]].*)
			# bb #1581 - temporarily add -fno-strict-aliasing so gcc 4.4.0
			# works correctly
			CFLAGS="$CFLAGS -fno-strict-aliasing"
			;;
		    *)
			;;
		esac
	fi
else
	CFLAGS="$CFLAGS -O0"
	VERSION_SUFFIX="$VERSION_SUFFIX-broken-compiler"
fi

# add distcheck warning flags
distcheck_enable_flags=0
if test "x$ac_compiler_gnu" = "xyes"; then
	gcc_version=`${CC} -dumpversion`
	case "${gcc_version}" in
		4.[[3456789]]*)
			distcheck_enable_flags=1
			;;
		[[56789]].*)
			distcheck_enable_flags=1
			;;
	esac
fi

dnl Checks if compiler produces valid code, regardless of compiler
dnl we do these checks here to avoid receiving endless bugreports about
dnl breakages due to compiler bugs.

dnl Check if compiler produces invalid code on gcc PR27603 (affects upx.c)
dnl testcase from gcc testsuite
AC_MSG_CHECKING([for gcc bug PR27603])
AC_TRY_RUN(
	   [
/* (C) Richard Guenther */	   
void exit (int);
void abort (void);
int a;
int main(void)
{
  int j;
  for (j = 0; j < 6; j++)
  {
    if ((unsigned)j - 3 <= 1)
      exit (0);
    a = 1000 * (6 - j);
  }
  abort ();
}
], [AC_MSG_RESULT([ok, bug not present])],
[AC_MSG_ERROR([your compiler has gcc PR27603 bug, use a different compiler, see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=27603])], [AC_MSG_RESULT([cross-compiling, assumed ok])])

dnl Check if compiler produces invalid code on gcc PR26763-2 (affects upx.c)
dnl testcase from gcc testsuite
AC_MSG_CHECKING([for gcc bug PR26763-2])
AC_TRY_RUN(
	   [
/* (C) Richard Guenther */	   
extern void abort(void);

static int try (char *a, int d)
{
  return a + d > a;
}

int main(void)
{
  char bla[100];

  if (try (bla + 50, -1))
    abort ();

  return 0;
}
], [AC_MSG_RESULT([ok, bug not present])],
[AC_MSG_ERROR([your compiler has gcc PR26763-2 bug, use a different compiler, see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=26763])],[AC_MSG_RESULT([cross-compiling, assumed ok])])

dnl Check if compiler produces invalid code on own testcase based on upx.c
AC_MSG_CHECKING([for valid code generation of CLI_ISCONTAINED])
AC_TRY_RUN(
	   [
#include <stdio.h>
static struct v{
	char* dst;
	unsigned int dsize;
	unsigned int dcur;
	unsigned int backsize;
	signed int unp_offset;
} values[] = {
	{(char*)0xf78ab008, 0x2e000, 1, 4, -1594},
	{(char*)0xb7af1008, 0x2e000, 1, 4, -1594}

};
extern void abort(void);

#define CLI_ISCONTAINED(bb, bb_size, sb, sb_size)	\
  ((bb_size) > 0 && (sb_size) > 0 && (size_t)(sb_size) <= (size_t)(bb_size) \
   && (sb) >= (bb) && ((sb) + (sb_size)) <= ((bb) + (bb_size)) && ((sb) + (sb_size)) > (bb) && (sb) < ((bb) + (bb_size)))

int crashtest()
{
	unsigned int backsize, dcur;
	int dval=0x12000, unp_offset;
	int* dsize = &dval;
	char* dst = (char*)0x12000;
	while(1) {
		backsize=4;
		dcur=0;
		unp_offset=0x800002c7;

		if (!CLI_ISCONTAINED(dst, *dsize, dst+dcur+unp_offset, backsize) || !CLI_ISCONTAINED(dst, *dsize, dst+dcur, backsize) || unp_offset >=0)
			return -1;
		abort();
	}
	return 0;
}

int main(void)
{
	size_t i;
	for(i=0;i<sizeof(values)/sizeof(values[0]);i++) {
		struct v* v= &values[i];
		char* dst = v->dst;
		unsigned int* dsize = &v->dsize;
		unsigned int dcur = v->dcur;
		unsigned int backsize = v->backsize-1;
		signed int  unp_offset = v->unp_offset;

		if(!CLI_ISCONTAINED(dst, *dsize, dst+dcur+unp_offset, backsize) ||
				!CLI_ISCONTAINED(dst, *dsize,dst+dcur,backsize) || unp_offset >= 0)  {
			continue;
		}
		abort();
	}
	crashtest();
	return 0;
}
], [AC_MSG_RESULT([ok, bug not present])],
[AC_MSG_ERROR([your compiler has a bug that causes clamav bug no. 670, use a different compiler, see https://bugzilla.clamav.net/show_bug.cgi?id=670])], [AC_MSG_RESULT([cross-compiling, assumed ok])])

dnl Check if compiler produces invalid code on gcc PR28045 (affects upx.c)
dnl testcase from gcc testsuite
AC_MSG_CHECKING([for gcc bug PR28045])
AC_TRY_RUN(
	   [
/* (C) Andrew Pinski */
extern void abort(void);
struct a
{
   unsigned int bits : 1;
   signed long val : ((sizeof(long) * 8) - 1);
};
static int Fnegate (struct a b)
{
  if ((-((long)b.val)) <= ((long) ((1UL << ((sizeof(long) * 8) - 2)) -1UL))
      && (-((long)b.val)) >= (-(((long) ((1UL << ((sizeof(long) * 8) - 2)) -1UL))) - 1))
     return 0 ;
  abort ();
}
int main (void)
{
  struct a b = {1, 1};
  Fnegate (b);
  return 0;
}
], [AC_MSG_RESULT([ok, bug not present])],
[AC_MSG_ERROR([your compiler has gcc PR28045 bug, use a different compiler, see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=28045])], [AC_MSG_RESULT([cross-compiling, assumed ok])])

dnl Check if compiler produces invalid code on gcc PR37573 (affects autoit.c)
dnl this is a bug in gcc 4.4.0, but for some reason it affects gcc 4.1.2 too
dnl gcc 4.1.3 is OK. This bug occurs only at -O3.
AC_MSG_CHECKING([for gcc bug PR37573])
AC_TRY_RUN(
	   [
#include <stdlib.h>
#include <string.h>
struct S
{
  unsigned int *a;
  unsigned int b;
  unsigned int c[624];
};
static unsigned char
foo (struct S *s)
{
  unsigned int r;
  if (!--s->b)
    {
      unsigned int *c = s->c;
      unsigned int i;
      s->a = c;
      for (i = 0; i < 227; i++)
	c[i] =
	  ((((c[i] ^ c[i + 1]) & 0x7ffffffe) ^ c[i]) >> 1) ^
	  ((0 - (c[i + 1] & 1)) & 0x9908b0df) ^ c[i + 397];
      for (; i < 623; i++)
	c[i] =
	  ((((c[i] ^ c[i + 1]) & 0x7ffffffe) ^ c[i]) >> 1) ^
	  ((0 - (c[i + 1] & 1)) & 0x9908b0df) ^ c[i - 227];
      c[623] =
	((((c[623] ^ c[0]) & 0x7ffffffe) ^ c[623]) >> 1) ^ ((0 - (c[0] & 1)) &
							    0x9908b0df) ^ c[i
									    -
									    227];
    }
  r = *(s->a++);
  r ^= (r >> 11);
  r ^= ((r & 0xff3a58ad) << 7);
  r ^= ((r & 0xffffdf8c) << 15);
  r ^= (r >> 18);
  return (unsigned char) (r >> 1);
}

void
bar (unsigned char *p, unsigned int q, unsigned int r)
{
  struct S s;
  unsigned int i;
  unsigned int *c = s.c;
  *c = r;
  for (i = 1; i < 624; i++)
    c[i] = i + 0x6c078965 * ((c[i - 1] >> 30) ^ c[i - 1]);
  s.b = 1;
  while (q--)
    *p++ ^= foo (&s);
};

static unsigned char p[23] = {
  0xc0, 0x49, 0x17, 0x32, 0x62, 0x1e, 0x2e, 0xd5, 0x4c, 0x19, 0x28, 0x49,
    0x91, 0xe4, 0x72, 0x83, 0x91, 0x3d, 0x93, 0x83, 0xb3, 0x61, 0x38
};

static unsigned char q[23] = {
  0x3e, 0x41, 0x55, 0x54, 0x4f, 0x49, 0x54, 0x20, 0x55, 0x4e, 0x49, 0x43,
    0x4f, 0x44, 0x45, 0x20, 0x53, 0x43, 0x52, 0x49, 0x50, 0x54, 0x3c
};

int
main (void)
{
  unsigned int s;
  s = 23;
  bar (p, s, s + 0xa25e);
  if (memcmp (p, q, s) != 0)
	abort ();
  return 0;
}

], [AC_MSG_RESULT([ok, bug not present])],
[AC_MSG_ERROR([your compiler has gcc PR37573 bug, use a lower optimization level (-O1 or -O2), see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=37573])], [AC_MSG_RESULT([cross-compiling, assumed ok])])

# It's not fatal if gperf is missing
AM_MISSING_PROG(GPERF, gperf)
AC_SUBST(GPERF)

AC_TYPE_OFF_T
AC_COMPILE_CHECK_SIZEOF([short])
AC_COMPILE_CHECK_SIZEOF([int])
AC_COMPILE_CHECK_SIZEOF([long])
AC_COMPILE_CHECK_SIZEOF([long long])
AC_COMPILE_CHECK_SIZEOF([void *])
