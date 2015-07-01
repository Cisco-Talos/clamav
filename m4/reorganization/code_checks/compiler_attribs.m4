dnl check for __attribute__((packed))
dnl but only on compilers claiming to be gcc compatible
dnl because for example Sun's compiler silently ignores the packed attribute.
AC_MSG_CHECKING([for structure packing via __attribute__((packed))])
AC_CACHE_VAL([have_cv_attrib_packed],[
	AC_TRY_COMPILE(,
		[#ifdef __GNUC__
		 struct { int i __attribute__((packed)); } s;
		 #else
		 #error Only checking for packed attribute on gcc-like compilers
		 #endif],
		[have_cv_attrib_packed=yes],
		[have_cv_attrib_packed=no])
	])
AC_MSG_RESULT([$have_cv_attrib_packed])

if test "$have_cv_attrib_packed" = no; then
	AC_MSG_CHECKING([for structure packing via pragma])
	AC_CACHE_VAL([have_cv_pragma_pack],[
		AC_TRY_RUN([
			    int main(int argc, char **argv) {
#pragma pack(1)			/* has to be in column 1 ! */
			struct { char c; long l; } s;
			return sizeof(s)==sizeof(s.c)+sizeof(s.l) ? 0:1; } ],
			[have_cv_pragma_pack=yes],
			[have_cv_pragma_pack=no])
		])
	AC_MSG_RESULT([$have_cv_pragma_pack])
	if test "$have_cv_pragma_pack" = yes; then
		AC_DEFINE([HAVE_PRAGMA_PACK], 1, "pragma pack")
	else
		AC_MSG_CHECKING([for structure packing via hppa/hp-ux pragma])
		AC_CACHE_VAL([have_cv_pragma_pack_hpux],[
			AC_TRY_RUN([
			/* hppa/hp-ux wants pragma outside of function */
#pragma pack 1 /* has to be in column 1 ! */
			struct { char c; long l; } s;
			    int main(int argc, char **argv) {
			return sizeof(s)==sizeof(s.c)+sizeof(s.l) ? 0:1; } ],
			[have_cv_pragma_pack_hpux=yes],
			[have_cv_pragma_pack_hpux=no])
		])
		AC_MSG_RESULT([$have_cv_pragma_pack_hpux])
		AC_DEFINE([HAVE_PRAGMA_PACK_HPPA], 1, "pragma pack hppa/hp-ux style")
	fi
fi

dnl check for __attribute__((aligned))
AC_MSG_CHECKING([for type aligning via __attribute__((aligned))])
AC_CACHE_VAL([have_cv_attrib_aligned],[
	AC_TRY_COMPILE(,
		[typedef int cl_aligned_int __attribute__((aligned));],
		[have_cv_attrib_aligned=yes],
		[have_cv_attrib_aligned=no])
	])
AC_MSG_RESULT([$have_cv_attrib_aligned])

if test "$have_cv_attrib_packed" = no -a "$have_cv_pragma_pack" = no -a "$have_cv_pragma_pack_hpux" = no; then
	AC_MSG_ERROR(Need to know how to pack structures with this compiler)
fi

if test "$have_cv_attrib_packed" = yes; then
	AC_DEFINE([HAVE_ATTRIB_PACKED], 1, [attrib packed])
fi

if test "$have_cv_attrib_aligned" = yes; then
	AC_DEFINE([HAVE_ATTRIB_ALIGNED], 1, [attrib aligned])
fi

dnl Sanity check that struct packing works
AC_MSG_CHECKING([that structure packing works])
AC_CACHE_VAL([have_cv_struct_pack],[
    AC_TRY_RUN([
#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1) /* has to be in column 1 ! */
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1 /* has to be in column 1 ! */
#endif

struct { char c __attribute__((packed)); long l __attribute__((packed)); } s;

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

struct { char c; long l;} s2;

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1) /* has to be in column 1 ! */
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1 /* has to be in column 1 ! */
#endif

struct { char c; long l; } __attribute__((packed)) s3;

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

    int main(int argc, char **argv) {
        if (sizeof(s)!=sizeof(s.c)+sizeof(s.l))
	    return 1;
	if (sizeof(s) != sizeof(s3))
	    return 2;
	return (sizeof(s2) >= sizeof(s)) ? 0 : 3;
    }],
    [have_cv_struct_pack=yes],
    [have_cv_struct_pack=no],
    [have_cv_struct_pack=yes])
])
AC_MSG_RESULT([$have_cv_struct_pack])

if test "$have_cv_struct_pack" = "no"; then
    AC_MSG_ERROR([Structure packing seems to be available, but is not working with this compiler])
fi
