/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef BYTECODE_DETECT_H
#define BYTECODE_DETECT_H
/* mostly from m4/acinclude.m4 */
enum arch_list {
  arch_unknown=0,
  arch_i386,
  arch_x86_64,
  arch_ppc32,
  arch_ppc64,
  arch_arm,
  arch_sparc,
  arch_sparc64,
  arch_mips,
  arch_mips64,
  arch_alpha,
  arch_hppa1,
  arch_hppa2,
  arch_m68k,
  arch_ANY = 0xf
};

/* from ClamAV's configure.in */
enum os_kind_conf {
  os_unknown=0,
  os_aix,
  os_beos,
  os_bsd,
  os_darwin,
  os_gnu_hurd,
  os_hpux,
  os_interix,
  os_irix,
  os_kfreebsd_gnu,
  os_linux,
  os_os2,
  os_osf,
  os_qnx6,
  os_solaris,
  os_win32,
  os_win64,
  os_generic,
  os_ANY = 0xff
};

enum os_kind_llvm {
  llvm_os_UnknownOS=0,
  llvm_os_AuroraUX,
  llvm_os_Cygwin,
  llvm_os_Darwin,
  llvm_os_DragonFly,
  llvm_os_FreeBSD,
  llvm_os_Linux,
  llvm_os_Lv2,
  llvm_os_MinGW32,
  llvm_os_MinGW64,
  llvm_os_NetBSD,
  llvm_os_OpenBSD,
  llvm_os_Psp,
  llvm_os_Solaris,
  llvm_os_Win32,
  llvm_os_Haiku,
  llvm_os_Minix,
  llvm_os_ANY = 0xff
};

/* the ones from clamconf */
enum compiler_list {
  compiler_unknown = 0,
  compiler_gnuc,
  compiler_llvm,
  compiler_clang,
  compiler_intel,
  compiler_msc,
  compiler_sun,
  compiler_other,
  compiler_ANY = 0xf
};

enum endian_list {
    endian_little=0,
    endian_big=1,
    endian_ANY=0xf
};

enum os_feature_bits {
    feature_map_rwx = 0,
    feature_selinux = 1,
    feature_selinux_enforcing = 2,
    feature_pax = 3,
    feature_pax_mprotect = 4
};

struct cli_environment {
    uint32_t platform_id_a;
    uint32_t platform_id_b;
    uint32_t platform_id_c;
    uint32_t c_version;
    uint32_t cpp_version; /* LLVM only */
    /* engine */
    uint32_t functionality_level;
    uint32_t dconf_level;
    int8_t   engine_version[65];
    /* detailed runtime info */
    int8_t    triple[65];/* LLVM only */
    int8_t    cpu[65];/* LLVM only */
    /* uname */
    int8_t    sysname[65];
    int8_t    release[65];
    int8_t    version[65];
    int8_t    machine[65];
    /* build time */
    uint8_t big_endian;
    uint8_t sizeof_ptr;
    uint8_t arch;
    uint8_t os_category;/* from configure */
    uint8_t os;/* from LLVM if available */
    uint8_t compiler;
    uint8_t has_jit_compiled;
    uint8_t os_features;
    uint8_t reserved0;
};

#ifndef __CLAMBC__
#define MAKE_VERSION(a,b,c,d) ((a << 24) | (b << 16) | (c << 8) | d)
#define INIT_STRFIELD(field, value) do {\
    strncpy((char*)(field), (value), sizeof(field)-1);\
    (field)[sizeof(field)-1]=0;\
} while (0)
#endif

void cli_detect_env_jit(struct cli_environment *env);
void cli_detect_environment(struct cli_environment *env);
#endif
