/*
 *  Detect environment for bytecode.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "target.h"

#include "bytecode_detect.h"
#include "others.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_UNAME_SYSCALL
#include <sys/utsname.h>
#endif

#define CHECK_ARCH(a) if (!strcmp(TARGET_ARCH_TYPE, #a)) env->arch = arch_##a

extern int have_clamjit;

static void cli_print_environment(struct cli_environment *env)
{
    uint32_t id_a = env->platform_id_a;
    uint32_t id_b = env->platform_id_b;
    uint32_t id_c = env->platform_id_c;
    /* the bytecode instruction that exactly identifies this platform */
    /* the space separated groups can be a concrete value, or 0xff for ANY */
    cli_dbgmsg("environment detected:\n");
    cli_dbgmsg("check_platform(0x%08x, 0x%08x, 0x%08x)\n",
	       id_a, id_b, id_c);
    cli_dbgmsg("check_platform(0x%02x  %01x  %01x  %02x  %02x,"
	       "0x%01x  %01x       %02x %02x %02x,"
	       "0x%02x    %02x %02x %02x)\n",
	       env->os_category, env->arch, env->compiler,
	       env->functionality_level,
	       env->dconf_level,
               env->big_endian,
               env->sizeof_ptr,
	       (env->cpp_version >> 16)&0xff,
	       (env->cpp_version >> 8)&0xff,
	       env->cpp_version&0xff,
	       env->os_features,
	       (env->c_version >> 16)&0xff,
	       (env->c_version >> 8)&0xff,
	       env->c_version&0xff);
    cli_dbgmsg("check_platform( OS CPU COM FL DCONF,BE PTR CXX VV.VV.VV, FLG CC VV.VV.VV)\n");
    cli_dbgmsg("Engine version: %s\n", env->engine_version);
    cli_dbgmsg("Host triple: %s\n", env->triple);
    cli_dbgmsg("Host CPU: %s\n", env->cpu);
    cli_dbgmsg("OS: %s\n", env->sysname);
    cli_dbgmsg("OS release: %s\n", env->release);
    cli_dbgmsg("OS version: %s\n", env->version);
    cli_dbgmsg("OS hardware: %s\n", env->machine);
    cli_dbgmsg("OS LLVM category: %d\n", env->os);
    cli_dbgmsg("Has JIT compiled: %d\n", env->has_jit_compiled);
    cli_dbgmsg("------------------------------------------------------\n");
}

#ifdef __linux__

static int detect_PaX(void)
{
    char line[128];
    int pax = 0;
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
	return 0;
    while (fgets(line, sizeof(line), f)) {
	if (!memcmp(line, "PaX:", 4)) {
	    pax = 1;
	    if (!strchr(line,'m'))
		pax = 2;
	    break;
	}
    }
    fclose(f);
    return pax;
}

static int detect_SELinux(void)
{
    char line[128];
    int selinux = 0;
    int enforce = 0;
    FILE *f = fopen("/proc/filesystems", "r");
    if (!f) {
	f = fopen("/selinux/enforce", "r");
        if (!f && errno == EACCES)
		return 2;
	if (f) {
	    if (fscanf(f, "%d", &enforce) == 1)
		selinux = 2;
	    fclose(f);
	}
	return selinux;
    }
    while (fgets(line, sizeof(line), f)) {
	if (strstr(line, "selinuxfs\n")) {
	    selinux = 1;
	    break;
	}
    }
    fclose(f);
    if (!selinux)
	return 0;

    f = fopen("/selinux/enforce", "r");
    if (f) {
	if (fscanf(f, "%d", &enforce) == 1) {
	    if (enforce == 1)
		selinux = 2;
	    if (enforce == -1)
		selinux = 0;
	}
	fclose(f);
    }
    return selinux;
}

static void detect_os_features(uint8_t *os_features)
{
    int features = 0;
    switch (detect_PaX()) {
	case 2:
	    features |= 1 << feature_pax_mprotect;
	    /* fall through */
	case 1:
	    features |= 1 << feature_pax;
	    break;
	default:
	    break;
    }
    switch (detect_SELinux()) {
	case 2:
	    features |= 1 << feature_selinux_enforcing;
	    /* fall through */
	case 1:
	    features |= 1 << feature_selinux;
	    break;
	default:
	    break;
    }

    *os_features = features;
}
#else
static void detect_os_features(uint8_t *os_features)
{
    *os_features = 0;
}
#endif

/* OS features : 
 * Linux: PaX << 2| SELinux << 1| mmap-RWX
 * Other:                         mmap-RWX */

void cli_detect_environment(struct cli_environment *env)
{
    memset(env, 0, sizeof(*env));
#if WORDS_BIGENDIAN == 0
    env->big_endian = 0;
#else
    env->big_endian = 1;
#endif
    env->sizeof_ptr = sizeof(void*);

    /* -- Detect arch -- */
    CHECK_ARCH(i386);
    else CHECK_ARCH(x86_64);
    else if (!strcmp(TARGET_ARCH_TYPE,"amd64")) env->arch = arch_x86_64;
    else if (!strcmp(TARGET_ARCH_TYPE,"ppc")) env->arch = arch_ppc32;/* llvm will fix ppc64 */
    else CHECK_ARCH(arm);
    else CHECK_ARCH(sparc);
    else CHECK_ARCH(sparc64);
    else CHECK_ARCH(mips);
    else CHECK_ARCH(mips64);
    else CHECK_ARCH(alpha);
    else CHECK_ARCH(hppa1);
    else CHECK_ARCH(hppa2);
    else CHECK_ARCH(m68k);
    else env->arch = arch_unknown;

    /* -- Detect OS -- */
#ifdef C_AIX
    env->os_category = os_aix;
#elif defined(C_BEOS)
    env->os_category = os_beos;
    /* DARWIN must come before BSD since it defines both */
#elif defined(C_DARWIN)
    env->os_category = os_darwin;
#elif defined(C_BSD)
    env->os_category = os_bsd;
#elif defined(C_GNU_HURD)
    env->os_category = os_gnu_hurd;
#elif defined(C_HPUX)
    env->os_category = os_hpux;
#elif defined(C_INTERIX)
    env->os_category = os_interix;
#elif defined(C_IRIX)
    env->os_category = os_irix;
#elif defined(C_KFREEBSD_GNU)
    env->os_category = os_kfreebsd_gnu;
#elif defined(C_LINUX)
    env->os_category = os_linux;
#elif defined(C_OS2)
    env->os_category = os_os2;
#elif defined(C_OSF)
    env->os_category = os_osf;
#elif defined(C_QNX6)
    env->os_category = os_qnx6;
#elif defined(C_SOLARIS)
    env->os_category = os_solaris;
#elif defined(_WIN64)
    env->os_category = os_win64;
#elif defined(_WIN32)
    env->os_category = os_win32;
#else
    env->os_category = os_generic;
#endif

    env->os = llvm_os_UnknownOS;
    /* -- Detect compiler -- */

    /* check GNUC last, because some other compilers might define it */
#ifdef __INTEL_COMPILER
    env->compiler = compiler_intel;
    env->c_version = __INTEL_COMPILER;
#elif defined(_MSC_VER)
    env->compiler = compiler_msc;
    env->c_version = _MSC_VER;
#elif defined(__SUNPRO_C)
    env->compiler = compiler_sun;
    env->c_version = __SUNPRO_C;
#elif defined(__GNUC__)

#ifdef __clang__
    env->compiler = compiler_clang;
#elif defined(__llvm__)
    env->compiler = compiler_llvm;
#else
    env->compiler = compiler_gnuc;
#endif
    env->c_version =
	MAKE_VERSION(0, __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);

#else
    env->compiler = compiler_other;
    env->c_version = 0;
#endif
    env->cpp_version = 0;

    env->has_jit_compiled = have_clamjit;

    /* engine */
    env->functionality_level = cl_retflevel();
    env->dconf_level = CL_FLEVEL_DCONF;

    INIT_STRFIELD(env->engine_version, cl_retver());
#ifdef HAVE_UNAME_SYSCALL
    {
	struct utsname name;
	if (uname(&name) == 0) {
	    INIT_STRFIELD(env->sysname, name.sysname);
	    INIT_STRFIELD(env->release, name.release);
	    INIT_STRFIELD(env->version, name.version);
	    INIT_STRFIELD(env->machine, name.machine);
	}
    }
#endif
#ifdef _WIN32
    {
	OSVERSIONINFOEX info;
	info.dwOSVersionInfoSize = sizeof(info);
	if (GetVersionEx((OSVERSIONINFO *)&info) != 0 && info.dwPlatformId == VER_PLATFORM_WIN32_NT) {
	    if (info.wProductType == VER_NT_WORKSTATION)
		INIT_STRFIELD(env->sysname, "Microsoft Windows");
	    else
		INIT_STRFIELD(env->sysname, "Microsoft Windows Server");
	    snprintf((char*)env->release, sizeof(env->release), "%d.%d SP%d.%d",
		     info.dwMajorVersion, info.dwMinorVersion,
		     info.wServicePackMajor, info.wServicePackMinor);
	    snprintf((char*)env->version, sizeof(env->version),"Build %d",
		     info.dwBuildNumber);
	}
    }
    
#endif
    if (!env->sysname[0]) {
	INIT_STRFIELD(env->sysname, TARGET_OS_TYPE);
    }

    detect_os_features(&env->os_features);

    cli_detect_env_jit(env);

    env->platform_id_a = (env->os_category << 24) | (env->arch << 20) |
	(env->compiler << 16) | (env->functionality_level << 8) |
	(env->dconf_level);
    env->platform_id_b = (env->big_endian << 28) | (env->sizeof_ptr << 24) |
      env->cpp_version;
    env->platform_id_c = (env->os_features << 24) | env->c_version;
    cli_print_environment(env);
}
