/*
 *  JIT detection for ClamAV bytecode.
 *
 *  Copyright (C) 2010 Sourcefire, Inc.
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

#include "llvm/ADT/Triple.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/System/Host.h"
#include "llvm/System/DataTypes.h"
#include "llvm/System/Memory.h"
#include "llvm/Config/config.h"

extern "C" {
#include "bytecode_detect.h"
}

using namespace llvm;

static void warn_assumptions(const char *msg, int a, int b)
{
    errs() << "LibClamAV Warning: libclamav and llvm make inconsistent"
	<< "assumptions about " << msg << ": " <<
	a << " and " << b << "."
	<< "Please report to http://bugs.clamav.net\n";
}

#define CASE_OS(theos, compat) case Triple::theos:\
    env->os = llvm_os_##theos;\
    if (env->os_category != compat)\
        warn_assumptions("Operating System", env->os_category, Triple::theos);\
    break

void cli_detect_env_jit(struct cli_environment *env)
{
    std::string host_triple = sys::getHostTriple();
    INIT_STRFIELD(env->triple, host_triple.c_str());

    std::string cpu = sys::getHostCPUName();
    INIT_STRFIELD(env->cpu, cpu.c_str());

    if (env->big_endian != (int)sys::isBigEndianHost()) {
	warn_assumptions("host endianness", env->big_endian, sys::isBigEndianHost());
	env->big_endian = sys::isBigEndianHost();
    }

#ifdef __GNUC__
    env->cpp_version = MAKE_VERSION(0, __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined (__INTEL_COMPILER)
    env->cpp_version = __INTEL_COMPILER;
#elif defined (_MSC_VER)
    env->cpp_version = _MSC_VER;
#endif

    Triple triple(host_triple);

    // CPU architecture
    enum Triple::ArchType arch = triple.getArch();
    enum arch_list earch;
    bool conflicts = false;
    switch (arch) {
	case Triple::arm:
	    earch = arch_arm;
	    if (env->arch != earch) conflicts = true;
	    break;
	case Triple::ppc:
	    earch = arch_ppc32;
	    if (env->arch != earch) conflicts = true;
	    break;
	case Triple::ppc64:
	    earch = arch_ppc64;
	    // ppc64 is fixed up by llvm
	    if (env->arch != arch_ppc32 &&
		env->arch != arch_ppc64) conflicts = true;
	    break;
	case Triple::x86:
	    earch = arch_i386;
	    if (env->arch != earch) conflicts = true;
	    break;
	case Triple::x86_64:
	    earch = arch_x86_64;
	    if (env->arch != earch) conflicts = true;
	    break;
	default:
	    earch = arch_unknown;
	    break;
    }
    if (conflicts)
	warn_assumptions("CPU architecture", env->arch, earch);
    if (earch != arch_unknown)
	env->arch = earch;

    // OS
    Triple::OSType os = triple.getOS();
    switch (os) {
	case Triple::UnknownOS:
	    env->os = llvm_os_UnknownOS;
	    break;
	CASE_OS(AuroraUX, os_solaris);
	CASE_OS(Cygwin, os_win32);
	CASE_OS(Darwin, os_darwin);
	CASE_OS(DragonFly, os_bsd);
	CASE_OS(FreeBSD, os_bsd);
	CASE_OS(Linux, os_linux);
	CASE_OS(Lv2, os_unknown);
	CASE_OS(MinGW32, os_win32);
	CASE_OS(MinGW64, os_win64);
	CASE_OS(NetBSD,  os_bsd);
	CASE_OS(OpenBSD, os_bsd);
	CASE_OS(Psp, os_unknown);
	CASE_OS(Solaris, os_solaris);
	CASE_OS(Win32, os_win32);
	CASE_OS(Haiku, os_unknown);
    }

    // mmap RWX
    std::string ErrMsg;
    sys::MemoryBlock B = sys::Memory::AllocateRWX(4096, NULL, &ErrMsg);
    if (B.base() == 0) {
	errs() << "LibClamAV Warning: RWX mapping denied: " << ErrMsg << "\n";
    } else {
	env->os_features |= 1 << feature_map_rwx;
	sys::Memory::ReleaseRWX(B);
    }
}

