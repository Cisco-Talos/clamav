/*
 *  JIT detection for ClamAV bytecode.
 *
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2010-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin, Andy Ragusa
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
#include "llvm/Config/llvm-config.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/Memory.h"

#include "llvm/Support/Endian.h"

extern "C" {
#include "bytecode_detect.h"
}

using namespace llvm;

static void warn_assumptions(const char *msg, int a, int b)
{
    errs() << "LibClamAV Warning: libclamav and llvm make inconsistent "
           << "assumptions about " << msg << ": " << a << " and " << b << "."
           << "Please report to https://github.com/Cisco-Talos/clamav/issues\n";
}

#define CASE_OS(theos, compat)                                                     \
    case Triple::theos:                                                            \
        env->os = llvm_os_##theos;                                                 \
        if (env->os_category != compat)                                            \
            warn_assumptions("Operating System", env->os_category, Triple::theos); \
        break

void cli_detect_env_jit(struct cli_environment *env)
{
    std::string host_triple = sys::getDefaultTargetTriple();
    INIT_STRFIELD(env->triple, host_triple.c_str());

    std::string cpu = sys::getHostCPUName().data();
    INIT_STRFIELD(env->cpu, cpu.c_str());

    if (env->big_endian != (int)sys::IsBigEndianHost) {
        warn_assumptions("host endianness", env->big_endian, sys::IsBigEndianHost);
        env->big_endian = sys::IsBigEndianHost;
    }

#ifdef __GNUC__
    env->cpp_version = MAKE_VERSION(0, __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(__INTEL_COMPILER)
    env->cpp_version = __INTEL_COMPILER;
#elif defined(_MSC_VER)
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
            if (env->arch != earch &&
                env->arch != arch_ppc64) conflicts = true;
            break;
        case Triple::ppc64:
            earch = arch_ppc64;
            // ppc64 is fixed up by llvm
            if (env->arch != arch_ppc32 &&
                env->arch != arch_ppc64) conflicts = true;
            break;
        case Triple::x86:
            earch = arch_i386;
            if (env->arch != earch) {
                /* bb #2153 */
                if (env->arch != arch_x86_64)
                    conflicts = true;
            }
            break;
        case Triple::x86_64:
            earch = arch_x86_64;
            if (env->arch != earch) {
                /* bb #2153, bb #2214 */
                /* configure can't detect -m32, so it thinks we are x86_64, when
                 * in fact we are i386 only.
                 * LLVM correctly detects which one it is using preprocessor
                 * macros, so don't warn here, startup.cbc will just have to
                 * rely on the LLVM provided info, and not the configure
                 * provided one! */
                if (env->arch != arch_i386)
                    conflicts = true;
            }
            break;
        default:
            earch = arch_unknown;
            break;
    }
#ifndef AC_APPLE_UNIVERSAL_BUILD
    if (conflicts)
        warn_assumptions("CPU architecture", env->arch, earch);
#endif
    if (earch != arch_unknown)
        env->arch = earch;

    // OS
    Triple::OSType os = triple.getOS();
    switch (os) {
        default: /*Treat unhandled cases as UnknownOS.*/
        case Triple::UnknownOS:
            env->os = llvm_os_UnknownOS;
            break;
            CASE_OS(Darwin, os_darwin);
            CASE_OS(DragonFly, os_bsd);
            CASE_OS(FreeBSD, os_bsd);
            CASE_OS(Linux, os_linux);
            CASE_OS(Lv2, os_unknown);
            CASE_OS(NetBSD, os_bsd);
            CASE_OS(OpenBSD, os_bsd);
            CASE_OS(Solaris, os_solaris);
        case Triple::Win32:
            env->os = llvm_os_Win32;
            if (env->os_category != os_win32 &&
                env->os_category != os_win64)
                warn_assumptions("Operating System", env->os_category, Triple::Win32);
            break;
            CASE_OS(Haiku, os_unknown);
            CASE_OS(Minix, os_unknown);
    }

    // mmap RWX
    std::error_code ec;
    sys::MemoryBlock memoryBlock = sys::Memory::allocateMappedMemory(4096, nullptr, sys::Memory::MF_READ | sys::Memory::MF_WRITE | sys::Memory::MF_EXEC, ec);
    if (ec) {
        errs() << "LibClamAV Warning: RWX mapping denied: " << ec.message() << "\n";
    } else {
        env->os_features |= 1 << feature_map_rwx;
        sys::Memory::releaseMappedMemory(memoryBlock);
    }
}
