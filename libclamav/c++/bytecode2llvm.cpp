/*
 *  JIT compile ClamAV bytecode.
 *
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
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

#include <pthread.h>
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <cstdlib>
#include <csetjmp>
#include <new>
#include <cerrno>
#include <string>

#include "ClamBCModule.h"
#include "ClamBCDiagnostics.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/AutoUpgrade.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/ExecutionEngine/JITEventListener.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/PrettyStackTrace.h"

#include "llvm/PassRegistry.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/Memory.h"
#include "llvm/Support/Mutex.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/Threading.h"
#include "llvm/Support/ThreadLocal.h"

#include "llvm/IR/IntrinsicInst.h"

#include "llvm/Support/Timer.h"

extern "C" {
void LLVMInitializeX86AsmPrinter();
void LLVMInitializePowerPCAsmPrinter();
}

#include "llvm/Support/TargetSelect.h"

#include "llvm/Target/TargetOptions.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "llvm/IR/DebugInfo.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/DataLayout.h"

#include "llvm/IR/CallingConv.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"

#include <llvm/IR/Instructions.h>

#include "llvm/Analysis/CFG.h"

#include "llvm/IR/Dominators.h"

//#define TIMING
#undef TIMING

#include "llvm/Config/llvm-config.h"
#ifdef ENABLE_THREADS
#if !ENABLE_THREADS
#error "Thread support was explicitly disabled. Cannot continue"
#endif
#endif

#ifdef LLVM_ENABLE_THREADS
#if !LLVM_ENABLE_THREADS
#error "Thread support was explicitly disabled. Cannot continue"
#endif
#endif

#ifdef _GLIBCXX_PARALLEL
#error "libstdc++ parallel mode is not supported for ClamAV. Please remove -D_GLIBCXX_PARALLEL from CXXFLAGS!"
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/Analysis/TargetFolder.h"
#include "llvm-c/Core.h"

#include "llvm/InitializePasses.h"

#ifdef HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PACKAGE_URL
#include "clamav-config.h"
#endif

#include "dconf.h"
#include "clamav.h"
#include "clambc.h"
#include "bytecode.h"
#include "bytecode_priv.h"
#include "type_desc.h"

#if LLVM_VERSION < 80
#error "LLVM_VERSION < 80 not supported"
#endif

#define MODULE "Bytecode JIT: "

extern "C" unsigned int cli_rndnum(unsigned int max);
using namespace llvm;
typedef DenseMap<const struct cli_bc_func *, void *> FunctionMapTy;
struct cli_bcengine {
    ExecutionEngine *EE;
    JITEventListener *Listener;
    LLVMContext Context;
    FunctionMapTy compiledFunctions;
    union {
        unsigned char b[16];
        void *align; /* just to align field to ptr */
    } guard;
};

extern "C" uint8_t cli_debug_flag;
namespace llvm
{
void initializeRuntimeLimitsPass(PassRegistry &);
};
namespace
{

#define llvm_report_error(x) report_fatal_error(x)
#define llvm_install_error_handler(x) install_fatal_error_handler(x)
#define DwarfExceptionHandling JITExceptionHandling

#define DEFINEPASS(passname) passname() : FunctionPass(ID)

#define NORETURN LLVM_ATTRIBUTE_NORETURN

static sys::ThreadLocal<const jmp_buf> ExceptionReturn;

static void UpgradeCall(CallInst *&C, Function *Intr)
{
    Function *New;
    if (!UpgradeIntrinsicFunction(Intr, New) || New == Intr)
        return;
    UpgradeIntrinsicCall(C, New);
}

extern "C" {
#ifdef __GNUC__
void cli_errmsg(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
void cli_errmsg(const char *str, ...);
#endif

#ifdef __GNUC__
void cli_warnmsg(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
void cli_warnmsg(const char *str, ...);
#endif

#ifdef __GNUC__
void cli_dbgmsg_no_inline(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
void cli_dbgmsg_no_inline(const char *str, ...);
#endif
}

class ScopedExceptionHandler
{
  public:
    jmp_buf &getEnv()
    {
        return env;
    }
    void Set()
    {
        /* set the exception handler's return location to here for the
         * current thread */
        ExceptionReturn.set((const jmp_buf *)&env);
    }
    ~ScopedExceptionHandler()
    {
        /* leaving scope, remove exception handler for current thread */
        ExceptionReturn.erase();
    }

  private:
    jmp_buf env;
};
#define HANDLER_TRY(handler)             \
    if (setjmp(handler.getEnv()) == 0) { \
        handler.Set();

#define HANDLER_END(handler) \
    }                        \
    else cli_warnmsg("[%s]: recovered from error\n", MODULE);

void do_shutdown()
{
    ScopedExceptionHandler handler;
    HANDLER_TRY(handler)
    {
        // TODO: be on the safe side, and clear errors here,
        // otherwise destructor calls report_fatal_error
        ((class raw_fd_ostream &)errs()).clear_error();

        llvm_shutdown();

        ((class raw_fd_ostream &)errs()).clear_error();
    }
    HANDLER_END(handler);
    remove_fatal_error_handler();
}

static void NORETURN jit_exception_handler(void)
{
    jmp_buf *buf = const_cast<jmp_buf *>(ExceptionReturn.get());
    if (buf) {
        // For errors raised during bytecode generation and execution.
        longjmp(*buf, 1);
    } else {
        // Oops, got no error recovery pointer set up,
        // this is probably an error raised during shutdown.
        cli_errmsg("[Bytecode JIT]: exception handler called, but no recovery point set up");
        // should never happen, we remove the error handler when we don't use
        // LLVM anymore, and when we use it, we do set an error recovery point.
        llvm_unreachable("Bytecode JIT]: no exception handler recovery installed, but exception hit!");
    }
}

static void NORETURN jit_ssp_handler(void)
{
    cli_errmsg("[Bytecode JIT]: *** stack smashing detected, bytecode aborted\n");
    jit_exception_handler();
}

void llvm_error_handler(void *user_data, const std::string &reason, bool gen_crash_diag = true)
{
    // Output it to stderr, it might exceed the 1k/4k limit of cli_errmsg
    cli_errmsg("[Bytecode JIT]: [LLVM error] %s\n", reason.c_str());
    jit_exception_handler();
}

// Since libgcc is not available on all compilers (for example on win32),
// just define what these functions should do, the compiler will forward to
// the appropriate libcall if needed.
static int64_t rtlib_sdiv_i64(int64_t a, int64_t b)
{
    return a / b;
}

static uint64_t rtlib_udiv_i64(uint64_t a, uint64_t b)
{
    return a / b;
}

static int64_t rtlib_srem_i64(int64_t a, int64_t b)
{
    return a % b;
}

static uint64_t rtlib_urem_i64(uint64_t a, uint64_t b)
{
    return a % b;
}

static int64_t rtlib_mul_i64(uint64_t a, uint64_t b)
{
    return a * b;
}

static int64_t rtlib_shl_i64(int64_t a, int32_t b)
{
    return a << b;
}

static int64_t rtlib_srl_i64(int64_t a, int32_t b)
{
    return (uint64_t)a >> b;
}
/* Implementation independent sign-extended signed right shift */
#ifdef HAVE_SAR
#define CLI_SRS(n, s) ((n) >> (s))
#else
#define CLI_SRS(n, s) ((((n) >> (s)) ^ (1 << (sizeof(n) * 8 - 1 - s))) - (1 << (sizeof(n) * 8 - 1 - s)))
#endif
static int64_t rtlib_sra_i64(int64_t a, int32_t b)
{
    return CLI_SRS(a, b); // CLI_./..
}

static void rtlib_bzero(void *s, size_t n)
{
    memset(s, 0, n);
}

#ifdef _WIN32
#ifdef _WIN64
extern "C" void __chkstk(void);
#else
extern "C" void _chkstk(void);
#endif
#endif
// Resolve integer libcalls, but nothing else.
static void *noUnknownFunctions(const std::string &name)
{
    void *addr =
        StringSwitch<void *>(name)
            .Case("__divdi3", (void *)(intptr_t)rtlib_sdiv_i64)
            .Case("__udivdi3", (void *)(intptr_t)rtlib_udiv_i64)
            .Case("__moddi3", (void *)(intptr_t)rtlib_srem_i64)
            .Case("__umoddi3", (void *)(intptr_t)rtlib_urem_i64)
            .Case("__muldi3", (void *)(intptr_t)rtlib_mul_i64)
            .Case("__ashrdi3", (void *)(intptr_t)rtlib_sra_i64)
            .Case("__ashldi3", (void *)(intptr_t)rtlib_shl_i64)
            .Case("__lshrdi3", (void *)(intptr_t)rtlib_srl_i64)
            .Case("__bzero", (void *)(intptr_t)rtlib_bzero)
            .Case("memmove", (void *)(intptr_t)memmove)
            .Case("memcpy", (void *)(intptr_t)memcpy)
            .Case("memset", (void *)(intptr_t)memset)
            .Case("abort", (void *)(intptr_t)jit_exception_handler)
#ifdef _WIN32
#ifdef _WIN64
            .Case("_chkstk", (void *)(intptr_t)__chkstk)
#else
            .Case("_chkstk", (void *)(intptr_t)_chkstk)
#endif
#endif
            .Default(0);
    if (addr) {
        return addr;
    }

    return 0;
}

class NotifyListener : public JITEventListener
{
  public:
    // MCJIT doesn't emit single functions, but instead whole objects.
    virtual void NotifyObjectEmitted(const object::ObjectFile &Obj,
                                     const RuntimeDyld::LoadedObjectInfo &L)
    {
        if (!cli_debug_flag)
            return;
        cli_dbgmsg_no_inline("[Bytecode JIT]; emitted %s %s of %zd bytes\n",
                             Obj.getFileFormatName().str().c_str(),
                             Obj.getFileName().str().c_str(), Obj.getData().size());
    }
};

class TimerWrapper
{
  private:
    Timer *t;

  public:
    TimerWrapper(const std::string &name)
    {
        t = 0;
#ifdef TIMING
        t = new Timer(name);
#endif
    }
    ~TimerWrapper()
    {
        if (t)
            delete t;
    }
    void startTimer()
    {
        if (t)
            t->startTimer();
    }
    void stopTimer()
    {
        if (t)
            t->stopTimer();
    }
};

class LLVMTypeMapper
{
  private:
    std::vector<Type *> TypeMap;
    LLVMContext &Context;
    unsigned numTypes;
    Type *getStatic(uint16_t ty)
    {
        if (!ty)
            return Type::getVoidTy(Context);
        if (ty <= 64)
            return IntegerType::get(Context, ty);
        switch (ty) {
            case 65:
                return PointerType::getUnqual(Type::getInt8Ty(Context));
            case 66:
                return PointerType::getUnqual(Type::getInt16Ty(Context));
            case 67:
                return PointerType::getUnqual(Type::getInt32Ty(Context));
            case 68:
                return PointerType::getUnqual(Type::getInt64Ty(Context));
        }
        llvm_unreachable("getStatic");
    }

  public:
    TimerWrapper pmTimer;
    TimerWrapper irgenTimer;

    LLVMTypeMapper(LLVMContext &Context, const struct cli_bc_type *types,
                   unsigned count, Type *Hidden = 0)
        : Context(Context), numTypes(count),
          pmTimer("Function passes"), irgenTimer("IR generation")
    {
        TypeMap.reserve(count);
        // During recursive type construction pointers to Type* may be
        // invalidated, so we must use a TypeHolder to an Opaque type as a
        // start.
        for (unsigned i = 0; i < count; i++) {
            TypeMap.push_back(0);
        }
        for (unsigned i = 0; i < count; i++) {
            const struct cli_bc_type *type = &types[i];

            Type *Ty   = buildType(type, types, Hidden, 0);
            TypeMap[i] = Ty;
        }
    }

    Type *buildType(const struct cli_bc_type *type, const struct cli_bc_type *types, Type *Hidden, int recursive)
    {
        std::vector<Type *> Elts;
        unsigned n = type->kind == DArrayType ? 1 : type->numElements;
        for (unsigned j = 0; j < n; j++) {
            Elts.push_back(get(type->containedTypes[j], types, Hidden));
        }
        Type *Ty;
        switch (type->kind) {
            case DFunctionType: {
                assert(Elts.size() > 0 && "Function with no return type?");
                Type *RetTy = Elts[0];
                if (Hidden)
                    Elts[0] = Hidden;
                else
                    Elts.erase(Elts.begin());
                Ty = FunctionType::get(RetTy, Elts, false);
                break;
            }
            case DPointerType:
                if (!PointerType::isValidElementType(Elts[0]))
                    Ty = PointerType::getUnqual(Type::getInt8Ty(Context));
                else
                    Ty = PointerType::getUnqual(Elts[0]);
                break;
            case DStructType:
            case DPackedStructType:
                Ty = StructType::get(Context, Elts, type->kind == DPackedStructType);
                break;
            case DArrayType:
                Ty = ArrayType::get(Elts[0], type->numElements);
                break;
            default:
                llvm_unreachable("type->kind");
        }
        return Ty;
    }

    Type *get(uint16_t ty, const struct cli_bc_type *types, Type *Hidden)
    {
        ty &= 0x7fff;
        if (ty < 69)
            return getStatic(ty);
        ty -= 69;
        assert((ty < numTypes) && "TypeID out of range");
        Type *Ty = TypeMap[ty];
        if (Ty)
            return Ty;
        assert((types && Hidden) || "accessing not-yet-built type");
        Ty          = buildType(&types[ty], types, Hidden, 1);
        TypeMap[ty] = Ty;
        return Ty;
    }
};

struct CommonFunctions {
    Function *FHandler;
    Function *FMemset;
    Function *FMemmove;
    Function *FMemcpy;
    Function *FRealmemset;
    Function *FRealMemmove;
    Function *FRealmemcmp;
    Function *FRealmemcpy;
    Function *FBSwap16;
    Function *FBSwap32;
    Function *FBSwap64;
};

// loops with tripcounts higher than this need timeout check
static const unsigned LoopThreshold = 1000;

// after every N API calls we need timeout check
static const unsigned ApiThreshold = 100;

class RuntimeLimits : public FunctionPass
{
    typedef SmallVector<std::pair<const BasicBlock *, const BasicBlock *>, 16>
        BBPairVectorTy;
    typedef SmallSet<BasicBlock *, 16> BBSetTy;
    typedef DenseMap<const BasicBlock *, unsigned> BBMapTy;
    bool loopNeedsTimeoutCheck(ScalarEvolution &SE, const Loop *L, BBMapTy &Map)
    {
        // This BB is a loop header, if trip count is small enough
        // no timeout checks are needed here.

#if LLVM_VERSION < 100
        const SCEV *S = SE.getMaxBackedgeTakenCount(L);
#else
        const SCEV *S     = SE.getConstantMaxBackedgeTakenCount(L);
#endif
        if (isa<SCEVCouldNotCompute>(S)) {
            return true;
        }
        ConstantRange CR = SE.getUnsignedRange(S);
        uint64_t max     = CR.getUnsignedMax().getLimitedValue();
        if (max > LoopThreshold) {
            return true;
        }
        unsigned apicalls = 0;
        for (Loop::block_iterator J = L->block_begin(), JE = L->block_end();
             J != JE; ++J) {
            apicalls += Map[*J];
        }
        apicalls *= max;
        if (apicalls > ApiThreshold) {
            return true;
        }
        Map[L->getHeader()] = apicalls;
        return false;
    }

  public:
    static char ID;
    DEFINEPASS(RuntimeLimits)
    {
        PassRegistry &Registry = *PassRegistry::getPassRegistry();
        initializeRuntimeLimitsPass(Registry);
    }

    virtual bool runOnFunction(Function &F)
    {
        // Module * pMod = F.getParent();
        BBSetTy BackedgeTargets;
        if (!F.isDeclaration()) {
            // Get the common backedge targets.
            // Note that we don't rely on LoopInfo here, since
            // it is possible to construct a CFG that doesn't have natural loops,
            // yet it does have backedges, and thus can lead to unbounded/high
            // execution time.
            BBPairVectorTy V;
            FindFunctionBackedges(F, V);
            for (BBPairVectorTy::iterator I = V.begin(), E = V.end(); I != E; ++I) {
                BackedgeTargets.insert(const_cast<BasicBlock *>(I->second));
            }
        }
        BBSetTy needsTimeoutCheck;
        BBMapTy BBMap;
        DominatorTree &DT = getAnalysis<DominatorTreeWrapperPass>().getDomTree();
        for (Function::iterator I = F.begin(), E = F.end(); I != E; ++I) {
            BasicBlock *BB    = &*I;
            unsigned apicalls = 0;
            for (BasicBlock::const_iterator J = BB->begin(), JE = BB->end();
                 J != JE; ++J) {
                if (const CallInst *CI = dyn_cast<CallInst>(J)) {
                    Function *F = CI->getCalledFunction();
                    if (!F || F->isDeclaration())
                        apicalls++;
                }
            }
            if (apicalls > ApiThreshold) {
                needsTimeoutCheck.insert(BB);
                apicalls = 0;
            }
            BBMap[BB] = apicalls;
        }
        if (!BackedgeTargets.empty()) {
            LoopInfo &LI        = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
            ScalarEvolution &SE = getAnalysis<ScalarEvolutionWrapperPass>().getSE();

            // Now check whether any of these backedge targets are part of a loop
            // with a small constant trip count
            for (BBSetTy::iterator I = BackedgeTargets.begin(), E = BackedgeTargets.end();
                 I != E; ++I) {
                const Loop *L = LI.getLoopFor(*I);
                if (L && L->getHeader() == *I &&
                    !loopNeedsTimeoutCheck(SE, L, BBMap))
                    continue;
                needsTimeoutCheck.insert(*I);
                BBMap[*I] = 0;
            }
        }
        // Estimate number of apicalls by walking dominator-tree bottom-up.
        // BBs that have timeout checks are considered to have 0 APIcalls
        // (since we already checked for timeout).
        for (po_iterator<DomTreeNode *> I = po_begin(DT.getRootNode()),
                                        E = po_end(DT.getRootNode());
             I != E; ++I) {
            if (needsTimeoutCheck.count(I->getBlock()))
                continue;
            unsigned apicalls = BBMap[I->getBlock()];
            for (DomTreeNode::iterator J = I->begin(), JE = I->end();
                 J != JE; ++J) {
                apicalls += BBMap[(*J)->getBlock()];
            }
            if (apicalls > ApiThreshold) {
                needsTimeoutCheck.insert(I->getBlock());
                apicalls = 0;
            }
            BBMap[I->getBlock()] = apicalls;
        }
        if (needsTimeoutCheck.empty()) {
            return false;
        }

        std::vector<Type *> args;
        FunctionType *abrtTy = FunctionType::get(
            Type::getVoidTy(F.getContext()), args, false);

#if LLVM_VERSION < 90
        Value *func_abort = F.getParent()->getOrInsertFunction("abort", abrtTy);
#else
        Value *func_abort = F.getParent()->getOrInsertFunction("abort", abrtTy).getCallee();
#endif

        BasicBlock *AbrtBB = BasicBlock::Create(F.getContext(), "runOnFunction_abort_", &F);
        CallInst *AbrtC    = CallInst::Create(abrtTy, func_abort, "", AbrtBB);
        AbrtC->setCallingConv(CallingConv::C);
        AbrtC->setTailCall(true);
        AbrtC->setDoesNotReturn();
        AbrtC->setDoesNotThrow();
        new UnreachableInst(F.getContext(), AbrtBB);

        IRBuilder<> Builder(F.getContext());

        Value *Flag = F.arg_begin();
        verifyFunction(F);
        BasicBlock *BB = &F.getEntryBlock();

        Builder.SetInsertPoint(BB->getTerminator());

        Flag = Builder.CreatePointerCast(Flag, PointerType::getUnqual(
                                                   Type::getInt1Ty(F.getContext())));

        for (BBSetTy::iterator I = needsTimeoutCheck.begin(),
                               E = needsTimeoutCheck.end();
             I != E; ++I) {

            BasicBlock *BB     = *I;
            Instruction *pInst = nullptr;
            for (auto i = BB->begin(), e = BB->end(); i != e; i++) {
                pInst = llvm::cast<Instruction>(i);

                // I know we don't currently support Landing Pads, but this is
                // still easy enough to check for.
                if (not(llvm::isa<PHINode>(pInst) or llvm::isa<LandingPadInst>(i))) {
                    break;
                }
            }

            Builder.SetInsertPoint(pInst);

            Builder.CreateFence(AtomicOrdering::Release);

            // Load Flag that tells us we timed out (first byte in bc_ctx)
            Instruction *Cond = Builder.CreateLoad(Flag, true);

            /* splitBasicBlock splits AFTER insPt */
            BasicBlock *newBB = BB->splitBasicBlock(pInst, "runOnFunction_block_");

            pInst = llvm::cast<Instruction>(BB->getTerminator());
            BranchInst::Create(AbrtBB, newBB, Cond, pInst);
            pInst->eraseFromParent();

            // Update dominator info
            DomTreeNode *N = DT.getNode(AbrtBB);
            if (!N) {
                DT.addNewBlock(AbrtBB, BB);
            } else {
                BasicBlock *DomBB = DT.findNearestCommonDominator(BB,
                                                                  N->getIDom()->getBlock());
                DT.changeImmediateDominator(AbrtBB, DomBB);
            }
        }

        verifyFunction(F);
        return true;
    }

    virtual void getAnalysisUsage(AnalysisUsage &AU) const
    {
        AU.setPreservesAll();
        AU.addRequired<LoopInfoWrapperPass>();
        AU.addRequired<ScalarEvolutionWrapperPass>();
        AU.addRequired<DominatorTreeWrapperPass>();
    }
};
char RuntimeLimits::ID;

// select i1 false ... which instcombine would simplify but we don't run
// instcombine.
class BrSimplifier : public FunctionPass
{
  public:
    static char ID;
    DEFINEPASS(BrSimplifier) {}

    virtual bool runOnFunction(Function &F)
    {
        bool Changed = false;
        for (Function::iterator I = F.begin(), E = F.end(); I != E; ++I) {
            if (BranchInst *BI = dyn_cast<BranchInst>(I->getTerminator())) {
                if (BI->isUnconditional())
                    continue;
                Value *V = BI->getCondition();
                if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
                    BasicBlock *Other;
                    if (CI->isOne()) {
                        BranchInst::Create(BI->getSuccessor(0), &*I);
                        Other = BI->getSuccessor(1);
                    } else {
                        BranchInst::Create(BI->getSuccessor(1), &*I);
                        Other = BI->getSuccessor(0);
                    }
                    Other->removePredecessor(&*I);
                    BI->eraseFromParent();
                    Changed = true;
                }
            }
            for (BasicBlock::iterator J = I->begin(), JE = I->end();
                 J != JE;) {
                SelectInst *SI = dyn_cast<SelectInst>(J);
                ++J;
                if (!SI)
                    continue;
                ConstantInt *CI = dyn_cast<ConstantInt>(SI->getCondition());
                if (!CI)
                    continue;
                if (CI->isOne())
                    SI->replaceAllUsesWith(SI->getTrueValue());
                else
                    SI->replaceAllUsesWith(SI->getFalseValue());
                SI->eraseFromParent();
                Changed = true;
            }
        }

        return Changed;
    }
};
char BrSimplifier::ID;
class LLVMCodegen
{
  private:
    const struct cli_bc *bc;
    Module *M;
    LLVMContext &Context;
    ExecutionEngine *EE;
    legacy::FunctionPassManager &PM, &PMUnsigned;
    LLVMTypeMapper *TypeMap;

    Function **apiFuncs;
    LLVMTypeMapper &apiMap;
    FunctionMapTy &compiledFunctions;
    Twine BytecodeID;

    TargetFolder Folder;
    IRBuilder<> Builder;

    std::vector<Value *> globals;
    DenseMap<unsigned, unsigned> GVoffsetMap;
    DenseMap<unsigned, Type *> GVtypeMap;
    Value **Values;
    unsigned numLocals;
    unsigned numArgs;
    std::vector<MDNode *> mdnodes;

    struct CommonFunctions *CF;

    Value *getOperand(const struct cli_bc_func *func, Type *Ty, operand_t operand)
    {
        unsigned map[] = {0, 1, 2, 3, 3, 4, 4, 4, 4};
        if (operand < func->numValues)
            return Values[operand];
        unsigned w = Ty->getPrimitiveSizeInBits();
        if (w > 1)
            w = (w + 7) / 8;
        else
            w = 0;
        return convertOperand(func, map[w], operand);
    }

    Value *convertOperand(const struct cli_bc_func *func, Type *Ty, operand_t operand)
    {
        unsigned map[] = {0, 1, 2, 3, 3, 4, 4, 4, 4};
        if (operand < func->numArgs)
            return Values[operand];
        if (operand < func->numValues) {
            Value *V = Values[operand];
            if (func->types[operand] & 0x8000 && V->getType() == Ty) {
                return V;
            }
            V = Builder.CreateLoad(V);
            if (V->getType() != Ty &&
                isa<PointerType>(V->getType()) &&
                isa<PointerType>(Ty))
                V = Builder.CreateBitCast(V, Ty);
            if (V->getType() != Ty) {
                if (cli_debug_flag) {
                    std::string str;
                    raw_string_ostream ostr(str);
                    ostr << operand << " ";
                    V->print(ostr);
                    Ty->print(ostr);
                    // M->dump();
                    cli_dbgmsg_no_inline("[Bytecode JIT]: operand %d: %s\n", operand, ostr.str().c_str());
                }
                llvm_report_error("(libclamav) Type mismatch converting operand");
            }
            return V;
        }
        unsigned w = Ty->getPrimitiveSizeInBits();
        if (w > 1)
            w = (w + 7) / 8;
        else
            w = 0;
        return convertOperand(func, map[w], operand);
    }

    Value *convertOperand(const struct cli_bc_func *func,
                          const struct cli_bc_inst *inst, operand_t operand)
    {
        return convertOperand(func, inst->interp_op % 5, operand);
    }

    Value *convertOperand(const struct cli_bc_func *func,
                          unsigned w, operand_t operand)
    {
        if (operand < func->numArgs)
            return Values[operand];
        if (operand < func->numValues) {
            if (func->types[operand] & 0x8000)
                return Values[operand];
            return Builder.CreateLoad(Values[operand]);
        }

        if (operand & 0x80000000) {
            operand &= 0x7fffffff;
            assert((operand < globals.size()) && "Global index out of range");
            // Global
            if (!operand)
                return ConstantPointerNull::get(PointerType::getUnqual(Type::getInt8Ty(Context)));
            assert(globals[operand]);
            if (GlobalVariable *GV = dyn_cast<GlobalVariable>(globals[operand])) {
                if (ConstantExpr *CE = dyn_cast<ConstantExpr>(GV->getInitializer())) {
                    return CE;
                }
                return GV;
            }
            return globals[operand];
        }
        // Constant
        operand -= func->numValues;
        // This was already validated by libclamav.
        assert((operand < func->numConstants) && "Constant out of range");
        uint64_t *c = &func->constants[operand];
        uint64_t v;
        Type *Ty;
        switch (w) {
            case 0:
            case 1:
                Ty = w ? Type::getInt8Ty(Context) : Type::getInt1Ty(Context);
                v  = *(uint8_t *)c;
                break;
            case 2:
                Ty = Type::getInt16Ty(Context);
                v  = *(uint16_t *)c;
                break;
            case 3:
                Ty = Type::getInt32Ty(Context);
                v  = *(uint32_t *)c;
                break;
            case 4:
                Ty = Type::getInt64Ty(Context);
                v  = *(uint64_t *)c;
                break;
            default:
                llvm_unreachable("width");
        }
        return ConstantInt::get(Ty, v);
    }

    void Store(uint16_t dest, Value *V)
    {
        assert(((dest >= numArgs) && (dest < numLocals + numArgs)) && "Instruction destination out of range");
        Builder.CreateStore(V, Values[dest]);
    }

    // Insert code that calls \arg CF->FHandler if \arg FailCond is true.
    void InsertVerify(Value *FailCond, BasicBlock *&Fail, Function *FHandler,
                      Function *F)
    {
        if (!Fail) {
            Fail = BasicBlock::Create(Context, "fail", F);
            CallInst::Create(FHandler, "", Fail);
            new UnreachableInst(Context, Fail);
        }
        BasicBlock *OkBB = BasicBlock::Create(Context, "", F);
        Builder.CreateCondBr(FailCond, Fail, OkBB);
        Builder.SetInsertPoint(OkBB);
    }

    Type *mapType(uint16_t typeID)
    {
        return TypeMap->get(typeID & 0x7fffffff, NULL, NULL);
    }

    Constant *buildConstant(Type *Ty, uint64_t *components, unsigned &c)
    {
        if (PointerType *PTy = dyn_cast<PointerType>(Ty)) {
            Value *idxs[1] = {
                ConstantInt::get(Type::getInt64Ty(Context), components[c++])};
            unsigned idx = components[c++];
            if (!idx) {
                return ConstantPointerNull::get(PTy);
            }
            if (idx >= globals.size()) {
                return ConstantPointerNull::get(PTy);
            }
            assert(idx < globals.size());
            GlobalVariable *GV = dyn_cast<GlobalVariable>(globals[idx]);
            if (nullptr == GV) {
                return ConstantPointerNull::get(PTy);
            }
            Type *IP8Ty = PointerType::getUnqual(Type::getInt8Ty(Ty->getContext()));
            Constant *C = ConstantExpr::getPointerCast(GV, IP8Ty);
            // TODO: check constant bounds here
            return ConstantExpr::getPointerCast(
                ConstantExpr::getInBoundsGetElementPtr(C->getType(), C, idxs),
                PTy);
        }
        if (isa<IntegerType>(Ty)) {
            return ConstantInt::get(Ty, components[c++]);
        }
        if (ArrayType *ATy = dyn_cast<ArrayType>(Ty)) {
            std::vector<Constant *> elements;
            elements.reserve(ATy->getNumElements());
            for (unsigned i = 0; i < ATy->getNumElements(); i++) {
                elements.push_back(buildConstant(ATy->getElementType(), components, c));
            }
            return ConstantArray::get(ATy, elements);
        }
        if (StructType *STy = dyn_cast<StructType>(Ty)) {
            std::vector<Constant *> elements;
            elements.reserve(STy->getNumElements());
            for (unsigned i = 0; i < STy->getNumElements(); i++) {
                elements.push_back(buildConstant(STy->getElementType(i), components, c));
            }
            return ConstantStruct::get(STy, elements);
        }
        // Ty->dump();
        llvm_unreachable("invalid type");
        return 0;
    }

  public:
    LLVMCodegen(const struct cli_bc *bc, Module *M, struct CommonFunctions *CF, FunctionMapTy &cFuncs,
                ExecutionEngine *EE, legacy::FunctionPassManager &PM, legacy::FunctionPassManager &PMUnsigned,
                Function **apiFuncs, LLVMTypeMapper &apiMap)
        : bc(bc), M(M), Context(M->getContext()), EE(EE),
          PM(PM), PMUnsigned(PMUnsigned), TypeMap(), apiFuncs(apiFuncs), apiMap(apiMap),
          compiledFunctions(cFuncs), BytecodeID("bc" + Twine(bc->id)),
          Folder(EE->getDataLayout()), Builder(Context), Values(), CF(CF)
    {

        for (unsigned i = 0; i < cli_apicall_maxglobal - _FIRST_GLOBAL; i++) {
            unsigned id     = cli_globals[i].globalid;
            GVoffsetMap[id] = cli_globals[i].offset;
        }
        numLocals = 0;
        numArgs   = 0;
    }

    Value *createGEP(Value *Base, Type *ETy, ArrayRef<Value *> ARef)
    {
        return Builder.CreateGEP(Base, ARef);
    }

    bool createGEP(unsigned dest, Value *Base, ArrayRef<Value *> ARef)
    {
        assert(((dest >= numArgs) && (dest < numLocals + numArgs)) && "Instruction destination out of range");
        Type *ETy = cast<PointerType>(cast<PointerType>(Values[dest]->getType())->getElementType())->getElementType();
        Value *V  = createGEP(Base, ETy, ARef);
        if (!V) {
            if (cli_debug_flag) {
                cli_dbgmsg_no_inline("[Bytecode JIT] @%d\n", dest);
            }
            return false;
        }
        V = Builder.CreateBitCast(V, PointerType::getUnqual(ETy));
        Store(dest, V);
        return true;
    }

    MDNode *convertMDNode(unsigned i)
    {
        if (i < mdnodes.size()) {
            if (mdnodes[i])
                return mdnodes[i];
        } else
            mdnodes.resize(i + 1);
        assert(i < mdnodes.size());
        const struct cli_bc_dbgnode *node = &bc->dbgnodes[i];
        Metadata **Vals                   = new Metadata *[node->numelements];
        for (unsigned j = 0; j < node->numelements; j++) {
            const struct cli_bc_dbgnode_element *el = &node->elements[j];
            Metadata *V;
            if (!el->len) {
                if (el->nodeid == ~0u)
                    V = 0;
                else if (el->nodeid)
                    V = convertMDNode(el->nodeid);
                else
                    V = MDString::get(Context, "");
            } else if (el->string) {
                V = MDString::get(Context, StringRef(el->string, el->len));
            } else {
                V = ConstantAsMetadata::get(ConstantInt::get(IntegerType::get(Context, el->len),
                                                             el->constant));
            }
            Vals[j] = V;
        }
        MDNode *N = MDNode::get(Context, ArrayRef<Metadata *>(Vals, node->numelements));
        delete[] Vals;
        mdnodes[i] = N;
        return N;
    }

    void AddStackProtect(Function *F)
    {
        BasicBlock &BB = F->getEntryBlock();
        if (isa<AllocaInst>(BB.begin())) {
            // Have an alloca -> some instruction uses its address otherwise
            // mem2reg would have converted it to an SSA register.
            // Enable stack protector for this function.
        }
        // always add stackprotect attribute (bb #2239), so we know this
        // function was verified. If there is no alloca it won't actually add
        // stack protector in emitted code so this won't slow down the app.
    }

    Value *GEPOperand(Value *V)
    {
        if (LoadInst *LI = dyn_cast<LoadInst>(V)) {
            Value *VI     = LI->getOperand(0);
            StoreInst *SI = 0;
            for (Value::use_iterator I = VI->use_begin(),
                                     E = VI->use_end();
                 I != E; ++I) {
                Value *I_V = *I;
                if (StoreInst *S = dyn_cast<StoreInst>(I_V)) {
                    if (SI)
                        return V;
                    SI = S;
                } else if (!isa<LoadInst>(I_V))
                    return V;
            }
            V = SI->getOperand(0);
        }
        if (EE->getDataLayout().getPointerSize() == 8) {
            // eliminate useless trunc, GEP can take i64 too
            if (TruncInst *I = dyn_cast<TruncInst>(V)) {
                Value *Src = I->getOperand(0);
                if (Src->getType() == Type::getInt64Ty(Context) &&
                    I->getType() == Type::getInt32Ty(Context))
                    return Src;
            }
        }
        return V;
    }

    Function *generate()
    {
        PrettyStackTraceString CrashInfo("Generate LLVM IR functions");
        apiMap.irgenTimer.startTimer();
        TypeMap = new LLVMTypeMapper(Context, bc->types + 4, bc->num_types - 5);
        for (unsigned i = 0; i < bc->dbgnode_cnt; i++) {
            mdnodes.push_back(convertMDNode(i));
        }

        for (unsigned i = 0; i < cli_apicall_maxglobal - _FIRST_GLOBAL; i++) {
            unsigned id   = cli_globals[i].globalid;
            Type *Ty      = apiMap.get(cli_globals[i].type, NULL, NULL);
            GVtypeMap[id] = Ty;
        }

        // The hidden ctx param to all functions
        unsigned maxh   = cli_globals[0].offset + sizeof(struct cli_bc_hooks);
        Type *HiddenCtx = PointerType::getUnqual(ArrayType::get(Type::getInt8Ty(Context), maxh));

        globals.reserve(bc->num_globals);
        BitVector FakeGVs;
        FakeGVs.resize(bc->num_globals);
        globals.push_back(0);
        for (unsigned i = 1; i < bc->num_globals; i++) {
            Type *Ty = mapType(bc->globaltys[i]);

            // TODO: validate number of components against type_components
            unsigned c = 0;
            GlobalVariable *GV;
            if (isa<PointerType>(Ty)) {
                unsigned g = bc->globals[i][1];
                if (GVoffsetMap.count(g)) {
                    FakeGVs.set(i);
                    globals.push_back(0);
                    continue;
                }
            }
            Constant *C = buildConstant(Ty, bc->globals[i], c);

            GV = new GlobalVariable(*M, Ty, true,
                                    GlobalValue::InternalLinkage,
                                    C, "glob" + Twine(i));
            globals.push_back(GV);
        }
        Function **Functions = new Function *[bc->num_func];
        for (unsigned j = 0; j < bc->num_func; j++) {
            // Create LLVM IR Function
            const struct cli_bc_func *func = &bc->funcs[j];
            std::vector<Type *> argTypes;
            argTypes.push_back(HiddenCtx);
            for (unsigned a = 0; a < func->numArgs; a++) {
                argTypes.push_back(mapType(func->types[a]));
            }
            Type *RetTy       = mapType(func->returnType);
            FunctionType *FTy = FunctionType::get(RetTy, argTypes, false);
            Functions[j]      = Function::Create(FTy, Function::InternalLinkage, BytecodeID + "f" + Twine(j), M);
            Functions[j]->setDoesNotThrow();
            Functions[j]->setCallingConv(CallingConv::Fast);
            Functions[j]->setLinkage(GlobalValue::InternalLinkage);
        }
        Type *I32Ty = Type::getInt32Ty(Context);
        for (unsigned j = 0; j < bc->num_func; j++) {
            PrettyStackTraceString CrashInfo("Generate LLVM IR");
            const struct cli_bc_func *func = &bc->funcs[j];
            bool broken                    = false;

            // Create all BasicBlocks
            Function *F     = Functions[j];
            BasicBlock **BB = new BasicBlock *[func->numBB];
            for (unsigned i = 0; i < func->numBB; i++) {
                BB[i] = BasicBlock::Create(Context, "", F);
            }

            BasicBlock *Fail = 0;
            Values           = new Value *[func->numValues];
            Builder.SetInsertPoint(BB[0]);
            Function::arg_iterator I = F->arg_begin();
            assert((F->arg_size() == (unsigned)(func->numArgs + 1)) && "Mismatched args");
            ++I;
            for (unsigned i = 0; i < func->numArgs; i++) {
                assert(I != F->arg_end());
                Values[i] = &*I;
                ++I;
            }
            for (unsigned i = func->numArgs; i < func->numValues; i++) {
                if (!func->types[i]) {
                    // instructions without return value, like store
                    Values[i] = 0;
                    continue;
                }
                Values[i] = Builder.CreateAlloca(mapType(func->types[i]));
            }
            numLocals = func->numLocals;
            numArgs   = func->numArgs;

            if (FakeGVs.any()) {
                Argument *Ctx = F->arg_begin();
                for (unsigned i = 0; i < bc->num_globals; i++) {
                    if (!FakeGVs[i])
                        continue;
                    unsigned g      = bc->globals[i][1];
                    unsigned offset = GVoffsetMap[g];
                    Constant *Idx   = ConstantInt::get(Type::getInt32Ty(Context), offset);
                    Value *Idxs[2]  = {
                        ConstantInt::get(Type::getInt32Ty(Context), 0),
                        Idx};
                    Value *GEP       = Builder.CreateInBoundsGEP(Ctx, ArrayRef<Value *>(Idxs, Idxs + 2));
                    Type *Ty         = GVtypeMap[g];
                    Ty               = PointerType::getUnqual(PointerType::getUnqual(Ty));
                    Value *Cast      = Builder.CreateBitCast(GEP, Ty);
                    Value *SpecialGV = Builder.CreateLoad(Cast);
                    Type *IP8Ty      = Type::getInt8Ty(Context);
                    IP8Ty            = PointerType::getUnqual(IP8Ty);
                    SpecialGV        = Builder.CreateBitCast(SpecialGV, IP8Ty);
                    SpecialGV->setName("g" + Twine(g - _FIRST_GLOBAL) + "_");
                    Value *C[] = {
                        ConstantInt::get(Type::getInt32Ty(Context), bc->globals[i][0])};
                    globals[i] = createGEP(SpecialGV, 0, ArrayRef<Value *>(C, C + 1));
                    if (!globals[i]) {
                        if (cli_debug_flag) {
                            std::string str;
                            raw_string_ostream ostr(str);
                            ostr << i << ":" << g << ":" << bc->globals[i][0] << "\n";
                            Ty->print(ostr);
                            cli_dbgmsg_no_inline("[Bytecode JIT]: %s\n", ostr.str().c_str());
                        }
                        llvm_report_error("(libclamav) unable to create fake global");
                    }
                    globals[i] = Builder.CreateBitCast(globals[i], Ty);
                    if (GetElementPtrInst *GI = dyn_cast<GetElementPtrInst>(globals[i])) {
                        GI->setIsInBounds(true);
                        GI->setName("geped" + Twine(i) + "_");
                    }
                }
            }

            // Generate LLVM IR for each BB
            for (unsigned i = 0; i < func->numBB && !broken; i++) {
                bool unreachable           = false;
                const struct cli_bc_bb *bb = &func->BB[i];
                Builder.SetInsertPoint(BB[i]);
                unsigned c = 0;
                for (unsigned j = 0; j < bb->numInsts && !broken; j++) {
                    const struct cli_bc_inst *inst = &bb->insts[j];
                    Value *Op0 = 0, *Op1 = 0, *Op2 = 0;
                    // libclamav has already validated this.
                    assert(inst->opcode < OP_BC_INVALID && "Invalid opcode");
                    if (func->dbgnodes) {
                        if (func->dbgnodes[c] != ~0u) {
                            unsigned j = func->dbgnodes[c];
                            assert(j < mdnodes.size());
                            if (DILocation *dil = llvm::dyn_cast<DILocation>(mdnodes[j])) {
                                Builder.SetCurrentDebugLocation(dil);
                            }
                        } else {
                            Builder.SetCurrentDebugLocation(0);
                        }
                    }
                    c++;
                    switch (inst->opcode) {
                        case OP_BC_JMP:
                        case OP_BC_BRANCH:
                        case OP_BC_CALL_API:
                        case OP_BC_CALL_DIRECT:
                        case OP_BC_ZEXT:
                        case OP_BC_SEXT:
                        case OP_BC_TRUNC:
                        case OP_BC_GEP1:
                        case OP_BC_GEPZ:
                        case OP_BC_GEPN:
                        case OP_BC_STORE:
                        case OP_BC_COPY:
                        case OP_BC_RET:
                        case OP_BC_PTRDIFF32:
                        case OP_BC_PTRTOINT64:
                            // these instructions represents operands differently
                            break;
                        default:
                            switch (operand_counts[inst->opcode]) {
                                case 1:
                                    Op0 = convertOperand(func, inst, inst->u.unaryop);
                                    break;
                                case 2:
                                    Op0 = convertOperand(func, inst, inst->u.binop[0]);
                                    Op1 = convertOperand(func, inst, inst->u.binop[1]);
                                    if (Op0->getType() != Op1->getType()) {
                                        cli_warnmsg("[%s] binop type mismatch %s %s", MODULE, Op0->getName().data(), Op1->getName().data());
                                    }
                                    break;
                                case 3:
                                    Op0 = convertOperand(func, inst, inst->u.three[0]);
                                    Op1 = convertOperand(func, inst, inst->u.three[1]);
                                    Op2 = convertOperand(func, inst, inst->u.three[2]);
                                    break;
                            }
                    }

                    switch (inst->opcode) {
                        case OP_BC_ADD:
                            Store(inst->dest, Builder.CreateAdd(Op0, Op1));
                            break;
                        case OP_BC_SUB:
                            Store(inst->dest, Builder.CreateSub(Op0, Op1));
                            break;
                        case OP_BC_MUL:
                            Store(inst->dest, Builder.CreateMul(Op0, Op1));
                            break;
                        case OP_BC_UDIV: {
                            Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
                            InsertVerify(Bad, Fail, CF->FHandler, F);
                            Store(inst->dest, Builder.CreateUDiv(Op0, Op1));
                            break;
                        }
                        case OP_BC_SDIV: {
                            // TODO: also verify Op0 == -1 && Op1 = INT_MIN
                            Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
                            InsertVerify(Bad, Fail, CF->FHandler, F);
                            Store(inst->dest, Builder.CreateSDiv(Op0, Op1));
                            break;
                        }
                        case OP_BC_UREM: {
                            Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
                            InsertVerify(Bad, Fail, CF->FHandler, F);
                            Store(inst->dest, Builder.CreateURem(Op0, Op1));
                            break;
                        }
                        case OP_BC_SREM: {
                            // TODO: also verify Op0 == -1 && Op1 = INT_MIN
                            Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
                            InsertVerify(Bad, Fail, CF->FHandler, F);
                            Store(inst->dest, Builder.CreateSRem(Op0, Op1));
                            break;
                        }
                        case OP_BC_SHL:
                            Store(inst->dest, Builder.CreateShl(Op0, Op1));
                            break;
                        case OP_BC_LSHR:
                            Store(inst->dest, Builder.CreateLShr(Op0, Op1));
                            break;
                        case OP_BC_ASHR:
                            Store(inst->dest, Builder.CreateAShr(Op0, Op1));
                            break;
                        case OP_BC_AND:
                            Store(inst->dest, Builder.CreateAnd(Op0, Op1));
                            break;
                        case OP_BC_OR:
                            Store(inst->dest, Builder.CreateOr(Op0, Op1));
                            break;
                        case OP_BC_XOR:
                            Store(inst->dest, Builder.CreateXor(Op0, Op1));
                            break;
                        case OP_BC_TRUNC: {
                            Value *Src = convertOperand(func, inst, inst->u.cast.source);
                            Type *Ty   = mapType(func->types[inst->dest]);
                            Store(inst->dest, Builder.CreateTrunc(Src, Ty));
                            break;
                        }
                        case OP_BC_ZEXT: {
                            Value *Src = convertOperand(func, inst, inst->u.cast.source);
                            Type *Ty   = mapType(func->types[inst->dest]);
                            Store(inst->dest, Builder.CreateZExt(Src, Ty));
                            break;
                        }
                        case OP_BC_SEXT: {
                            Value *Src = convertOperand(func, inst, inst->u.cast.source);
                            Type *Ty   = mapType(func->types[inst->dest]);
                            Store(inst->dest, Builder.CreateSExt(Src, Ty));
                            break;
                        }
                        case OP_BC_BRANCH: {
                            Value *Cond       = convertOperand(func, inst, inst->u.branch.condition);
                            BasicBlock *True  = BB[inst->u.branch.br_true];
                            BasicBlock *False = BB[inst->u.branch.br_false];
                            if (Cond->getType() != Type::getInt1Ty(Context)) {
                                cli_warnmsg("[%s]: type mismatch in condition", MODULE);
                                broken = true;
                                break;
                            }
                            Builder.CreateCondBr(Cond, True, False);
                            break;
                        }
                        case OP_BC_JMP: {
                            BasicBlock *Jmp = BB[inst->u.jump];
                            Builder.CreateBr(Jmp);
                            break;
                        }
                        case OP_BC_RET: {
                            Op0 = convertOperand(func, F->getReturnType(), inst->u.unaryop);
                            Builder.CreateRet(Op0);
                            break;
                        }
                        case OP_BC_RET_VOID:
                            Builder.CreateRetVoid();
                            break;
                        case OP_BC_ICMP_EQ:
                            Store(inst->dest, Builder.CreateICmpEQ(Op0, Op1));
                            break;
                        case OP_BC_ICMP_NE:
                            Store(inst->dest, Builder.CreateICmpNE(Op0, Op1));
                            break;
                        case OP_BC_ICMP_UGT:
                            Store(inst->dest, Builder.CreateICmpUGT(Op0, Op1));
                            break;
                        case OP_BC_ICMP_UGE:
                            Store(inst->dest, Builder.CreateICmpUGE(Op0, Op1));
                            break;
                        case OP_BC_ICMP_ULT:
                            Store(inst->dest, Builder.CreateICmpULT(Op0, Op1));
                            break;
                        case OP_BC_ICMP_ULE:
                            Store(inst->dest, Builder.CreateICmpULE(Op0, Op1));
                            break;
                        case OP_BC_ICMP_SGT:
                            Store(inst->dest, Builder.CreateICmpSGT(Op0, Op1));
                            break;
                        case OP_BC_ICMP_SGE:
                            Store(inst->dest, Builder.CreateICmpSGE(Op0, Op1));
                            break;
                        case OP_BC_ICMP_SLT:
                            Store(inst->dest, Builder.CreateICmpSLT(Op0, Op1));
                            break;
                        case OP_BC_ICMP_SLE:
                            Store(inst->dest, Builder.CreateICmpSLE(Op0, Op1));
                            break;
                        case OP_BC_SELECT:
                            Store(inst->dest, Builder.CreateSelect(Op0, Op1, Op2));
                            break;
                        case OP_BC_COPY: {
                            Value *Dest      = Values[inst->u.binop[1]];
                            PointerType *PTy = cast<PointerType>(Dest->getType());
                            Op0              = convertOperand(func, PTy->getElementType(), inst->u.binop[0]);
                            PTy              = PointerType::getUnqual(Op0->getType());
                            Dest             = Builder.CreateBitCast(Dest, PTy);
                            Builder.CreateStore(Op0, Dest);
                            break;
                        }
                        case OP_BC_CALL_DIRECT: {
                            Function *DestF = Functions[inst->u.ops.funcid];
                            SmallVector<Value *, 2> args;
                            args.push_back(&*F->arg_begin()); // pass hidden arg
                            for (unsigned a = 0; a < inst->u.ops.numOps; a++) {
                                operand_t op = inst->u.ops.ops[a];
                                args.push_back(convertOperand(func, DestF->getFunctionType()->getParamType(a + 1), op));
                            }
                            CallInst *CI = Builder.CreateCall(DestF, ArrayRef<Value *>(args.begin(), args.end()));
                            CI->setCallingConv(CallingConv::Fast);
                            CI->setDoesNotThrow();
                            if (CI->getType()->getTypeID() != Type::VoidTyID)
                                Store(inst->dest, CI);
                            break;
                        }
                        case OP_BC_CALL_API: {
                            assert(inst->u.ops.funcid < cli_apicall_maxapi && "APICall out of range");
                            std::vector<Value *> args;
                            Function *DestF = apiFuncs[inst->u.ops.funcid];
                            if (!strcmp(cli_apicalls[inst->u.ops.funcid].name, "engine_functionality_level")) {
                                Store(inst->dest,
                                      ConstantInt::get(Type::getInt32Ty(Context),
                                                       cl_retflevel()));
                            } else {
                                args.push_back(&*F->arg_begin()); // pass hidden arg
                                for (unsigned a = 0; a < inst->u.ops.numOps; a++) {
                                    operand_t op = inst->u.ops.ops[a];
                                    args.push_back(convertOperand(func, DestF->getFunctionType()->getParamType(a + 1), op));
                                }
                                CallInst *CI = Builder.CreateCall(DestF, ArrayRef<Value *>(args));
                                CI->setDoesNotThrow();
                                Store(inst->dest, CI);
                            }
                            break;
                        }
                        case OP_BC_GEP1: {
                            Type *SrcTy = mapType(inst->u.three[0]);
                            Value *V    = convertOperand(func, SrcTy, inst->u.three[1]);
                            Value *Op   = convertOperand(func, I32Ty, inst->u.three[2]);
                            Op          = GEPOperand(Op);
                            if (!createGEP(inst->dest, V, ArrayRef<Value *>(&Op, &Op + 1))) {
                                cli_warnmsg("[%s]: OP_BC_GEP1 createGEP failed\n", MODULE);
                                broken = true;
                            }
                            break;
                        }
                        case OP_BC_GEPZ: {
                            Value *Ops[2];
                            Ops[0]      = ConstantInt::get(Type::getInt32Ty(Context), 0);
                            Type *SrcTy = mapType(inst->u.three[0]);
                            Value *V    = convertOperand(func, SrcTy, inst->u.three[1]);
                            Ops[1]      = convertOperand(func, I32Ty, inst->u.three[2]);
                            Ops[1]      = GEPOperand(Ops[1]);
                            if (!createGEP(inst->dest, V, ArrayRef<Value *>(Ops, Ops + 2))) {
                                cli_warnmsg("[%s]: OP_BC_GEPZ createGEP failed\n", MODULE);
                                broken = true;
                            }
                            break;
                        }
                        case OP_BC_GEPN: {
                            std::vector<Value *> Idxs;
                            assert(inst->u.ops.numOps > 2);
                            Type *SrcTy = mapType(inst->u.ops.ops[0]);
                            Value *V    = convertOperand(func, SrcTy, inst->u.ops.ops[1]);
                            for (unsigned a = 2; a < inst->u.ops.numOps; a++) {
                                Value *Op = convertOperand(func, I32Ty, inst->u.ops.ops[a]);
                                Op        = GEPOperand(Op);
                                Idxs.push_back(Op);
                            }
                            if (!createGEP(inst->dest, V, ArrayRef<Value *>(Idxs))) {
                                cli_warnmsg("[%s]: OP_BC_GEPN createGEP failed\n", MODULE);
                                broken = true;
                            }
                            break;
                        }
                        case OP_BC_STORE: {
                            Value *Dest = convertOperand(func, inst, inst->u.binop[1]);
                            Value *V    = convertOperand(func, inst, inst->u.binop[0]);
                            Type *VPTy  = PointerType::getUnqual(V->getType());
                            if (VPTy != Dest->getType())
                                Dest = Builder.CreateBitCast(Dest, VPTy);
                            Builder.CreateStore(V, Dest);
                            break;
                        }
                        case OP_BC_LOAD: {
                            Op0 = Builder.CreateBitCast(Op0,
                                                        Values[inst->dest]->getType());
                            Op0 = Builder.CreateLoad(Op0);
                            Store(inst->dest, Op0);
                            break;
                        }
                        case OP_BC_MEMSET: {
                            Value *Dst  = convertOperand(func, inst, inst->u.three[0]);
                            Dst         = Builder.CreatePointerCast(Dst, PointerType::getUnqual(Type::getInt8Ty(Context)));
                            Value *Val  = convertOperand(func, Type::getInt8Ty(Context), inst->u.three[1]);
                            Value *Len  = convertOperand(func, Type::getInt32Ty(Context), inst->u.three[2]);
                            CallInst *c = Builder.CreateCall(CF->FMemset, {Dst, Val, Len,
                                                                           ConstantInt::get(Type::getInt32Ty(Context), 1),
                                                                           ConstantInt::get(Type::getInt1Ty(Context), 0)});
                            c->setTailCall(true);
                            c->setDoesNotThrow();
                            UpgradeCall(c, CF->FMemset);
                            break;
                        }
                        case OP_BC_MEMCPY: {
                            Value *Dst  = convertOperand(func, inst, inst->u.three[0]);
                            Dst         = Builder.CreatePointerCast(Dst, PointerType::getUnqual(Type::getInt8Ty(Context)));
                            Value *Src  = convertOperand(func, inst, inst->u.three[1]);
                            Src         = Builder.CreatePointerCast(Src, PointerType::getUnqual(Type::getInt8Ty(Context)));
                            Value *Len  = convertOperand(func, Type::getInt32Ty(Context), inst->u.three[2]);
                            CallInst *c = Builder.CreateCall(CF->FMemcpy, {Dst, Src, Len,
                                                                           ConstantInt::get(Type::getInt32Ty(Context), 1),
                                                                           ConstantInt::get(Type::getInt1Ty(Context), 0)});
                            c->setTailCall(true);
                            c->setDoesNotThrow();
                            UpgradeCall(c, CF->FMemcpy);
                            break;
                        }
                        case OP_BC_MEMMOVE: {
                            Value *Dst  = convertOperand(func, inst, inst->u.three[0]);
                            Dst         = Builder.CreatePointerCast(Dst, PointerType::getUnqual(Type::getInt8Ty(Context)));
                            Value *Src  = convertOperand(func, inst, inst->u.three[1]);
                            Src         = Builder.CreatePointerCast(Src, PointerType::getUnqual(Type::getInt8Ty(Context)));
                            Value *Len  = convertOperand(func, Type::getInt32Ty(Context), inst->u.three[2]);
                            CallInst *c = Builder.CreateCall(CF->FMemmove, {Dst, Src, Len,
                                                                            ConstantInt::get(Type::getInt32Ty(Context), 1),
                                                                            ConstantInt::get(Type::getInt1Ty(Context), 0)});
                            c->setTailCall(true);
                            c->setDoesNotThrow();
                            UpgradeCall(c, CF->FMemmove);
                            break;
                        }
                        case OP_BC_MEMCMP: {
                            Value *Dst  = convertOperand(func, inst, inst->u.three[0]);
                            Dst         = Builder.CreatePointerCast(Dst, PointerType::getUnqual(Type::getInt8Ty(Context)));
                            Value *Src  = convertOperand(func, inst, inst->u.three[1]);
                            Src         = Builder.CreatePointerCast(Src, PointerType::getUnqual(Type::getInt8Ty(Context)));
                            Value *Len  = convertOperand(func, EE->getDataLayout().getIntPtrType(Context), inst->u.three[2]);
                            CallInst *c = Builder.CreateCall(CF->FRealmemcmp, {Dst, Src, Len});
                            c->setTailCall(true);
                            c->setDoesNotThrow();
                            Store(inst->dest, c);
                            break;
                        }
                        case OP_BC_ISBIGENDIAN:
                            Store(inst->dest, WORDS_BIGENDIAN ? ConstantInt::getTrue(Context) : ConstantInt::getFalse(Context));
                            break;
                        case OP_BC_ABORT:
                            if (!unreachable) {
                                CallInst *CI = Builder.CreateCall(CF->FHandler);
                                CI->setDoesNotReturn();
                                CI->setDoesNotThrow();
                                Builder.CreateUnreachable();
                                unreachable = true;
                            }
                            break;
                        case OP_BC_BSWAP16: {
                            CallInst *C = Builder.CreateCall(CF->FBSwap16, convertOperand(func, inst, inst->u.unaryop));
                            C->setTailCall(true);
                            C->setDoesNotThrow();
                            Store(inst->dest, C);
                            break;
                        }
                        case OP_BC_BSWAP32: {
                            CallInst *C = Builder.CreateCall(CF->FBSwap32, convertOperand(func, inst, inst->u.unaryop));
                            C->setTailCall(true);
                            C->setDoesNotThrow();
                            Store(inst->dest, C);
                            break;
                        }
                        case OP_BC_BSWAP64: {
                            CallInst *C = Builder.CreateCall(CF->FBSwap64, convertOperand(func, inst, inst->u.unaryop));
                            C->setTailCall(true);
                            C->setDoesNotThrow();
                            Store(inst->dest, C);
                            break;
                        }
                        case OP_BC_PTRDIFF32: {
                            Value *P1 = convertOperand(func, inst, inst->u.binop[0]);
                            Value *P2 = convertOperand(func, inst, inst->u.binop[1]);
                            P1        = Builder.CreatePtrToInt(P1, Type::getInt64Ty(Context));
                            P2        = Builder.CreatePtrToInt(P2, Type::getInt64Ty(Context));
                            Value *R  = Builder.CreateSub(P1, P2);
                            R         = Builder.CreateTrunc(R, Type::getInt32Ty(Context));
                            Store(inst->dest, R);
                            break;
                        }
                        case OP_BC_PTRTOINT64: {
                            Value *P1 = convertOperand(func, inst, inst->u.unaryop);
                            P1        = Builder.CreatePtrToInt(P1, Type::getInt64Ty(Context));
                            Store(inst->dest, P1);
                            break;
                        }
                        default:
                            cli_warnmsg("[%s]: JIT doesn't implement opcode %d yet!\n",
                                        MODULE, inst->opcode);
                            broken = true;

                            assert(0 && "IMPLEMENT THIS OPCODE");

                            break;
                    }
                }
            }

            // If successful so far, run verifyFunction
            if (!broken) {
                if (verifyFunction(*F, &errs())) {
                    // verification failed
                    broken = true;
                    cli_warnmsg("[%s]: Verification failed\n", MODULE);
                    if (cli_debug_flag) {
                        std::string str;
                        raw_string_ostream ostr(str);
                        F->print(ostr);
                        cli_dbgmsg_no_inline("[Bytecode JIT]: %s\n", ostr.str().c_str());
                    }
                }
            }

            delete[] Values;

            // Cleanup after failure and return 0
            if (broken) {
                for (unsigned z = 0; z < func->numBB; z++) {
                    delete BB[z];
                }
                delete[] BB;
                apiMap.irgenTimer.stopTimer();
                delete TypeMap;
                for (unsigned z = 0; z < bc->num_func; z++) {
                    delete Functions[z];
                }
                delete[] Functions;
                return 0;
            }

            delete[] BB;
            apiMap.irgenTimer.stopTimer();
            apiMap.pmTimer.startTimer();
            if (bc->trusted) {
                PM.doInitialization();
                PM.run(*F);
                PM.doFinalization();
            } else {
                PMUnsigned.doInitialization();
                PMUnsigned.run(*F);
                PMUnsigned.doFinalization();
            }
            apiMap.pmTimer.stopTimer();
            apiMap.irgenTimer.startTimer();
        }

        for (unsigned j = 0; j < bc->num_func; j++) {
            Function *F = Functions[j];
            AddStackProtect(F);
        }
        delete TypeMap;
        std::vector<Type *> args;
        args.clear();
        args.push_back(HiddenCtx);
        FunctionType *Callable = FunctionType::get(Type::getInt32Ty(Context),
                                                   args, false);

        // If prototype matches, add to callable functions
        if (Functions[0]->getFunctionType() != Callable) {
            cli_warnmsg("[%s]: Wrong prototype for function 0 in bytecode %d\n", MODULE, bc->id);
            apiMap.irgenTimer.stopTimer();
            for (unsigned z = 0; z < bc->num_func; z++) {
                delete Functions[z];
            }
            delete[] Functions;
            return 0;
        }
        // All functions have the Fast calling convention, however
        // entrypoint can only be C, emit wrapper
        Function *F = Function::Create(Functions[0]->getFunctionType(),
                                       Function::ExternalLinkage,
                                       Functions[0]->getName().str() + "_wrap", M);
        F->setDoesNotThrow();
        BasicBlock *BB = BasicBlock::Create(Context, "", F);
        std::vector<Value *> Args;
        for (Function::arg_iterator J  = F->arg_begin(),
                                    JE = F->arg_end();
             J != JE; ++J) {
            Argument *pArg = llvm::cast<Argument>(J);
            Args.push_back(pArg);
        }

        CallInst *CI = CallInst::Create(Functions[0], ArrayRef<Value *>(Args), "", BB);
        CI->setCallingConv(CallingConv::Fast);
        ReturnInst::Create(Context, CI, BB);

        delete[] Functions;
        if (verifyFunction(*F, &errs())) {
            return 0;
        }

        apiMap.irgenTimer.stopTimer();
        return F;
    }
};

static sys::Mutex llvm_api_lock;

// This class automatically acquires the lock when instantiated,
// and releases the lock when leaving scope.
class LLVMApiScopedLock
{
  public:
    // when multithreaded mode is false (no atomics available),
    // we need to wrap all LLVM API calls with a giant mutex lock, but
    // only then.
    LLVMApiScopedLock()
    {
        // It is safer to just run all codegen under the mutex,
        // it is not like we are going to codegen from multiple threads
        // at a time anyway.
        llvm_api_lock.lock();
    }
    ~LLVMApiScopedLock()
    {
        llvm_api_lock.unlock();
    }
};

static void addNoCapture(Function *pFunc)
{
    for (auto i = pFunc->arg_begin(), e = pFunc->arg_end(); i != e; i++) {
        Argument *pArg = llvm::cast<Argument>(i);
        if (pArg->getType()->isPointerTy() and (not pArg->hasNoCaptureAttr())) {
            pArg->addAttr(Attribute::NoCapture);
        }
    }
}

static void addFunctionProtos(struct CommonFunctions *CF, ExecutionEngine *EE, Module *M)
{
    LLVMContext &Context = M->getContext();
    FunctionType *FTy    = FunctionType::get(Type::getVoidTy(Context), false);
    CF->FHandler         = Function::Create(FTy, Function::ExternalLinkage, "clamjit.fail", M);
    CF->FHandler->setDoesNotReturn();
    CF->FHandler->setDoesNotThrow();
    CF->FHandler->addFnAttr(Attribute::NoInline);
    sys::DynamicLibrary::AddSymbol(CF->FHandler->getName(), (void *)(intptr_t)jit_exception_handler);
    EE->InstallLazyFunctionCreator(noUnknownFunctions);
    EE->getPointerToFunction(CF->FHandler);

    std::vector<Type *> args;
    args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
    args.push_back(Type::getInt8Ty(Context));
    args.push_back(Type::getInt32Ty(Context));
    args.push_back(Type::getInt32Ty(Context));
    args.push_back(Type::getInt1Ty(Context));
    FunctionType *FuncTy_3 = FunctionType::get(Type::getVoidTy(Context), args, false);
    CF->FMemset            = Function::Create(FuncTy_3, GlobalValue::ExternalLinkage, "llvm.memset.p0i8.i32", M);
    CF->FMemset->setDoesNotThrow();
    addNoCapture(CF->FMemset);

    args.clear();
    args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
    args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
    args.push_back(Type::getInt32Ty(Context));
    args.push_back(Type::getInt32Ty(Context));
    args.push_back(Type::getInt1Ty(Context));
    FunctionType *FuncTy_4 = FunctionType::get(Type::getVoidTy(Context), args, false);
    CF->FMemmove           = Function::Create(FuncTy_4, GlobalValue::ExternalLinkage, "llvm.memmove.p0i8.i32", M);
    CF->FMemmove->setDoesNotThrow();
    addNoCapture(CF->FMemmove);

    CF->FMemcpy = Function::Create(FuncTy_4, GlobalValue::ExternalLinkage, "llvm.memcpy.p0i8.p0i8.i32", M);
    CF->FMemcpy->setDoesNotThrow();
    addNoCapture(CF->FMemcpy);

    args.clear();
    args.push_back(Type::getInt16Ty(Context));
    FunctionType *FuncTy_5 = FunctionType::get(Type::getInt16Ty(Context), args, false);
    CF->FBSwap16           = Function::Create(FuncTy_5, GlobalValue::ExternalLinkage, "llvm.bswap.i16", M);
    CF->FBSwap16->setDoesNotThrow();

    args.clear();
    args.push_back(Type::getInt32Ty(Context));
    FunctionType *FuncTy_6 = FunctionType::get(Type::getInt32Ty(Context), args, false);
    CF->FBSwap32           = Function::Create(FuncTy_6, GlobalValue::ExternalLinkage, "llvm.bswap.i32", M);
    CF->FBSwap32->setDoesNotThrow();

    args.clear();
    args.push_back(Type::getInt64Ty(Context));
    FunctionType *FuncTy_7 = FunctionType::get(Type::getInt64Ty(Context), args, false);
    CF->FBSwap64           = Function::Create(FuncTy_7, GlobalValue::ExternalLinkage, "llvm.bswap.i64", M);
    CF->FBSwap64->setDoesNotThrow();

    FunctionType *DummyTy = FunctionType::get(Type::getVoidTy(Context), false);
    CF->FRealmemset       = Function::Create(DummyTy, GlobalValue::ExternalLinkage, "memset", M);
    sys::DynamicLibrary::AddSymbol(CF->FRealmemset->getName(), (void *)(intptr_t)memset);
    EE->getPointerToFunction(CF->FRealmemset);
    CF->FRealMemmove = Function::Create(DummyTy, GlobalValue::ExternalLinkage,
                                        "memmove", M);
    sys::DynamicLibrary::AddSymbol(CF->FRealMemmove->getName(), (void *)(intptr_t)memmove);
    EE->getPointerToFunction(CF->FRealMemmove);
    CF->FRealmemcpy = Function::Create(DummyTy, GlobalValue::ExternalLinkage,
                                       "memcpy", M);
    sys::DynamicLibrary::AddSymbol(CF->FRealmemcpy->getName(), (void *)(intptr_t)memcpy);
    EE->getPointerToFunction(CF->FRealmemcpy);

    args.clear();
    args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
    args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
    args.push_back(EE->getDataLayout().getIntPtrType(Context));
    FuncTy_5        = FunctionType::get(Type::getInt32Ty(Context), args, false);
    CF->FRealmemcmp = Function::Create(FuncTy_5, GlobalValue::ExternalLinkage, "memcmp", M);
    sys::DynamicLibrary::AddSymbol(CF->FRealmemcmp->getName(), (void *)(intptr_t)memcmp);
    EE->getPointerToFunction(CF->FRealmemcmp);
}

} // namespace
INITIALIZE_PASS_BEGIN(RuntimeLimits, "rl", "Runtime Limits", false, false)
INITIALIZE_PASS_DEPENDENCY(LoopInfoWrapperPass)
INITIALIZE_PASS_DEPENDENCY(ScalarEvolutionWrapperPass)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_END(RuntimeLimits, "rl", "Runtime Limits", false, false)

static pthread_mutex_t watchdog_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t watchdog_cond   = PTHREAD_COND_INITIALIZER;
static pthread_cond_t watchdog_cond2  = PTHREAD_COND_INITIALIZER;
static int watchdog_running           = 0;

struct watchdog_item {
    volatile uint8_t *timeout;
    struct timespec abstimeout;
    struct watchdog_item *next;
    int in_use;
};

static struct watchdog_item *watchdog_head = NULL;
static struct watchdog_item *watchdog_tail = NULL;

extern "C" const char *cli_strerror(int errnum, char *buf, size_t len);
#define WATCHDOG_IDLE 10
static void *bytecode_watchdog(void *arg)
{
    struct timeval tv;
    struct timespec out;
    int ret;
    char err[128];
    pthread_mutex_lock(&watchdog_mutex);
    if (cli_debug_flag)
        cli_dbgmsg_no_inline("bytecode watchdog is running\n");
    do {
        struct watchdog_item *item;
        gettimeofday(&tv, NULL);
        out.tv_sec  = tv.tv_sec + WATCHDOG_IDLE;
        out.tv_nsec = tv.tv_usec * 1000;
        /* wait for some work, up to WATCHDOG_IDLE time */
        while (watchdog_head == NULL) {
            ret = pthread_cond_timedwait(&watchdog_cond, &watchdog_mutex,
                                         &out);
            if (ret == ETIMEDOUT)
                break;
            if (ret) {
                cli_warnmsg("[%s] bytecode_watchdog: cond_timedwait(1) failed: %s\n",
                            MODULE, cli_strerror(ret, err, sizeof(err)));
                break;
            }
        }
        if (watchdog_head == NULL)
            break;
        /* wait till timeout is reached on this item */
        item = watchdog_head;
        while (item == watchdog_head) {
            item->in_use = 1;
            ret          = pthread_cond_timedwait(&watchdog_cond, &watchdog_mutex, &item->abstimeout);
            if (ret == ETIMEDOUT)
                break;
            if (ret) {
                cli_warnmsg("[%s] bytecode_watchdog: cond_timedwait(2) failed: %s\n",
                            MODULE, cli_strerror(ret, err, sizeof(err)));
                break;
            }
        }
        item->in_use = 0;
        pthread_cond_signal(&watchdog_cond2);
        if (item != watchdog_head)
            continue; /* got removed meanwhile */
        /* timeout reached, signal it to bytecode */
        *item->timeout = 1;
        cli_warnmsg("[%s]: Bytecode run timed out, timeout flag set\n", MODULE);
        watchdog_head = item->next;
        if (!watchdog_head)
            watchdog_tail = NULL;
    } while (1);
    watchdog_running = 0;
    if (cli_debug_flag)
        cli_dbgmsg_no_inline("bytecode watchdog quiting\n");
    pthread_mutex_unlock(&watchdog_mutex);
    return NULL;
}

static void watchdog_disarm(struct watchdog_item *item)
{
    struct watchdog_item *q, *p = NULL;
    if (!item)
        return;
    pthread_mutex_lock(&watchdog_mutex);
    for (q = watchdog_head; q && q != item; p = q, q = q->next) {
    }
    if (q == item) {
        if (p)
            p->next = q->next;
        if (q == watchdog_head)
            watchdog_head = q->next;
        if (q == watchdog_tail)
            watchdog_tail = p;
    }
    /* don't remove the item from the list until the watchdog is sleeping on
     * item, or it'll wake up on uninit data */
    while (item->in_use) {
        pthread_cond_signal(&watchdog_cond);
        pthread_cond_wait(&watchdog_cond2, &watchdog_mutex);
    }
    pthread_mutex_unlock(&watchdog_mutex);
}

static int watchdog_arm(struct watchdog_item *item, int ms, volatile uint8_t *timeout)
{
    int rc = 0;
    struct timeval tv0;

    *timeout      = 0;
    item->timeout = timeout;
    item->next    = NULL;
    item->in_use  = 0;

    gettimeofday(&tv0, NULL);
    tv0.tv_usec += ms * 1000;
    item->abstimeout.tv_sec  = tv0.tv_sec + tv0.tv_usec / 1000000;
    item->abstimeout.tv_nsec = (tv0.tv_usec % 1000000) * 1000;

    pthread_mutex_lock(&watchdog_mutex);
    if (!watchdog_running) {
        pthread_t thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if ((rc = pthread_create(&thread, &attr, bytecode_watchdog, NULL))) {
            char buf[256];
            cli_errmsg("(watchdog) pthread_create failed: %s\n", cli_strerror(rc, buf, sizeof(buf)));
        }
        if (!rc)
            watchdog_running = 1;
        pthread_attr_destroy(&attr);
    }
    if (!rc) {
        if (watchdog_tail)
            watchdog_tail->next = item;
        watchdog_tail = item;
        if (!watchdog_head)
            watchdog_head = item;
    }
    pthread_cond_signal(&watchdog_cond);
    pthread_mutex_unlock(&watchdog_mutex);
    return rc;
}

static cl_error_t bytecode_execute(intptr_t code, struct cli_bc_ctx *ctx)
{
    ScopedExceptionHandler handler;
    // execute;
    HANDLER_TRY(handler)
    {
        // setup exception handler to longjmp back here
        uint32_t result          = ((uint32_t(*)(struct cli_bc_ctx *))(intptr_t)code)(ctx);
        *(uint32_t *)ctx->values = result;
        return CL_SUCCESS;
    }
    HANDLER_END(handler);
    cli_warnmsg("[%s]: JITed code intercepted runtime error!\n", MODULE);
    return CL_EBYTECODE;
}

cl_error_t cli_vm_execute_jit(const struct cli_all_bc *bcs, struct cli_bc_ctx *ctx,
                              const struct cli_bc_func *func)
{
    cl_error_t ret;
    struct timeval tv0, tv1;
    struct watchdog_item witem;
    // no locks needed here, since LLVM automatically acquires a JIT lock
    // if needed.
    void *code = bcs->engine->compiledFunctions[func];
    if (!code) {
        cli_warnmsg("[%s]: Unable to find compiled function\n", MODULE);
        if (func->numArgs)
            cli_warnmsg("[%s] Function has %d arguments, it must have 0 to be called as entrypoint\n",
                        MODULE, func->numArgs);
        return CL_EBYTECODE;
    }
    if (cli_debug_flag)
        gettimeofday(&tv0, NULL);

    if (ctx->bytecode_timeout) {
        /* only spawn if timeout is set.
         * we don't set timeout for selfcheck (see bb #2235) */
        if (watchdog_arm(&witem, ctx->bytecode_timeout, &ctx->timeout)) return CL_EBYTECODE;
    }

    ret = bytecode_execute((intptr_t)code, ctx);

    if (ctx->bytecode_timeout) {
        watchdog_disarm(&witem);
    }

    if (cli_debug_flag) {
        long diff;
        gettimeofday(&tv1, NULL);
        tv1.tv_sec -= tv0.tv_sec;
        tv1.tv_usec -= tv0.tv_usec;
        diff = tv1.tv_sec * 1000000 + tv1.tv_usec;
        cli_dbgmsg_no_inline("bytecode finished in %ld us\n", diff);
    }
    return ctx->timeout ? CL_ETIMEOUT : ret;
} // namespace

static unsigned char name_salt[16] = {16, 38, 97, 12, 8, 4, 72, 196, 217, 144, 33, 124, 18, 11, 17, 253};
static void setGuard(unsigned char *guardbuf)
{
    char salt[48];
    memcpy(salt, name_salt, 16);
    for (unsigned i = 16; i < 48; i++)
        salt[i] = cli_rndnum(255);

    cl_hash_data((char *)"md5", salt, 48, guardbuf, NULL);
}
static void addFPasses(legacy::FunctionPassManager &FPM, bool trusted, Module *M)
{
    // Set up the optimizer pipeline.  Start with registering info about how
    // the target lays out data structures.

    // Promote allocas to registers.
    FPM.add(createPromoteMemoryToRegisterPass());
    FPM.add(new BrSimplifier());
    FPM.add(createDeadCodeEliminationPass());
}

cl_error_t cli_bytecode_prepare_jit(struct cli_all_bc *bcs)
{
    if (!bcs->engine)
        return CL_EBYTECODE;
    ScopedExceptionHandler handler;
    LLVMApiScopedLock scopedLock;
    // setup exception handler to longjmp back here
    HANDLER_TRY(handler)
    {
        // LLVM itself never throws exceptions, but operator new may throw bad_alloc
        try {
            Module *M = new Module("ClamAV jit module", bcs->engine->Context);
            {
                // Create the JIT.
                std::string ErrorMsg;
                EngineBuilder builder(std::move(std::unique_ptr<Module>(M)));

                TargetOptions Options;
                builder.setTargetOptions(Options);

                builder.setErrorStr(&ErrorMsg);
                builder.setEngineKind(EngineKind::JIT);
                builder.setOptLevel(CodeGenOpt::Default);
                ExecutionEngine *EE = bcs->engine->EE = builder.create();
                if (!EE) {
                    if (!ErrorMsg.empty())
                        cli_errmsg("[Bytecode JIT]: error creating execution engine: %s\n",
                                   ErrorMsg.c_str());
                    else
                        cli_errmsg("[Bytecode JIT]: JIT not registered?\n");
                    return CL_EBYTECODE;
                }
                bcs->engine->Listener = new NotifyListener();
                EE->RegisterJITEventListener(bcs->engine->Listener);
                //	EE->RegisterJITEventListener(createOProfileJITEventListener());
                // Due to LLVM PR4816 only X86 supports non-lazy compilation, disable
                // for now.
                EE->DisableLazyCompilation();
                // This must be enabled for AddSymbol to work.
                EE->DisableSymbolSearching(false);

                struct CommonFunctions CF;
                addFunctionProtos(&CF, EE, M);

                legacy::FunctionPassManager OurFPM(M), OurFPMUnsigned(M);
                M->setDataLayout(EE->getDataLayout().getStringRepresentation());
                M->setTargetTriple(sys::getDefaultTargetTriple());
                addFPasses(OurFPM, true, M);
                addFPasses(OurFPMUnsigned, false, M);

                // TODO: create a wrapper that calls pthread_getspecific
                unsigned maxh   = cli_globals[0].offset + sizeof(struct cli_bc_hooks);
                Type *HiddenCtx = PointerType::getUnqual(ArrayType::get(Type::getInt8Ty(bcs->engine->Context), maxh));

                LLVMTypeMapper apiMap(bcs->engine->Context, cli_apicall_types, cli_apicall_maxtypes, HiddenCtx);
                Function **apiFuncs = new Function *[cli_apicall_maxapi];
                for (unsigned i = 0; i < cli_apicall_maxapi; i++) {
                    const struct cli_apicall *api = &cli_apicalls[i];
                    FunctionType *FTy             = cast<FunctionType>(apiMap.get(69 + api->type, NULL, NULL));
                    Function *F                   = Function::Create(FTy, Function::ExternalLinkage, api->name, M);
                    void *dest;
                    switch (api->kind) {
                        case 0:
                            dest = (void *)(intptr_t)cli_apicalls0[api->idx];
                            break;
                        case 1:
                            dest = (void *)(intptr_t)cli_apicalls1[api->idx];
                            break;
                        case 2:
                            dest = (void *)(intptr_t)cli_apicalls2[api->idx];
                            break;
                        case 3:
                            dest = (void *)(intptr_t)cli_apicalls3[api->idx];
                            break;
                        case 4:
                            dest = (void *)(intptr_t)cli_apicalls4[api->idx];
                            break;
                        case 5:
                            dest = (void *)(intptr_t)cli_apicalls5[api->idx];
                            break;
                        case 6:
                            dest = (void *)(intptr_t)cli_apicalls6[api->idx];
                            break;
                        case 7:
                            dest = (void *)(intptr_t)cli_apicalls7[api->idx];
                            break;
                        case 8:
                            dest = (void *)(intptr_t)cli_apicalls8[api->idx];
                            break;
                        case 9:
                            dest = (void *)(intptr_t)cli_apicalls9[api->idx];
                            break;
                        default:
                            llvm_unreachable("invalid api type");
                    }
                    if (!dest) {
                        std::string reason((Twine("No mapping for builtin api ") + api->name).str());
                        llvm_error_handler(0, reason);
                    }
                    // addGlobalMapping doesn't work with MCJIT, so use symbol searching instead.
                    sys::DynamicLibrary::AddSymbol(F->getName(), dest);
                    EE->getPointerToFunction(F);
                    apiFuncs[i] = F;
                }

                // stack protector
                FunctionType *FTy     = FunctionType::get(Type::getVoidTy(M->getContext()), false);
                GlobalVariable *Guard = new GlobalVariable(*M, PointerType::getUnqual(Type::getInt8Ty(M->getContext())),
                                                           true, GlobalValue::ExternalLinkage, 0, "__stack_chk_guard");
                unsigned plus         = 0;
                if (2 * sizeof(void *) <= 16 && cli_rndnum(2) == 2) {
                    plus = sizeof(void *);
                }
                sys::DynamicLibrary::AddSymbol(Guard->getName(), (void *)(&bcs->engine->guard.b[plus]));
                setGuard(bcs->engine->guard.b);
                bcs->engine->guard.b[plus + sizeof(void *) - 1] = 0x00;
                Function *SFail                                 = Function::Create(FTy, Function::ExternalLinkage, "__stack_chk_fail", M);
                sys::DynamicLibrary::AddSymbol(SFail->getName(), (void *)(intptr_t)jit_ssp_handler);
                EE->getPointerToFunction(SFail);

                llvm::Function **Functions = new Function *[bcs->count];
                for (unsigned i = 0; i < bcs->count; i++) {
                    const struct cli_bc *bc = &bcs->all_bcs[i];
                    if (bc->state == bc_skip || bc->state == bc_interp) {
                        Functions[i] = 0;
                        continue;
                    }
                    LLVMCodegen Codegen(bc, M, &CF, bcs->engine->compiledFunctions, EE,
                                        OurFPM, OurFPMUnsigned, apiFuncs, apiMap);
                    Function *F = Codegen.generate();
                    if (!F) {
                        cli_errmsg("[Bytecode JIT]: JIT codegen failed\n");
                        delete[] apiFuncs;
                        for (unsigned z = 0; z < i; z++) {
                            delete Functions[z];
                        }
                        delete[] Functions;
                        return CL_EBYTECODE;
                    }
                    Functions[i] = F;
                }
                delete[] apiFuncs;

                legacy::PassManager PM;

                // With LLVM 3.6 (MCJIT) this Pass is required to work around
                // a crash in LLVM caused by the SCCP Pass:
                // Pass 'Sparse Conditional Constant Propagation' is not initialized.
                // Verify if there is a pass dependency cycle.
                // Required Passes:
                //
                // Program received signal SIGSEGV, Segmentation fault.
                PM.add(createGVNPass());
                PM.add(createSCCPPass());
                PM.add(createCFGSimplificationPass());
                PM.add(createGlobalOptimizerPass());
                PM.add(createConstantMergePass());

                RuntimeLimits *RL = new RuntimeLimits();
                PM.add(RL);
                TimerWrapper pmTimer2("Transform passes");
                pmTimer2.startTimer();
                PM.run(*M);
                pmTimer2.stopTimer();

                EE->finalizeObject();
                PrettyStackTraceString CrashInfo2("Native machine codegen");
                TimerWrapper codegenTimer("Native codegen");
                codegenTimer.startTimer();
                // compile all functions now, not lazily!
                for (Module::iterator I = M->begin(), E = M->end(); I != E; ++I) {
                    Function *Fn = &*I;
                    if (!Fn->isDeclaration()) {
                        EE->getPointerToFunction(Fn);
                    }
                }
                codegenTimer.stopTimer();

                for (unsigned i = 0; i < bcs->count; i++) {
                    const struct cli_bc_func *func = &bcs->all_bcs[i].funcs[0];
                    if (!Functions[i])
                        continue; // not JITed
                    bcs->engine->compiledFunctions[func] = EE->getPointerToFunction(Functions[i]);
                    bcs->all_bcs[i].state                = bc_jit;
                }
                delete[] Functions;
            }
            return CL_SUCCESS;
        } catch (std::bad_alloc &badalloc) {
            cli_errmsg("[Bytecode JIT]: bad_alloc: %s\n",
                       badalloc.what());
            return CL_EMEM;
        } catch (...) {
            cli_errmsg("[Bytecode JIT]: Unexpected unknown exception occurred\n");
            return CL_EBYTECODE;
        }
        return CL_SUCCESS;
    }
    HANDLER_END(handler);
    cli_errmsg("[Bytecode JIT] *** FATAL error encountered during bytecode generation\n");
    return CL_EBYTECODE;
}

cl_error_t bytecode_init(void)
{
    if (!LLVMIsMultithreaded()) {
        cli_warnmsg("[%s] bytecode_init: LLVM is compiled without multithreading support\n", MODULE);
    }

    // LLVM safety assertion prevention fix
    // TODO: do we want to do a full shutdown?
    remove_fatal_error_handler();
    llvm_install_error_handler(llvm_error_handler);
#ifdef CL_DEBUG
    sys::PrintStackTraceOnErrorSignal();
    llvm::EnablePrettyStackTrace();
#endif
    atexit(do_shutdown);

    // If we have a native target, initialize it to ensure it is linked in and
    // usable by the JIT.
#ifndef AC_APPLE_UNIVERSAL_BUILD
    InitializeNativeTarget();
    InitializeNativeTargetAsmPrinter();
    InitializeNativeTargetAsmParser();
#else
    InitializeAllTargets();
#endif

    if (!LLVMIsMultithreaded()) {
        const char *const warnmsg = "ClamAV JIT built w/o atomic builtins\n"
                                    "On x86 for best performance ClamAV "
                                    "should be built for i686, not i386!\n";
        cli_warnmsg("[%s] %s", MODULE, warnmsg);
    }
    return CL_SUCCESS;
}

// Called once when loading a new set of BC files
cl_error_t cli_bytecode_init_jit(struct cli_all_bc *bcs, unsigned dconfmask)
{
    LLVMApiScopedLock scopedLock;
    bcs->engine = new (std::nothrow) cli_bcengine;
    if (!bcs->engine)
        return CL_EMEM;
    bcs->engine->EE       = 0;
    bcs->engine->Listener = 0;
    return CL_SUCCESS;
}

cl_error_t cli_bytecode_done_jit(struct cli_all_bc *bcs, int partial)
{
    LLVMApiScopedLock scopedLock;
    if (bcs->engine) {
        if (bcs->engine->EE) {
            if (bcs->engine->Listener)
                bcs->engine->EE->UnregisterJITEventListener(bcs->engine->Listener);
            delete bcs->engine->EE;
            bcs->engine->EE = 0;
        }
        delete bcs->engine->Listener;
        bcs->engine->Listener = 0;
        if (!partial) {
            delete bcs->engine;
            bcs->engine = 0;
        }
    }
    return CL_SUCCESS;
}

void cli_bytecode_debug(int argc, char **argv)
{
    cl::ParseCommandLineOptions(argc, argv);
}

typedef struct lines {
    MemoryBuffer *buffer;
    std::vector<const char *> linev;
} linesTy;

static struct lineprinter {
    StringMap<linesTy *> files;
} LinePrinter;

void cli_bytecode_debug_printsrc(const struct cli_bc_ctx *ctx)
{
    if (!ctx->file || !ctx->directory || !ctx->line) {
        errs() << (ctx->directory ? "d" : "null") << ":" << (ctx->file ? "f" : "null") << ":" << ctx->line << "\n";
        return;
    }
    // acquire a mutex here
#if LLVM_VERSION < 100
    sys::Mutex mtx(false);
#else
    sys::Mutex mtx;
#endif
    sys::SmartScopedLock<false> lock(mtx);

    std::string path                 = std::string(ctx->directory) + "/" + std::string(ctx->file);
    StringMap<linesTy *>::iterator I = LinePrinter.files.find(path);
    linesTy *lines;
    if (I == LinePrinter.files.end()) {
        lines = new linesTy;
        std::string ErrorMessage;
        ErrorOr<std::unique_ptr<MemoryBuffer>> FileOrErr = MemoryBuffer::getFile(path);
        if (!FileOrErr) {
            lines->buffer = 0;
        } else {
            lines->buffer = FileOrErr.get().release();
        }
        if (!lines->buffer) {
            errs() << "Unable to open file '" << path << "'\n";
            delete lines;
            return;
        }
        LinePrinter.files[path] = lines;
    } else {
        lines = I->getValue();
    }
    while (lines->linev.size() <= ctx->line + 1) {
        const char *p;
        if (lines->linev.empty()) {
            p = lines->buffer->getBufferStart();
            lines->linev.push_back(p);
        } else {
            p = lines->linev.back();
            if (p == lines->buffer->getBufferEnd())
                break;
            p = strchr(p, '\n');
            if (!p) {
                p = lines->buffer->getBufferEnd();
                lines->linev.push_back(p);
            } else
                lines->linev.push_back(p + 1);
        }
    }
    if (ctx->line >= lines->linev.size()) {
        errs() << "Line number " << ctx->line << "out of file\n";
        return;
    }
    assert(ctx->line < lines->linev.size());
}

bool have_clamjit()
{
    return true;
}

void cli_bytecode_printversion()
{
    cl::PrintVersionMessage();
}

void cli_printcxxver()
{
    /* Try to print information about some commonly used compilers */
#ifdef __GNUC__
    printf("GNU C++: %s (%u.%u.%u)\n", __VERSION__, __GNUC__, __GNUC_MINOR__,
           __GNUC_PATCHLEVEL__);
#endif
#ifdef __INTEL_COMPILER
    printf("Intel Compiler C++ %u\n", __INTEL_COMPILER);
#endif
#ifdef _MSC_VER
    printf("Microsoft Visual C++ %u\n", _MSC_VER);
#endif
}

namespace ClamBCModule
{
void stop(const char *msg, llvm::Function *F, llvm::Instruction *I)
{
    if (F && F->hasName()) {
        cli_warnmsg("[%s] in function %s: %s", MODULE, F->getName().str().c_str(), msg);
    } else {
        cli_warnmsg("[%s] %s", MODULE, msg);
    }
}
} // namespace ClamBCModule
