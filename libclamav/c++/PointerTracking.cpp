//===- PointerTracking.cpp - Pointer Bounds Tracking ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements tracking of pointer bounds.
//
//===----------------------------------------------------------------------===//

/* this shouldn't be part of win32 proj at all, but its easier to exclude here
 * */
#ifndef _WIN32

#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/ValueTracking.h"
#include "PointerTracking.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#if LLVM_VERSION < 35
#include "llvm/Support/CallSite.h"
#include "llvm/Support/InstIterator.h"
#else
#include "llvm/IR/CallSite.h"
#include "llvm/IR/InstIterator.h"
#endif
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetLibraryInfo.h"

#if LLVM_VERSION < 32
#include "llvm/Target/TargetData.h"
#elif LLVM_VERSION < 33
#include "llvm/DataLayout.h"
#else
#include "llvm/IR/DataLayout.h"
#endif

#if LLVM_VERSION < 33
#include "llvm/Constants.h"
#include "llvm/Module.h"
#include "llvm/Value.h"
#else
#include "llvm/IR/Constants.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#endif

using namespace llvm;
#if LLVM_VERSION < 29
/* function is succeeded in later LLVM with LLVM corresponding standalone */
static Value *GetUnderlyingObject(Value *P, TargetData *TD)
{
    return P->getUnderlyingObject();
}
#endif

#if LLVM_VERSION >= 29
namespace llvm
{
void initializePointerTrackingPass(llvm::PassRegistry &);
};
INITIALIZE_PASS_BEGIN(PointerTracking, "pointertracking",
                      "Track pointer bounds", false, true)
#if LLVM_VERSION < 35
INITIALIZE_PASS_DEPENDENCY(DominatorTree)
#else
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
#endif
INITIALIZE_PASS_DEPENDENCY(LoopInfo)
INITIALIZE_PASS_DEPENDENCY(ScalarEvolution)
#if LLVM_VERSION < 35
INITIALIZE_PASS_DEPENDENCY(DominatorTree)
#else
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
#endif
INITIALIZE_PASS_END(PointerTracking, "pointertracking",
                    "Track pointer bounds", false, true)
#endif

char PointerTracking::ID = 0;
PointerTracking::PointerTracking()
    : FunctionPass(ID)
{
#if LLVM_VERSION >= 29
    initializePointerTrackingPass(*PassRegistry::getPassRegistry());
#endif
}

bool PointerTracking::runOnFunction(Function &F)
{
    predCache.clear();
    assert(analyzing.empty());
    FF = &F;
#if LLVM_VERSION < 32
    TD = getAnalysisIfAvailable<TargetData>();
#elif LLVM_VERSION < 35
    TD = getAnalysisIfAvailable<DataLayout>();
#else
    DataLayoutPass *DLP = getAnalysisIfAvailable<DataLayoutPass>();
    TD                  = DLP ? &DLP->getDataLayout() : 0;
#endif
    SE = &getAnalysis<ScalarEvolution>();
    LI = &getAnalysis<LoopInfo>();
#if LLVM_VERSION < 35
    DT = &getAnalysis<DominatorTree>();
#else
    DT = &getAnalysis<DominatorTreeWrapperPass>().getDomTree();
#endif
    return false;
}

void PointerTracking::getAnalysisUsage(AnalysisUsage &AU) const
{
#if LLVM_VERSION < 35
    AU.addRequiredTransitive<DominatorTree>();
#else
    AU.addRequiredTransitive<DominatorTreeWrapperPass>();
#endif
    AU.addRequiredTransitive<LoopInfo>();
    AU.addRequiredTransitive<ScalarEvolution>();
    AU.setPreservesAll();
}

bool PointerTracking::doInitialization(Module &M)
{
    constType *PTy = Type::getInt8PtrTy(M.getContext());

    // Find calloc(i64, i64) or calloc(i32, i32).
    callocFunc = M.getFunction("calloc");
    if (callocFunc) {
        constFunctionType *Ty = callocFunc->getFunctionType();

        std::vector<constType *> args, args2;
        args.push_back(Type::getInt64Ty(M.getContext()));
        args.push_back(Type::getInt64Ty(M.getContext()));
        args2.push_back(Type::getInt32Ty(M.getContext()));
        args2.push_back(Type::getInt32Ty(M.getContext()));
        constFunctionType *Calloc1Type =
            FunctionType::get(PTy, args, false);
        constFunctionType *Calloc2Type =
            FunctionType::get(PTy, args2, false);
        if (Ty != Calloc1Type && Ty != Calloc2Type)
            callocFunc = 0; // Give up
    }

    // Find realloc(i8*, i64) or realloc(i8*, i32).
    reallocFunc = M.getFunction("realloc");
    if (reallocFunc) {
        constFunctionType *Ty = reallocFunc->getFunctionType();
        std::vector<constType *> args, args2;
        args.push_back(PTy);
        args.push_back(Type::getInt64Ty(M.getContext()));
        args2.push_back(PTy);
        args2.push_back(Type::getInt32Ty(M.getContext()));

        constFunctionType *Realloc1Type =
            FunctionType::get(PTy, args, false);
        constFunctionType *Realloc2Type =
            FunctionType::get(PTy, args2, false);
        if (Ty != Realloc1Type && Ty != Realloc2Type)
            reallocFunc = 0; // Give up
    }
    return false;
}

// Calculates the number of elements allocated for pointer P,
// the type of the element is stored in Ty.
const SCEV *PointerTracking::computeAllocationCount(Value *P,
                                                    constType *&Ty) const
{
    Value *V = P->stripPointerCasts();
    if (AllocaInst *AI = dyn_cast<AllocaInst>(V)) {
        Value *arraySize = AI->getArraySize();
        Ty               = AI->getAllocatedType();
        // arraySize elements of type Ty.
        return SE->getSCEV(arraySize);
    }

#if LLVM_VERSION < 32
    if (CallInst *CI = extractMallocCall(V)) {
        Value *arraySize   = getMallocArraySize(CI, TD);
        constType *AllocTy = getMallocAllocatedType(CI);
#else
    TargetLibraryInfo *TLI = new TargetLibraryInfo();

    if (CallInst *CI = extractMallocCall(V, TLI)) {
        Value *arraySize   = getMallocArraySize(CI, TD, TLI);
        constType *AllocTy = getMallocAllocatedType(CI, TLI);
#endif
        if (!AllocTy || !arraySize) return SE->getCouldNotCompute();
        Ty = AllocTy;
        // arraySize elements of type Ty.
        return SE->getSCEV(arraySize);
    }

    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(V)) {
        if (GV->hasDefinitiveInitializer()) {
            Constant *C = GV->getInitializer();
            if (const ArrayType *ATy = dyn_cast<ArrayType>(C->getType())) {
                Ty = ATy->getElementType();
                return SE->getConstant(Type::getInt32Ty(P->getContext()),
                                       ATy->getNumElements());
            }
        }
        Ty = GV->getType();
        return SE->getConstant(Type::getInt32Ty(P->getContext()), 1);
        //TODO: implement more tracking for globals
    }

    if (CallInst *CI = dyn_cast<CallInst>(V)) {
        CallSite CS(CI);
        Function *F   = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
        const Loop *L = LI->getLoopFor(CI->getParent());
        if (F == callocFunc) {
            Ty = Type::getInt8Ty(P->getContext());
            // calloc allocates arg0*arg1 bytes.
            return SE->getSCEVAtScope(SE->getMulExpr(SE->getSCEV(CS.getArgument(0)),
                                                     SE->getSCEV(CS.getArgument(1))),
                                      L);
        } else if (F == reallocFunc) {
            Ty = Type::getInt8Ty(P->getContext());
            // realloc allocates arg1 bytes.
            return SE->getSCEVAtScope(CS.getArgument(1), L);
        }
    }

    return SE->getCouldNotCompute();
}

Value *PointerTracking::computeAllocationCountValue(Value *P, constType *&Ty) const
{
    Value *V = P->stripPointerCasts();
    if (AllocaInst *AI = dyn_cast<AllocaInst>(V)) {
        Ty = AI->getAllocatedType();
        // arraySize elements of type Ty.
        return AI->getArraySize();
    }

#if LLVM_VERSION < 32
    if (CallInst *CI = extractMallocCall(V)) {
        Ty = getMallocAllocatedType(CI);
        if (!Ty)
            return 0;
        Value *arraySize = getMallocArraySize(CI, TD);
#else
    TargetLibraryInfo *TLI = new TargetLibraryInfo();

    if (CallInst *CI = extractMallocCall(V, TLI)) {
        Ty = getMallocAllocatedType(CI, TLI);
        if (!Ty)
            return 0;
        Value *arraySize = getMallocArraySize(CI, TD, TLI);
#endif
        if (!arraySize) {
            Ty = Type::getInt8Ty(P->getContext());
            return CI->getArgOperand(0);
        }
        // arraySize elements of type Ty.
        return arraySize;
    }

    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(V)) {
        if (GV->hasDefinitiveInitializer()) {
            Constant *C = GV->getInitializer();
            if (const ArrayType *ATy = dyn_cast<ArrayType>(C->getType())) {
                Ty = ATy->getElementType();
                return ConstantInt::get(Type::getInt32Ty(P->getContext()),
                                        ATy->getNumElements());
            }
        }
        Ty = cast<PointerType>(GV->getType())->getElementType();
        return ConstantInt::get(Type::getInt32Ty(P->getContext()), 1);
        //TODO: implement more tracking for globals
    }

    if (CallInst *CI = dyn_cast<CallInst>(V)) {
        CallSite CS(CI);
        Function *F = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
        if (F == reallocFunc) {
            Ty = Type::getInt8Ty(P->getContext());
            // realloc allocates arg1 bytes.
            return CS.getArgument(1);
        }
    }

    return 0;
}

// Calculates the number of elements of type Ty allocated for P.
const SCEV *PointerTracking::computeAllocationCountForType(Value *P,
                                                           constType *Ty)
    const
{
    constType *elementTy;
    const SCEV *Count = computeAllocationCount(P, elementTy);
    if (isa<SCEVCouldNotCompute>(Count))
        return Count;
    if (elementTy == Ty)
        return Count;

    if (!TD) // need TargetData from this point forward
        return SE->getCouldNotCompute();

    uint64_t elementSize = TD->getTypeAllocSize(elementTy);
    uint64_t wantSize    = TD->getTypeAllocSize(Ty);
    if (elementSize == wantSize)
        return Count;
    if (elementSize % wantSize) //fractional counts not possible
        return SE->getCouldNotCompute();
    return SE->getMulExpr(Count, SE->getConstant(Count->getType(),
                                                 elementSize / wantSize));
}

const SCEV *PointerTracking::getAllocationElementCount(Value *V) const
{
    // We only deal with pointers.
    const PointerType *PTy = cast<PointerType>(V->getType());
    return computeAllocationCountForType(V, PTy->getElementType());
}

const SCEV *PointerTracking::getAllocationSizeInBytes(Value *V) const
{
    return computeAllocationCountForType(V, Type::getInt8Ty(V->getContext()));
}

// Helper for isLoopGuardedBy that checks the swapped and inverted predicate too
enum SolverResult PointerTracking::isLoopGuardedBy(const Loop *L,
                                                   Predicate Pred,
                                                   const SCEV *A,
                                                   const SCEV *B) const
{
    if (SE->isLoopEntryGuardedByCond(L, Pred, A, B))
        return AlwaysTrue;
    Pred = ICmpInst::getSwappedPredicate(Pred);
    if (SE->isLoopEntryGuardedByCond(L, Pred, B, A))
        return AlwaysTrue;

    Pred = ICmpInst::getInversePredicate(Pred);
    if (SE->isLoopEntryGuardedByCond(L, Pred, B, A))
        return AlwaysFalse;
    Pred = ICmpInst::getSwappedPredicate(Pred);
    if (SE->isLoopEntryGuardedByCond(L, Pred, A, B))
        return AlwaysTrue;
    return Unknown;
}

enum SolverResult PointerTracking::checkLimits(const SCEV *Offset,
                                               const SCEV *Limit,
                                               BasicBlock *BB)
{
    //FIXME: merge implementation
    return Unknown;
}

void PointerTracking::getPointerOffset(Value *Pointer, Value *&Base,
                                       const SCEV *&Limit,
                                       const SCEV *&Offset) const
{
    Pointer = Pointer->stripPointerCasts();
    Base    = GetUnderlyingObject(Pointer, TD);
    Limit   = getAllocationSizeInBytes(Base);
    if (isa<SCEVCouldNotCompute>(Limit)) {
        Base   = 0;
        Offset = Limit;
        return;
    }

    Offset = SE->getMinusSCEV(SE->getSCEV(Pointer), SE->getSCEV(Base));
    if (isa<SCEVCouldNotCompute>(Offset)) {
        Base  = 0;
        Limit = Offset;
    }
}

void PointerTracking::print(raw_ostream &OS, const Module *M) const
{
    // Calling some PT methods may cause caches to be updated, however
    // this should be safe for the same reason its safe for SCEV.
    PointerTracking &PT = *const_cast<PointerTracking *>(this);
    for (inst_iterator I = inst_begin(*FF), E = inst_end(*FF); I != E; ++I) {
        if (!I->getType()->isPointerTy())
            continue;
        Value *Base;
        const SCEV *Limit, *Offset;
        getPointerOffset(&*I, Base, Limit, Offset);
        if (!Base)
            continue;

        if (Base == &*I) {
            const SCEV *S = getAllocationElementCount(Base);
            OS << *Base << " ==> " << *S << " elements, ";
            OS << *Limit << " bytes allocated\n";
            continue;
        }
        OS << &*I << " -- base: " << *Base;
        OS << " offset: " << *Offset;

        enum SolverResult res = PT.checkLimits(Offset, Limit, I->getParent());
        switch (res) {
            case AlwaysTrue:
                OS << " always safe\n";
                break;
            case AlwaysFalse:
                OS << " always unsafe\n";
                break;
            case Unknown:
                OS << " <<unknown>>\n";
                break;
        }
    }
}
#endif
