/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin, Kevin Lin
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
#define DEBUG_TYPE "clambc-rtcheck"
#include "ClamBCModule.h"
#include "ClamBCDiagnostics.h"
#include "llvm30_compat.h" /* libclamav-specific */
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/Analysis/CallGraph.h"
#if LLVM_VERSION < 32
#include "llvm/Analysis/DebugInfo.h"
#elif LLVM_VERSION < 35
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif
#if LLVM_VERSION < 35
#include "llvm/Analysis/Dominators.h"
#include "llvm/Analysis/Verifier.h"
#else
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Verifier.h"
#endif
#include "llvm/Analysis/ConstantFolding.h"
#if LLVM_VERSION < 29
//#include "llvm/Analysis/LiveValues.h" (unused)
#include "llvm/Analysis/PointerTracking.h"
#else
#include "llvm/Analysis/ValueTracking.h"
#include "PointerTracking.h" /* included from old LLVM source */
#endif
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/ScalarEvolutionExpander.h"
#include "llvm/Config/config.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#if LLVM_VERSION < 35
#include "llvm/Support/DataFlow.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/GetElementPtrTypeIterator.h"
#else
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#endif
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/Debug.h"
#if LLVM_VERSION < 32
#include "llvm/Target/TargetData.h"
#elif LLVM_VERSION < 33
#include "llvm/DataLayout.h"
#else
#include "llvm/IR/DataLayout.h"
#endif
#if LLVM_VERSION < 33
#include "llvm/DerivedTypes.h"
#include "llvm/Instructions.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Intrinsics.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#else
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#endif

#if LLVM_VERSION < 33
#include "llvm/Support/InstVisitor.h"
#elif LLVM_VERSION < 35
#include "llvm/InstVisitor.h"
#else
#include "llvm/IR/InstVisitor.h"
#endif

#define DEFINEPASS(passname) passname() : FunctionPass(ID)

using namespace llvm;
#if LLVM_VERSION < 29
/* function is succeeded in later LLVM with LLVM corresponding standalone */
static Value *GetUnderlyingObject(Value *P, TargetData *TD)
{
    return P->getUnderlyingObject();
}
#endif

namespace llvm {
  class PtrVerifier;
#if LLVM_VERSION >= 29
  void initializePtrVerifierPass(PassRegistry&);
#endif

  class PtrVerifier : public FunctionPass {
  private:
      DenseSet<Function*> badFunctions;
      std::vector<Instruction*> delInst;
#if LLVM_VERSION < 35
      CallGraphNode *rootNode;
#else
      CallGraph *CG;
#endif
  public:
      static char ID;
#if LLVM_VERSION < 35
      DEFINEPASS(PtrVerifier), rootNode(0), PT(), TD(), SE(), expander(),
#else
      DEFINEPASS(PtrVerifier), CG(0), PT(), TD(), SE(), expander(),
#endif
          DT(), AbrtBB(), Changed(false), valid(false), EP() {
#if LLVM_VERSION >= 29
          initializePtrVerifierPass(*PassRegistry::getPassRegistry());
#endif
      }

      virtual bool runOnFunction(Function &F) {
          /*
#ifndef CLAMBC_COMPILER
          // Bytecode was already verified and had stack protector applied.
          // We get called again because ALL bytecode functions loaded are part of
          // the same module.
          if (F.hasFnAttr(Attribute::StackProtectReq))
              return false;
#endif
          */

          DEBUG(errs() << "Running on " << F.getName() << "\n");
          DEBUG(F.dump());
          Changed = false;
          BaseMap.clear();
          BoundsMap.clear();
          delInst.clear();
          AbrtBB = 0;
          valid = true;

#if LLVM_VERSION < 35
          if (!rootNode) {
              rootNode = getAnalysis<CallGraph>().getRoot();
#else
          if (!CG) {
              CG = &getAnalysis<CallGraphWrapperPass>().getCallGraph();
#endif
              // No recursive functions for now.
              // In the future we may insert runtime checks for stack depth.
#if LLVM_VERSION < 35
              for (scc_iterator<CallGraphNode*> SCCI = scc_begin(rootNode),
                       E = scc_end(rootNode); SCCI != E; ++SCCI) {
#else
              for (scc_iterator<CallGraph*> SCCI = scc_begin(CG); !SCCI.isAtEnd(); ++SCCI) {
#endif
                  const std::vector<CallGraphNode*> &nextSCC = *SCCI;
                  if (nextSCC.size() > 1 || SCCI.hasLoop()) {
                      errs() << "INVALID: Recursion detected, callgraph SCC components: ";
                      for (std::vector<CallGraphNode*>::const_iterator I = nextSCC.begin(),
                               E = nextSCC.end(); I != E; ++I) {
                          Function *FF = (*I)->getFunction();
                          if (FF) {
                              errs() << FF->getName() << ", ";
                              badFunctions.insert(FF);
                          }
                      }
                      if (SCCI.hasLoop())
                          errs() << "(self-loop)";
                      errs() << "\n";
                  }
                  // we could also have recursion via function pointers, but we don't
                  // allow calls to unknown functions, see runOnFunction() below
              }
          }

          BasicBlock::iterator It = F.getEntryBlock().begin();
          while (isa<AllocaInst>(It) || isa<PHINode>(It)) ++It;
          EP = &*It;
#if LLVM_VERSION < 32
          TD = &getAnalysis<TargetData>();
#elif LLVM_VERSION < 35
          TD = &getAnalysis<DataLayout>();
#else
          DataLayoutPass *DLP = getAnalysisIfAvailable<DataLayoutPass>();
          TD = DLP ? &DLP->getDataLayout() : 0;
#endif
          SE = &getAnalysis<ScalarEvolution>();
          PT = &getAnalysis<PointerTracking>();
#if LLVM_VERSION < 35
          DT = &getAnalysis<DominatorTree>();
#else
          DT = &getAnalysis<DominatorTreeWrapperPass>().getDomTree();
#endif
          expander = new SCEVExpander(*SE OPT("SCEVexpander"));

          std::vector<Instruction*> insns;

          BasicBlock *LastBB = 0;
          for (inst_iterator I=inst_begin(F),E=inst_end(F); I != E;++I) {
              Instruction *II = &*I;
              /* only appears in the libclamav version */
              if (II->getParent() != LastBB) {
                  LastBB = II->getParent();
                  if (DT->getNode(LastBB) == 0)
                      continue;
              }
              /* end-block */
              if (isa<LoadInst>(II) || isa<StoreInst>(II) || isa<MemIntrinsic>(II))
                  insns.push_back(II);
              else if (CallInst *CI = dyn_cast<CallInst>(II)) {
                  Value *V = CI->getCalledValue()->stripPointerCasts();
                  Function *F = dyn_cast<Function>(V);
                  if (!F) {
                      printLocation(CI, true);
                      errs() << "Could not determine call target\n";
                      valid = 0;
                      continue;
                  }
                  // this statement disable checks on user-defined CallInst
                  //if (!F->isDeclaration())
                  //continue;
                  insns.push_back(CI);
              }
          }

          for (unsigned Idx = 0; Idx < insns.size(); ++Idx) {
              Instruction *II = insns[Idx];
              DEBUG(dbgs() << "checking " << *II << "\n");
              if (LoadInst *LI = dyn_cast<LoadInst>(II)) {
                  constType *Ty = LI->getType();
                  valid &= validateAccess(LI->getPointerOperand(),
                                          TD->getTypeAllocSize(Ty), LI);
              } else if (StoreInst *SI = dyn_cast<StoreInst>(II)) {
                  constType *Ty = SI->getOperand(0)->getType();
                  valid &= validateAccess(SI->getPointerOperand(),
                                          TD->getTypeAllocSize(Ty), SI);
              } else if (MemIntrinsic *MI = dyn_cast<MemIntrinsic>(II)) {
                  valid &= validateAccess(MI->getDest(), MI->getLength(), MI);
                  if (MemTransferInst *MTI = dyn_cast<MemTransferInst>(MI)) {
                      valid &= validateAccess(MTI->getSource(), MI->getLength(), MI);
                  }
              } else if (CallInst *CI = dyn_cast<CallInst>(II)) {
                  Value *V = CI->getCalledValue()->stripPointerCasts();
                  Function *F = cast<Function>(V);
                  constFunctionType *FTy = F->getFunctionType();
                  CallSite CS(CI);
                  if (F->getName().equals("memcmp") && FTy->getNumParams() == 3) {
                      valid &= validateAccess(CS.getArgument(0), CS.getArgument(2), CI);
                      valid &= validateAccess(CS.getArgument(1), CS.getArgument(2), CI);
                      continue;
                  }
                  unsigned i;
#ifdef CLAMBC_COMPILER
                  i = 0;
#else
                  i = 1;// skip hidden ctx*
#endif
                  for (;i<FTy->getNumParams();i++) {
                      if (isa<PointerType>(FTy->getParamType(i))) {
                          Value *Ptr = CS.getArgument(i);
                          if (i+1 >= FTy->getNumParams()) {
                              printLocation(CI, false);
                              errs() << "Call to external function with pointer parameter last"
                                  " cannot be analyzed\n";
                              errs() << *CI << "\n";
                              valid = 0;
                              break;
                          }
                          Value *Size = CS.getArgument(i+1);
                          if (!Size->getType()->isIntegerTy()) {
                              printLocation(CI, false);
                              errs() << "Pointer argument must be followed by integer argument"
                                  " representing its size\n";
                              errs() << *CI << "\n";
                              valid = 0;
                              break;
                          }
                          valid &= validateAccess(Ptr, Size, CI);
                      }
                  }
              }
          }
          if (badFunctions.count(&F))
              valid = 0;

          if (!valid) {
              DEBUG(F.dump());
              ClamBCModule::stop("Verification found errors!", &F);
              // replace function with call to abort
              std::vector<constType*>args;
              FunctionType* abrtTy = FunctionType::get(Type::getVoidTy(F.getContext()),args,false);
              Constant *func_abort = F.getParent()->getOrInsertFunction("abort", abrtTy);

              BasicBlock *BB = &F.getEntryBlock();
              Instruction *I = &*BB->begin();
              Instruction *UI = new UnreachableInst(F.getContext(), I);
              CallInst *AbrtC = CallInst::Create(func_abort, "", UI);
              AbrtC->setCallingConv(CallingConv::C);
              AbrtC->setTailCall(true);
#if LLVM_VERSION < 32
              AbrtC->setDoesNotReturn(true);
              AbrtC->setDoesNotThrow(true);
#else
              AbrtC->setDoesNotReturn();
              AbrtC->setDoesNotThrow();
#endif
              // remove all instructions from entry
              BasicBlock::iterator BBI = I, BBE=BB->end();
              while (BBI != BBE) {
                  if (!BBI->use_empty())
                      BBI->replaceAllUsesWith(UndefValue::get(BBI->getType()));
                  BB->getInstList().erase(BBI++);
              }
          }

          // bb#9967 - deleting obsolete termination instructions
          for (unsigned i = 0; i < delInst.size(); ++i)
              delInst[i]->eraseFromParent();

          delete expander;
          return Changed;
      }

      virtual void releaseMemory() {
          badFunctions.clear();
      }

      virtual void getAnalysisUsage(AnalysisUsage &AU) const {
#if LLVM_VERSION < 32
          AU.addRequired<TargetData>();
#elif LLVM_VERSION < 35
          AU.addRequired<DataLayout>();
#else
          AU.addRequired<DataLayoutPass>();
#endif
#if LLVM_VERSION < 35
          AU.addRequired<DominatorTree>();
#else
          AU.addRequired<DominatorTreeWrapperPass>();
#endif
          AU.addRequired<ScalarEvolution>();
          AU.addRequired<PointerTracking>();
#if LLVM_VERSION < 35
          AU.addRequired<CallGraph>();
#else
          AU.addRequired<CallGraphWrapperPass>();
#endif
      }

      bool isValid() const { return valid; }
  private:
      PointerTracking *PT;
#if LLVM_VERSION < 32
      TargetData *TD;
#elif LLVM_VERSION < 35
      DataLayout *TD;
#else
      const DataLayout *TD;
#endif
      ScalarEvolution *SE;
      SCEVExpander *expander;
      DominatorTree *DT;
      DenseMap<Value*, Value*> BaseMap;
      DenseMap<Value*, Value*> BoundsMap;
      BasicBlock *AbrtBB;
      bool Changed;
      bool valid;
      Instruction *EP;

      Instruction *getInsertPoint(Value *V)
      {
          BasicBlock::iterator It = EP;
          if (Instruction *I = dyn_cast<Instruction>(V)) {
              It = I;
              ++It;
          }
          return &*It;
      }

      Value *getPointerBase(Value *Ptr)
      {
          if (BaseMap.count(Ptr))
              return BaseMap[Ptr];
          Value *P = Ptr->stripPointerCasts();
          if (BaseMap.count(P)) {
              return BaseMap[Ptr] = BaseMap[P];
          }
          Value *P2 = GetUnderlyingObject(P, TD);
          if (P2 != P) {
              Value *V = getPointerBase(P2);
              return BaseMap[Ptr] = V;
          }

          constType *P8Ty =
              PointerType::getUnqual(Type::getInt8Ty(Ptr->getContext()));
          if (PHINode *PN = dyn_cast<PHINode>(Ptr)) {
              BasicBlock::iterator It = PN;
              ++It;
              PHINode *newPN = PHINode::Create(P8Ty, HINT(PN->getNumIncomingValues()) ".verif.base", &*It);
              Changed = true;
              BaseMap[Ptr] = newPN;

              for (unsigned i=0;i<PN->getNumIncomingValues();i++) {
                  Value *Inc = PN->getIncomingValue(i);
                  Value *V = getPointerBase(Inc);
                  newPN->addIncoming(V, PN->getIncomingBlock(i));
              }
              return newPN;
          }
          if (SelectInst *SI = dyn_cast<SelectInst>(Ptr)) {
              BasicBlock::iterator It = SI;
              ++It;
              Value *TrueB = getPointerBase(SI->getTrueValue());
              Value *FalseB = getPointerBase(SI->getFalseValue());
              if (TrueB && FalseB) {
                  SelectInst *NewSI = SelectInst::Create(SI->getCondition(), TrueB,
                                                         FalseB, ".select.base", &*It);
                  Changed = true;
                  return BaseMap[Ptr] = NewSI;
              }
          }
          if (Ptr->getType() != P8Ty) {
              if (Constant *C = dyn_cast<Constant>(Ptr))
                  Ptr = ConstantExpr::getPointerCast(C, P8Ty);
              else {
                  Instruction *I = getInsertPoint(Ptr);
                  Ptr = new BitCastInst(Ptr, P8Ty, "", I);
              }
          }
          return BaseMap[Ptr] = Ptr;
      }

      Value* getValAtIdx(Function *F, unsigned Idx) {
          Value *Val= NULL;

          // check if accessed Idx is within function parameter list
          if (Idx < F->arg_size()) {
              Function::arg_iterator It = F->arg_begin();
              Function::arg_iterator ItEnd = F->arg_end();
              for (unsigned i = 0; i < Idx; ++i, ++It) {
                  // redundant check, should not be possible
                  if (It == ItEnd) {
                      // Houston, the impossible has become possible
                      //printDiagnostic("Idx is outside of Function parameters", F);
                      errs() << "Idx is outside of Function parameters\n";
                      errs() << *F << "\n";
                      //valid = 0;
                      break;
                  }
              }
              // retrieve value ptr of argument of F at Idx
              Val = &(*It);
          }
          else {
              // Idx is outside function parameter list
              //printDiagnostic("Idx is outside of Function parameters", F);
              errs() << "Idx is outside of Function parameters\n";
              errs() << *F << "\n";
              //valid = 0;
          }
          return Val;
      }

      Value* getPointerBounds(Value *Base) {
          if (BoundsMap.count(Base))
              return BoundsMap[Base];
          constType *I64Ty =
              Type::getInt64Ty(Base->getContext());

#ifndef CLAMBC_COMPILER
          // first arg is hidden ctx
          if (Argument *A = dyn_cast<Argument>(Base)) {
              if (A->getArgNo() == 0) {
                  constType *Ty = cast<PointerType>(A->getType())->getElementType();
                  return ConstantInt::get(I64Ty, TD->getTypeAllocSize(Ty));
              } else if (Base->getType()->isPointerTy()) {
                  Function *F = A->getParent();
                  const FunctionType *FT = F->getFunctionType();

                  bool checks = true;
                  // last argument check
                  if (A->getArgNo() == (FT->getNumParams()-1)) {
                      //printDiagnostic("pointer argument cannot be last argument", F);
                      errs() << "pointer argument cannot be last argument\n";
                      errs() << *F << "\n";
                      checks = false;
                  }

                  // argument after pointer MUST be a integer (unsigned probably too)
                  if (checks && !FT->getParamType(A->getArgNo()+1)->isIntegerTy()) {
                      //printDiagnostic("argument following pointer argument is not an integer", F);
                      errs() << "argument following pointer argument is not an integer\n";
                      errs() << *F << "\n";
                      checks = false;
                  }

                  if (checks)
                      return BoundsMap[Base] = getValAtIdx(F, A->getArgNo()+1);
              }
          }
          if (LoadInst *LI = dyn_cast<LoadInst>(Base)) {
              Value *V = GetUnderlyingObject(LI->getPointerOperand()->stripPointerCasts(), TD);
              if (Argument *A = dyn_cast<Argument>(V)) {
                  if (A->getArgNo() == 0) {
                      // pointers from hidden ctx are trusted to be at least the
                      // size they say they are
                      constType *Ty = cast<PointerType>(LI->getType())->getElementType();
                      return ConstantInt::get(I64Ty, TD->getTypeAllocSize(Ty));
                  }
              }
          }
#else
          if (Base->getType()->isPointerTy()) {
              if (Argument *A = dyn_cast<Argument>(Base)) {
                  Function *F = A->getParent();
                  const FunctionType *FT = F->getFunctionType();

                  bool checks = true;
                  // last argument check
                  if (A->getArgNo() == (FT->getNumParams()-1)) {
                      //printDiagnostic("pointer argument cannot be last argument", F);
                      errs() << "pointer argument cannot be last argument\n";
                      errs() << *F << "\n";
                      checks = false;
                  }

                  // argument after pointer MUST be a integer (unsigned probably too)
                  if (checks && !FT->getParamType(A->getArgNo()+1)->isIntegerTy()) {
                      //printDiagnostic("argument following pointer argument is not an integer", F);
                      errs() << "argument following pointer argument is not an integer\n";
                      errs() << *F << "\n";
                      checks = false;
                  }

                  if (checks)
                      return BoundsMap[Base] = getValAtIdx(F, A->getArgNo()+1);
              }
          }
#endif
          if (PHINode *PN = dyn_cast<PHINode>(Base)) {
              BasicBlock::iterator It = PN;
              ++It;
              PHINode *newPN = PHINode::Create(I64Ty, HINT(PN->getNumIncomingValues()) ".verif.bounds", &*It);
              Changed = true;
              BoundsMap[Base] = newPN;

              bool good = true;
              for (unsigned i=0;i<PN->getNumIncomingValues();i++) {
                  Value *Inc = PN->getIncomingValue(i);
                  Value *B = getPointerBounds(Inc);
                  if (!B) {
                      good = false;
                      B = ConstantInt::get(newPN->getType(), 0);
                      DEBUG(dbgs() << "bounds not found while solving phi node: " << *Inc
                            << "\n");
                  }
                  newPN->addIncoming(B, PN->getIncomingBlock(i));
              }
              if (!good)
                  newPN = 0;
              return BoundsMap[Base] = newPN;
          }
          if (SelectInst *SI = dyn_cast<SelectInst>(Base)) {
              BasicBlock::iterator It = SI;
              ++It;
              Value *TrueB = getPointerBounds(SI->getTrueValue());
              Value *FalseB = getPointerBounds(SI->getFalseValue());
              if (TrueB && FalseB) {
                  SelectInst *NewSI = SelectInst::Create(SI->getCondition(), TrueB,
                                                         FalseB, ".select.bounds", &*It);
                  Changed = true;
                  return BoundsMap[Base] = NewSI;
              }
          }

          constType *Ty;
          Value *V = PT->computeAllocationCountValue(Base, Ty);
          if (!V) {
              Base = Base->stripPointerCasts();
              if (CallInst *CI = dyn_cast<CallInst>(Base)) {
                  Function *F = CI->getCalledFunction();
                  constFunctionType *FTy = F->getFunctionType();
                  // last operand is always size for this API call kind
                  if (F->isDeclaration() && FTy->getNumParams() > 0) {
                      CallSite CS(CI);
                      if (FTy->getParamType(FTy->getNumParams()-1)->isIntegerTy())
                          V = CS.getArgument(FTy->getNumParams()-1);
                  }
              }
              if (!V)
                  return BoundsMap[Base] = 0;
          } else {
              unsigned size = TD->getTypeAllocSize(Ty);
              if (size > 1) {
                  Constant *C = cast<Constant>(V);
                  C = ConstantExpr::getMul(C,
                                           ConstantInt::get(Type::getInt32Ty(C->getContext()),
                                                            size));
                  V = C;
              }
          }
          if (V->getType() != I64Ty) {
              if (Constant *C = dyn_cast<Constant>(V))
                  V = ConstantExpr::getZExt(C, I64Ty);
              else {
                  Instruction *I = getInsertPoint(V);
                  V = new ZExtInst(V, I64Ty, "", I);
              }
          }
          return BoundsMap[Base] = V;
      }

      MDNode *getLocation(Instruction *I, bool &Approximate, unsigned MDDbgKind)
      {
          Approximate = false;
          if (MDNode *Dbg = I->getMetadata(MDDbgKind))
              return Dbg;
          if (!MDDbgKind)
              return 0;
          Approximate = true;
          BasicBlock::iterator It = I;
          while (It != I->getParent()->begin()) {
              --It;
              if (MDNode *Dbg = It->getMetadata(MDDbgKind))
                  return Dbg;
          }
          BasicBlock *BB = I->getParent();
          while ((BB = BB->getUniquePredecessor())) {
              It = BB->end();
              while (It != BB->begin()) {
                  --It;
                  if (MDNode *Dbg = It->getMetadata(MDDbgKind))
                      return Dbg;
              }
          }
          return 0;
      }

      bool insertCheck(const SCEV *Idx, const SCEV *Limit, Instruction *I,
                       bool strict)
      {
          if (isa<SCEVCouldNotCompute>(Idx) && isa<SCEVCouldNotCompute>(Limit)) {
              errs() << "Could not compute the index and the limit!: \n" << *I << "\n";
              return false;
          }
          if (isa<SCEVCouldNotCompute>(Idx)) {
              errs() << "Could not compute index: \n" << *I << "\n";
              return false;
          }
          if (isa<SCEVCouldNotCompute>(Limit)) {
              errs() << "Could not compute limit: " << *I << "\n";
              return false;
          }
          BasicBlock *BB = I->getParent();
          BasicBlock::iterator It = I;
          BasicBlock *newBB = SplitBlock(BB, &*It, this);
          PHINode *PN;
          unsigned MDDbgKind = I->getContext().getMDKindID("dbg");
          //verifyFunction(*BB->getParent());
          if (!AbrtBB) {
              std::vector<constType*>args;
              FunctionType* abrtTy = FunctionType::get(Type::getVoidTy(BB->getContext()),args,false);
              args.push_back(Type::getInt32Ty(BB->getContext()));
              FunctionType* rterrTy = FunctionType::get(Type::getInt32Ty(BB->getContext()),args,false);
              Constant *func_abort = BB->getParent()->getParent()->getOrInsertFunction("abort", abrtTy);
              Constant *func_rterr = BB->getParent()->getParent()->getOrInsertFunction("bytecode_rt_error",
                                                                                       rterrTy);
              AbrtBB = BasicBlock::Create(BB->getContext(), "rterr.trig", BB->getParent());
              
              PN = PHINode::Create(Type::getInt32Ty(BB->getContext()),HINT(1) "",
                                   AbrtBB);
              if (MDDbgKind) {
                  CallInst *RtErrCall = CallInst::Create(func_rterr, PN, "", AbrtBB);
                  RtErrCall->setCallingConv(CallingConv::C);
                  RtErrCall->setTailCall(true);
#if LLVM_VERSION < 32
                  RtErrCall->setDoesNotThrow(true);
#else
                  RtErrCall->setDoesNotThrow();
#endif
              }
              CallInst* AbrtC = CallInst::Create(func_abort, "", AbrtBB);
              AbrtC->setCallingConv(CallingConv::C);
              AbrtC->setTailCall(true);
#if LLVM_VERSION < 32
              AbrtC->setDoesNotReturn(true);
              AbrtC->setDoesNotThrow(true);
#else
              AbrtC->setDoesNotReturn();
              AbrtC->setDoesNotThrow();
#endif
              new UnreachableInst(BB->getContext(), AbrtBB);
              DT->addNewBlock(AbrtBB, BB);
              //verifyFunction(*BB->getParent());
          } else {
              PN = cast<PHINode>(AbrtBB->begin());
          }
          unsigned locationid = 0;
          bool Approximate;
          if (MDNode *Dbg = getLocation(I, Approximate, MDDbgKind)) {
              DILocation Loc(Dbg);
              locationid = Loc.getLineNumber() << 8;
              unsigned col = Loc.getColumnNumber();
              if (col > 254)
                  col = 254;
              if (Approximate)
                  col = 255;
              locationid |= col;
          }
          PN->addIncoming(ConstantInt::get(Type::getInt32Ty(BB->getContext()),
                                           locationid), BB);
          TerminatorInst *TI = BB->getTerminator();
          Value *IdxV = expander->expandCodeFor(Idx, Limit->getType(), TI);
          Value *LimitV = expander->expandCodeFor(Limit, Limit->getType(), TI);
          if (isa<Instruction>(IdxV) &&
              !DT->dominates(cast<Instruction>(IdxV)->getParent(),I->getParent())) {
              printLocation(I, true);
              errs() << "basic block with value [ " << IdxV->getName();
              errs() << " ] with limit [ " << LimitV->getName();
              errs() << " ] does not dominate" << *I << "\n";
              return false;
          }
          if (isa<Instruction>(LimitV) &&
              !DT->dominates(cast<Instruction>(LimitV)->getParent(),I->getParent())) {
              printLocation(I, true);
              errs() << "basic block with limit [" << LimitV->getName();
              errs() << " ] on value [ " << IdxV->getName();
              errs() << " ] does not dominate" << *I << "\n";
              return false;
          }
          Value *Cond = new ICmpInst(TI, strict ?
                                     ICmpInst::ICMP_ULT :
                                     ICmpInst::ICMP_ULE, IdxV, LimitV);
          BranchInst::Create(newBB, AbrtBB, Cond, TI);
          //TI->eraseFromParent();
          delInst.push_back(TI);
          // Update dominator info
          BasicBlock *DomBB =
              DT->findNearestCommonDominator(BB, DT->getNode(AbrtBB)->getIDom()->getBlock());
          DT->changeImmediateDominator(AbrtBB, DomBB);
          return true;
      }

      static void MakeCompatible(ScalarEvolution *SE, const SCEV*& LHS, const SCEV*& RHS)
      {
          if (const SCEVZeroExtendExpr *ZL = dyn_cast<SCEVZeroExtendExpr>(LHS))
              LHS = ZL->getOperand();
          if (const SCEVZeroExtendExpr *ZR = dyn_cast<SCEVZeroExtendExpr>(RHS))
              RHS = ZR->getOperand();

          constType* LTy = SE->getEffectiveSCEVType(LHS->getType());
          constType *RTy = SE->getEffectiveSCEVType(RHS->getType());
          if (SE->getTypeSizeInBits(RTy) > SE->getTypeSizeInBits(LTy))
              LTy = RTy;
          LHS = SE->getNoopOrZeroExtend(LHS, LTy);
          RHS = SE->getNoopOrZeroExtend(RHS, LTy);
      }

      bool checkCond(Instruction *ICI, Instruction *I, bool equal)
      {
          for (Value::use_iterator JU=ICI->use_begin(),JUE=ICI->use_end();
               JU != JUE; ++JU) {
              Value *JU_V = *JU;
              if (BranchInst *BI = dyn_cast<BranchInst>(JU_V)) {
                  if (!BI->isConditional())
                      continue;
                  BasicBlock *S = BI->getSuccessor(equal);
                  if (DT->dominates(S, I->getParent()))
                      return true;
              }
              if (BinaryOperator *BI = dyn_cast<BinaryOperator>(JU_V)) {
                  if (BI->getOpcode() == Instruction::Or &&
                      checkCond(BI, I, equal))
                      return true;
                  if (BI->getOpcode() == Instruction::And &&
                      checkCond(BI, I, !equal))
                      return true;
              }
          }
          return false;
      }

      bool checkCondition(Instruction *CI, Instruction *I)
      {
          for (Value::use_iterator U=CI->use_begin(),UE=CI->use_end();
               U != UE; ++U) {
              Value *U_V = *U;
              if (ICmpInst *ICI = dyn_cast<ICmpInst>(U_V)) {
                  if (ICI->getOperand(0)->stripPointerCasts() == CI &&
                      isa<ConstantPointerNull>(ICI->getOperand(1))) {
                      if (checkCond(ICI, I, ICI->getPredicate() == ICmpInst::ICMP_EQ))
                          return true;
                  }
              }
          }
          return false;
      }

      bool validateAccess(Value *Pointer, Value *Length, Instruction *I)
      {
          // get base
          Value *Base = getPointerBase(Pointer);

          Value *SBase = Base->stripPointerCasts();
          // get bounds
          Value *Bounds = getPointerBounds(SBase);
          if (!Bounds) {
              printLocation(I, true);
              errs() << "no bounds for base ";
              printValue(SBase);
              errs() << " while checking access to ";
              printValue(Pointer);
              errs() << " of length ";
              printValue(Length);
              errs() << "\n";

              return false;
          }

          // checks if a NULL pointer check (returned from function) is made:
          if (CallInst *CI = dyn_cast<CallInst>(Base->stripPointerCasts())) {
              // by checking if use is in the same block (i.e. no branching decisions)
              if (I->getParent() == CI->getParent()) {
                  printLocation(I, true);
                  errs() << "no null pointer check of pointer ";
                  printValue(Base, false, true);
                  errs() << " obtained by function call";
                  errs() << " before use in same block\n";
                  return false;
              }
              // by checking if a conditional contains the values in question somewhere
              // between their usage
              if (!checkCondition(CI, I)) {
                  printLocation(I, true);
                  errs() << "no null pointer check of pointer ";
                  printValue(Base, false, true);
                  errs() << " obtained by function call";
                  errs() << " before use\n";
                  return false;
              }
          }

      constType *I64Ty =
          Type::getInt64Ty(Base->getContext());
      const SCEV *SLen = SE->getSCEV(Length);
      const SCEV *OffsetP = SE->getMinusSCEV(SE->getSCEV(Pointer),
                                             SE->getSCEV(Base));
      SLen = SE->getNoopOrZeroExtend(SLen, I64Ty);
      OffsetP = SE->getNoopOrZeroExtend(OffsetP, I64Ty);
      const SCEV *Limit = SE->getSCEV(Bounds);
      Limit = SE->getNoopOrZeroExtend(Limit, I64Ty);

      DEBUG(dbgs() << "Checking access to " << *Pointer << " of length " <<
            *Length << "\n");
      if (OffsetP == Limit) {
          printLocation(I, true);
          errs() << "OffsetP == Limit: " << *OffsetP << "\n";
          errs() << " while checking access to ";
          printValue(Pointer);
          errs() << " of length ";
          printValue(Length);
          errs() << "\n";
          return false;
      }

      if (SLen == Limit) {
          if (const SCEVConstant *SC = dyn_cast<SCEVConstant>(OffsetP)) {
              if (SC->isZero())
                  return true;
          }
          errs() << "SLen == Limit: " << *SLen << "\n";
          errs() << " while checking access to " << *Pointer << " of length "
                 << *Length << " at " << *I << "\n";
          return false;
      }

      bool valid = true;
      SLen = SE->getAddExpr(OffsetP, SLen);
      // check that offset + slen <= limit;
      // umax(offset+slen, limit) == limit is a sufficient (but not necessary
      // condition)
      const SCEV *MaxL = SE->getUMaxExpr(SLen, Limit);
      if (MaxL != Limit) {
          DEBUG(dbgs() << "MaxL != Limit: " << *MaxL << ", " << *Limit << "\n");
          valid &= insertCheck(SLen, Limit, I, false);
      }

      //TODO: nullpointer check
      const SCEV *Max = SE->getUMaxExpr(OffsetP, Limit);
      if (Max == Limit)
          return valid;
      DEBUG(dbgs() << "Max != Limit: " << *Max << ", " << *Limit << "\n");

      // check that offset < limit
      valid &= insertCheck(OffsetP, Limit, I, true);
      return valid;
      }

      bool validateAccess(Value *Pointer, unsigned size, Instruction *I)
      {
          return validateAccess(Pointer,
                                ConstantInt::get(Type::getInt32Ty(Pointer->getContext()),
                                                 size), I);
      }

  };
    char PtrVerifier::ID;

} /* end namespace llvm */
#if LLVM_VERSION >= 29
INITIALIZE_PASS_BEGIN(PtrVerifier, "", "", false, false)
#if LLVM_VERSION < 32
INITIALIZE_PASS_DEPENDENCY(TargetData)
#elif LLVM_VERSION < 35
INITIALIZE_PASS_DEPENDENCY(DataLayout)
#else
INITIALIZE_PASS_DEPENDENCY(DataLayoutPass)
#endif
#if LLVM_VERSION < 35
INITIALIZE_PASS_DEPENDENCY(DominatorTree)
#else
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
#endif
INITIALIZE_PASS_DEPENDENCY(ScalarEvolution)
#if LLVM_VERSION < 34
INITIALIZE_AG_DEPENDENCY(CallGraph)
#elif LLVM_VERSION < 35
INITIALIZE_PASS_DEPENDENCY(CallGraph)
#else
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
#endif
INITIALIZE_PASS_DEPENDENCY(PointerTracking)
INITIALIZE_PASS_END(PtrVerifier, "clambc-rtchecks", "ClamBC RTchecks", false, false)
#endif


llvm::Pass *createClamBCRTChecks()
{
    return new PtrVerifier();
}
