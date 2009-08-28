/*
 *  Load, and verify ClamAV bytecode.
 *
 *  Copyright (C) 2009 Sourcefire, Inc.
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
#define DEBUG_TYPE "clamavjit"
#include "llvm/ADT/DenseMap.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Function.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JIT.h"
#include "llvm/ExecutionEngine/JITEventListener.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/PassManager.h"
#include "llvm/ModuleProvider.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/System/Signals.h"
#include "llvm/System/Threading.h"
#include "llvm/Target/TargetSelect.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Support/TargetFolder.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/System/ThreadLocal.h"
#include <cstdlib>
#include <csetjmp>
#include <new>

#include "clamav.h"
#include "clambc.h"
#include "bytecode_priv.h"
#include "bytecode.h"

#define MODULE "libclamav JIT: "

using namespace llvm;
typedef DenseMap<const struct cli_bc_func*, void*> FunctionMapTy;
struct cli_bcengine {
    ExecutionEngine *EE;
    LLVMContext Context;
    FunctionMapTy compiledFunctions;
};

namespace {

static sys::ThreadLocal<const jmp_buf> ExceptionReturn;

void do_shutdown() {
    llvm_shutdown();
}

static void NORETURN jit_exception_handler(void)
{
    longjmp(*const_cast<jmp_buf*>(ExceptionReturn.get()), 1);
}

void llvm_error_handler(void *user_data, const std::string &reason)
{
    errs() << reason;
    jit_exception_handler();
}

class VISIBILITY_HIDDEN LLVMCodegen {
private:
    const struct cli_bc *bc;
    Module *M;
    LLVMContext &Context;
    FunctionMapTy &compiledFunctions;
    const Type **TypeMap;
    Twine BytecodeID;
    ExecutionEngine *EE;
    TargetFolder Folder;
    IRBuilder<false, TargetFolder> Builder;
    Value **Values;
    FunctionPassManager &PM;
    unsigned numLocals;
    unsigned numArgs;

    const Type *mapType(uint16_t ty)
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
	ty -= 69;
	// This was validated by libclamav already.
	assert(ty < bc->num_types && "Out of range type ID");
	return TypeMap[ty];
    }

    void convertTypes() {
	for (unsigned j=0;j<bc->num_types;j++) {

	}
    }

    Value *convertOperand(const struct cli_bc_func *func, const Type *Ty, operand_t operand)
    {
	unsigned map[] = {0, 1, 2, 3, 3, 4, 4, 4, 4};
	if (operand < func->numArgs)
	    return Values[operand];
	if (operand < func->numValues)
	    return Builder.CreateLoad(Values[operand]);
	unsigned w = (Ty->getPrimitiveSizeInBits()+7)/8;
	return convertOperand(func, map[w], operand);
    }

    Value *convertOperand(const struct cli_bc_func *func,
			  const struct cli_bc_inst *inst,  operand_t operand)
    {
	return convertOperand(func, inst->interp_op%5, operand);
    }

    Value *convertOperand(const struct cli_bc_func *func,
			  unsigned w, operand_t operand) {
	if (operand < func->numArgs)
	    return Values[operand];
	if (operand < func->numValues)
	    return Builder.CreateLoad(Values[operand]);

	// Constant
	operand -= func->numValues;
	// This was already validated by libclamav.
	assert(operand < func->numConstants && "Constant out of range");
	uint64_t *c = &func->constants[operand];
	uint64_t v;
	const Type *Ty;
	switch (w) {
	    case 0:
	    case 1:
		Ty = w ? Type::getInt8Ty(Context) : 
		    Type::getInt1Ty(Context);
		v = *(uint8_t*)c;
		break;
	    case 2:
		Ty = Type::getInt16Ty(Context);
		v = *(uint16_t*)c;
		break;
	    case 3:
		Ty = Type::getInt32Ty(Context);
		v = *(uint32_t*)c;
		break;
	    case 4:
		Ty = Type::getInt64Ty(Context);
		v = *(uint64_t*)c;
		break;
	}
	return ConstantInt::get(Ty, v);
    }

    void Store(uint16_t dest, Value *V)
    {
	assert(dest >= numArgs && dest < numLocals+numArgs && "Instruction destination out of range");
	Builder.CreateStore(V, Values[dest]);
    }

    // Insert code that calls \arg FHandler if \arg FailCond is true.
    void InsertVerify(Value *FailCond, BasicBlock *&Fail, Function *FHandler, 
		      Function *F) {
	if (!Fail) {
	    Fail = BasicBlock::Create(Context, "fail", F);
	    CallInst::Create(FHandler,"",Fail);
	    new UnreachableInst(Context, Fail);
	}
	BasicBlock *OkBB = BasicBlock::Create(Context, "", F);
	Builder.CreateCondBr(FailCond, Fail, OkBB);
	Builder.SetInsertPoint(OkBB);
    }
public:
    LLVMCodegen(const struct cli_bc *bc, Module *M, FunctionMapTy &cFuncs,
		ExecutionEngine *EE, FunctionPassManager &PM)
	: bc(bc), M(M), Context(M->getContext()), compiledFunctions(cFuncs), 
	BytecodeID("bc"+Twine(bc->id)), EE(EE), 
	Folder(EE->getTargetData(), Context), Builder(Context, Folder), PM(PM) {
	    TypeMap = new const Type*[bc->num_types];
    }

    bool generate() {
	PrettyStackTraceString Trace(BytecodeID.str().c_str());
	convertTypes();

	FunctionType *FTy = FunctionType::get(Type::getVoidTy(Context),
						    false);
	Function *FHandler = Function::Create(FTy, Function::InternalLinkage,
					      "clamjit.fail", M);
	FHandler->setDoesNotReturn();
	FHandler->setDoesNotThrow();
	FHandler->addFnAttr(Attribute::NoInline);
	EE->addGlobalMapping(FHandler, (void*)jit_exception_handler); 

	Function **Functions = new Function*[bc->num_func];
	for (unsigned j=0;j<bc->num_func;j++) {
	    PrettyStackTraceString CrashInfo("Generate LLVM IR functions");
	    // Create LLVM IR Function
	    const struct cli_bc_func *func = &bc->funcs[j];
	    std::vector<const Type*> argTypes;
	    for (unsigned a=0;a<func->numArgs;a++) {
		argTypes.push_back(mapType(func->types[a]));
	    }
	    const Type *RetTy = mapType(func->returnType);
	    FunctionType *FTy =  FunctionType::get(RetTy, argTypes,
							 false);
	    Functions[j] = Function::Create(FTy, Function::InternalLinkage, 
					   BytecodeID+"f"+Twine(j), M);
	    Functions[j]->setDoesNotThrow();
	}
	for (unsigned j=0;j<bc->num_func;j++) {
	    PrettyStackTraceString CrashInfo("Generate LLVM IR");
	    const struct cli_bc_func *func = &bc->funcs[j];
	    // Create all BasicBlocks
	    Function *F = Functions[j];
	    BasicBlock **BB = new BasicBlock*[func->numBB];
	    for (unsigned i=0;i<func->numBB;i++) {
		BB[i] = BasicBlock::Create(Context, "", F);
	    }

	    BasicBlock *Fail = 0;
	    Values = new Value*[func->numValues];
	    Builder.SetInsertPoint(BB[0]);
	    Function::arg_iterator I = F->arg_begin();
	    for (unsigned i=0;i<func->numArgs; i++) {
		assert(I != F->arg_end());
		Values[i] = &*I;
		++I;
	    }
	    for (unsigned i=func->numArgs;i<func->numValues;i++) {
		Values[i] = Builder.CreateAlloca(mapType(func->types[i]));
	    }
	    numLocals = func->numLocals;
	    numArgs = func->numArgs;
	    // Generate LLVM IR for each BB
	    for (unsigned i=0;i<func->numBB;i++) {
		const struct cli_bc_bb *bb = &func->BB[i];
		Builder.SetInsertPoint(BB[i]);
		for (unsigned j=0;j<bb->numInsts;j++) {
		    const struct cli_bc_inst *inst = &bb->insts[j];
		    Value *Op0, *Op1, *Op2;
		    // libclamav has already validated this.
		    assert(inst->opcode < OP_INVALID && "Invalid opcode");
		    switch (inst->opcode) {
			case OP_JMP:
			case OP_BRANCH:
			case OP_CALL_API:
			case OP_CALL_DIRECT:
			case OP_ZEXT:
			case OP_SEXT:
			case OP_TRUNC:
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
				    break;
				case 3:
				    Op0 = convertOperand(func, inst, inst->u.three[0]);
				    Op1 = convertOperand(func, inst, inst->u.three[1]);
				    Op2 = convertOperand(func, inst, inst->u.three[2]);
				    break;
			    }
		    }

		    switch (inst->opcode) {
			case OP_ADD:
			    Store(inst->dest, Builder.CreateAdd(Op0, Op1));
			    break;
			case OP_SUB:
			    Store(inst->dest, Builder.CreateSub(Op0, Op1));
			    break;
			case OP_MUL:
			    Store(inst->dest, Builder.CreateMul(Op0, Op1));
			    break;
			case OP_UDIV:
			{
			    Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
			    InsertVerify(Bad, Fail, FHandler, F);
			    Store(inst->dest, Builder.CreateUDiv(Op0, Op1));
			    break;
			}
			case OP_SDIV:
			{
			    //TODO: also verify Op0 == -1 && Op1 = INT_MIN
			    Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
			    InsertVerify(Bad, Fail, FHandler, F);
			    Store(inst->dest, Builder.CreateSDiv(Op0, Op1));
			    break;
			}
			case OP_UREM:
			{
			    Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
			    InsertVerify(Bad, Fail, FHandler, F);
			    Store(inst->dest, Builder.CreateURem(Op0, Op1));
			    break;
			}
			case OP_SREM:
			{
			    //TODO: also verify Op0 == -1 && Op1 = INT_MIN
			    Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
			    InsertVerify(Bad, Fail, FHandler, F);
			    Store(inst->dest, Builder.CreateSRem(Op0, Op1));
			    break;
			}
			case OP_SHL:
			    Store(inst->dest, Builder.CreateShl(Op0, Op1));
			    break;
			case OP_LSHR:
			    Store(inst->dest, Builder.CreateLShr(Op0, Op1));
			    break;
			case OP_ASHR:
			    Store(inst->dest, Builder.CreateAShr(Op0, Op1));
			    break;
			case OP_AND:
			    Store(inst->dest, Builder.CreateAnd(Op0, Op1));
			    break;
			case OP_OR:
			    Store(inst->dest, Builder.CreateOr(Op0, Op1));
			    break;
			case OP_XOR:
			    Store(inst->dest, Builder.CreateXor(Op0, Op1));
			    break;
			case OP_TRUNC:
			{
			    Value *Src = convertOperand(func, inst, inst->u.cast.source);
			    const Type *Ty = mapType(func->types[inst->dest]);
			    Store(inst->dest, Builder.CreateTrunc(Src,  Ty));
			    break;
			}
			case OP_ZEXT:
			{
			    Value *Src = convertOperand(func, inst, inst->u.cast.source);
			    const Type *Ty = mapType(func->types[inst->dest]);
			    Store(inst->dest, Builder.CreateZExt(Src,  Ty));
			    break;
			}
			case OP_SEXT:
			{
			    Value *Src = convertOperand(func, inst, inst->u.cast.source);
			    const Type *Ty = mapType(func->types[inst->dest]);
			    Store(inst->dest, Builder.CreateSExt(Src,  Ty));
			    break;
			}
			case OP_BRANCH:
			{
			    Value *Cond = convertOperand(func, inst, inst->u.branch.condition);
			    BasicBlock *True = BB[inst->u.branch.br_true];
			    BasicBlock *False = BB[inst->u.branch.br_false];
			    if (Cond->getType() != Type::getInt1Ty(Context)) {
				errs() << MODULE << "type mismatch in condition\n";
				return false;
			    }
			    Builder.CreateCondBr(Cond, True, False);
			    break;
			}
			case OP_JMP:
			{
			    BasicBlock *Jmp = BB[inst->u.jump];
			    Builder.CreateBr(Jmp);
			    break;
			}
			case OP_RET:
			    Builder.CreateRet(Op0);
			    break;
			case OP_ICMP_EQ:
			    Store(inst->dest, Builder.CreateICmpEQ(Op0, Op1));
			    break;
			case OP_ICMP_NE:
			    Store(inst->dest, Builder.CreateICmpNE(Op0, Op1));
			    break;
			case OP_ICMP_UGT:
			    Store(inst->dest, Builder.CreateICmpUGT(Op0, Op1));
			    break;
			case OP_ICMP_UGE:
			    Store(inst->dest, Builder.CreateICmpUGE(Op0, Op1));
			    break;
			case OP_ICMP_ULT:
			    Store(inst->dest, Builder.CreateICmpULT(Op0, Op1));
			    break;
			case OP_ICMP_ULE:
			    Store(inst->dest, Builder.CreateICmpULE(Op0, Op1));
			    break;
			case OP_ICMP_SGT:
			    Store(inst->dest, Builder.CreateICmpSGT(Op0, Op1));
			    break;
			case OP_ICMP_SGE:
			    Store(inst->dest, Builder.CreateICmpSGE(Op0, Op1));
			    break;
			case OP_ICMP_SLT:
			    Store(inst->dest, Builder.CreateICmpSLT(Op0, Op1));
			    break;
			case OP_SELECT:
			    Store(inst->dest, Builder.CreateSelect(Op0, Op1, Op2));
			    break;
			case OP_COPY:
			    Builder.CreateStore(Op0, Op1);
			    break;
			case OP_CALL_DIRECT:
			{
			    Function *DestF = Functions[inst->u.ops.funcid];
			    SmallVector<Value*, 2> args;
			    for (unsigned a=0;a<inst->u.ops.numOps;a++) {
				operand_t op = inst->u.ops.ops[a];
				args.push_back(convertOperand(func, DestF->getFunctionType()->getParamType(a), op));
			    }
			    Store(inst->dest, Builder.CreateCall(DestF, args.begin(), args.end()));
			    break;
			}
			default:
			    errs() << "JIT doesn't implement opcode " <<
				inst->opcode << " yet!\n";
			    return false;
		    }
		}
	    }

	    if (verifyFunction(*F, PrintMessageAction)) {
		errs() << MODULE << "Verification failed\n";
		// verification failed
		return false;
	    }
	    PM.run(*F);
	    delete [] Values;
	    delete [] BB;
	}

	DEBUG(M->dump());
	delete [] TypeMap;
	FunctionType *Callable = FunctionType::get(Type::getInt32Ty(Context),false);
	for (unsigned j=0;j<bc->num_func;j++) {
	    const struct cli_bc_func *func = &bc->funcs[j];
	    PrettyStackTraceString CrashInfo2("Native machine codegen");
	    // Codegen current function as executable machine code.
	    void *code = EE->getPointerToFunction(Functions[j]);

	    // If prototype matches, add to callable functions
	    if (Functions[j]->getFunctionType() == Callable)
		compiledFunctions[func] = code;
	}
	delete [] Functions;
	return true;
    }
};
}

int cli_vm_execute_jit(const struct cli_all_bc *bcs, struct cli_bc_ctx *ctx,
		       const struct cli_bc_func *func)
{
    jmp_buf env;
    void *code = bcs->engine->compiledFunctions[func];
    if (!code) {
	errs() << MODULE << "Unable to find compiled function\n";
	return CL_EBYTECODE;
    }
    // execute;
    if (setjmp(env) == 0) {
	// setup exception handler to longjmp back here
	ExceptionReturn.set(&env);
	uint32_t result = ((uint32_t (*)(void))code)();
	*(uint32_t*)ctx->values = result;
	return 0;
    }
    errs() << "\n";
    errs().changeColor(raw_ostream::RED, true) << MODULE 
	<< "*** JITed code intercepted runtime error!\n";
    errs().resetColor();
    return CL_EBYTECODE;
}


int cli_bytecode_prepare_jit(struct cli_all_bc *bcs)
{
  if (!bcs->engine)
      return CL_EBYTECODE;
  jmp_buf env;
  // setup exception handler to longjmp back here
  ExceptionReturn.set(&env);  
  if (setjmp(env) != 0) {
      errs() << "\n";
      errs().changeColor(raw_ostream::RED, true) << MODULE 
      << "*** FATAL error encountered during bytecode generation\n";
      errs().resetColor();
      return CL_EBYTECODE;
  }
  // LLVM itself never throws exceptions, but operator new may throw bad_alloc
  try {
    Module *M = new Module("ClamAV jit module", bcs->engine->Context);
    ExistingModuleProvider *MP = new ExistingModuleProvider(M);
    {
	// Create the JIT.
	std::string ErrorMsg;
	EngineBuilder builder(MP);
	builder.setErrorStr(&ErrorMsg);
	builder.setEngineKind(EngineKind::JIT);
	builder.setOptLevel(CodeGenOpt::Aggressive);
	ExecutionEngine *EE = bcs->engine->EE = builder.create();
	if (!EE) {
	    if (!ErrorMsg.empty())
		errs() << MODULE << "error creating execution engine: " << ErrorMsg << "\n";
	    else
		errs() << MODULE << "JIT not registered?\n";
	    return CL_EBYTECODE;
	}

	EE->RegisterJITEventListener(createOProfileJITEventListener());
	// Due to LLVM PR4816 only X86 supports non-lazy compilation, disable
	// for now.
	// EE->DisableLazyCompilation();
	EE->DisableSymbolSearching();

	FunctionPassManager OurFPM(MP);
	// Set up the optimizer pipeline.  Start with registering info about how
	// the target lays out data structures.
	OurFPM.add(new TargetData(*EE->getTargetData()));
	// Promote allocas to registers.
	OurFPM.add(createPromoteMemoryToRegisterPass());
	OurFPM.doInitialization();
	for (unsigned i=0;i<bcs->count;i++) {
	    const struct cli_bc *bc = &bcs->all_bcs[i];
	    LLVMCodegen Codegen(bc, M, bcs->engine->compiledFunctions, EE, OurFPM);
	    if (!Codegen.generate()) {
		errs() << MODULE << "JIT codegen failed\n";
		return CL_EBYTECODE;
	    }
	}

	for (unsigned i=0;i<bcs->count;i++) {
	    bcs->all_bcs[i].state = bc_jit;
	}
	// compile all functions now, not lazily!
	for (Module::iterator I = M->begin(), E = M->end(); I != E; ++I) {
	    Function *Fn = &*I;
	    if (!Fn->isDeclaration())
		EE->getPointerToFunction(Fn);
	}
    }
    return -1;
  } catch (std::bad_alloc &badalloc) {
      errs() << MODULE << badalloc.what() << "\n";
      return CL_EMEM;
  } catch (...) {
      errs() << MODULE << "Unexpected unknown exception occurred.\n";
      return CL_EBYTECODE;
  }
}

int bytecode_init(void)
{
    llvm_install_error_handler(llvm_error_handler);
    sys::PrintStackTraceOnErrorSignal();
    atexit(do_shutdown);

    llvm_start_multithreaded();

    // If we have a native target, initialize it to ensure it is linked in and
    // usable by the JIT.
    InitializeNativeTarget();
    return 0;
}

// Called once when loading a new set of BC files
int cli_bytecode_init_jit(struct cli_all_bc *bcs)
{
    bcs->engine = new(std::nothrow) struct cli_bcengine;
    if (!bcs->engine)
	return CL_EMEM;
    return 0;
}

int cli_bytecode_done_jit(struct cli_all_bc *bcs)
{
    if (bcs->engine) {
	if (bcs->engine->EE)
	    delete bcs->engine->EE;
	delete bcs->engine;
	bcs->engine = 0;
    }
    return 0;
}

void cli_bytecode_debug(int argc, char **argv)
{
  cl::ParseCommandLineOptions(argc, argv);
}

int have_clamjit=1;
