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

#include "llvm/ADT/DenseMap.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Function.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JIT.h"
#include "llvm/ExecutionEngine/JITEventListener.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/ModuleProvider.h"
#include "llvm/Support/Compiler.h"
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
#include "llvm/Support/TargetFolder.h"
#include <cstdlib>
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

void do_shutdown() {
    llvm_shutdown();
}

void llvm_error_handler(void *user_data, const std::string &reason)
{
    errs() << reason;
    //TODO: better error handling, don't exit here
    exit(1);
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

    const Type *mapType(uint16_t ty)
    {
	if (!ty)
	    return Type::getVoidTy(Context);
	if (ty < 64)
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

    Value *convertOperand(const struct cli_bc_func *func, 
			  const struct cli_bc_inst *inst,  operand_t operand)
    {
	if (operand >= func->numValues) {
	    // Constant
	    operand -= func->numValues;
	    // This was already validated by libclamav.
	    assert(operand < func->numConstants && "Constant out of range");
	    uint64_t *c = &func->constants[operand-func->numValues];
	    uint64_t v;
	    const Type *Ty;
	    switch (inst->interp_op%5) {
		case 0:
		case 1:
		    Ty = (inst->interp_op%5) ? Type::getInt8Ty(Context) : 
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
	assert(0 && "Not implemented yet");
    }
public:
    LLVMCodegen(const struct cli_bc *bc, Module *M, FunctionMapTy &cFuncs,
		ExecutionEngine *EE)
	: bc(bc), M(M), Context(M->getContext()), compiledFunctions(cFuncs), 
	BytecodeID("bc"+Twine(bc->id)), EE(EE) {
	    TypeMap = new const Type*[bc->num_types];
    }

    void generate() {
	PrettyStackTraceString Trace(BytecodeID.str().c_str());
	convertTypes();
	TargetFolder Folder(EE->getTargetData(), Context);
	IRBuilder<false, TargetFolder> Builder(Context, Folder);
	for (unsigned j=0;j<bc->num_func;j++) {
	    PrettyStackTraceString CrashInfo("Generate LLVM IR");
	    // Create LLVM IR Function
	    const struct cli_bc_func *func = &bc->funcs[j];
	    std::vector<const Type*> argTypes;
	    for (unsigned a=0;a<func->numArgs;a++) {
		argTypes.push_back(mapType(func->types[a]));
	    }
	    const Type *RetTy = mapType(func->returnType);
	    llvm::FunctionType *FTy =  FunctionType::get(RetTy, argTypes,
							 false);
	    Function *F = Function::Create(FTy, Function::InternalLinkage, 
					   BytecodeID+"f"+Twine(j), M);

	    // Create all BasicBlocks
	    BasicBlock **BB = new BasicBlock*[func->numBB];
	    for (unsigned i=0;i<func->numBB;i++) {
		BB[i] = BasicBlock::Create(Context, "", F);
	    }

	    // Generate LLVM IR for each BB
	    for (unsigned i=0;i<func->numBB;i++) {
		const struct cli_bc_bb *bb = &func->BB[i];
		Builder.SetInsertPoint(BB[i]);
		for (unsigned j=0;j<bb->numInsts;j++) {
		    const struct cli_bc_inst *inst = &bb->insts[i];

		    switch (inst->opcode) {
			case OP_RET:
			    Value *V = convertOperand(func, inst, inst->u.unaryop);
			    Builder.CreateRet(V);
			    break;
		    }
		}
	    }

	    PrettyStackTraceString CrashInfo2("Native machine codegen");
	    // Codegen current function as executable machine code.
	    compiledFunctions[func] = EE->getPointerToFunction(F);
	}
	delete TypeMap;
    }
};
}

int cli_vm_execute_jit(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const struct cli_bc_func *func, const struct cli_bc_inst *inst)
{
    return 0;
}


int cli_bytecode_prepare_jit(struct cli_all_bc *bcs)
{
  // LLVM itself never throws exceptions, but operator new may throw bad_alloc
  try {
    Module *M = new Module("ClamAV jit module", bcs->engine->Context);
    {
	// Create the JIT.
	std::string ErrorMsg;
	EngineBuilder builder(M);
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
	EE->DisableLazyCompilation();

	for (unsigned i=0;i<bcs->count;i++) {
	    const struct cli_bc *bc = &bcs->all_bcs[i];
	    LLVMCodegen Codegen(bc, M, bcs->engine->compiledFunctions, EE);
	    Codegen.generate();
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
    if (bcs->engine->EE)
	delete bcs->engine->EE;
    free(bcs->engine);
    bcs->engine = 0;
    return 0;
}

void cli_bytecode_debug(int argc, char **argv)
{
  cl::ParseCommandLineOptions(argc, argv);
}
