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
#include "llvm/Support/DataTypes.h"
#include "llvm/System/Threading.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JIT.h"
#include "llvm/LLVMContext.h"
#include "llvm/System/Signals.h"
#include "llvm/Target/TargetSelect.h"
#include "llvm/Module.h"
#include "llvm/ModuleProvider.h"
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
    
    }

    void generateLLVM(const struct cli_bc *bc, Module *M, 
		      FunctionMapTy &compiledFunctions) {

	Type *TypeMap = new Type*[bc->num_types];

	for (unsigned j=0;j<bc->num_types;j++) {

	}

	for (unsigned j=0;j<bc->num_func;j++) {
	    const struct cli_bc_func *func = &bc->funcs[j];
	    std::vector<const Type*> argTypes;
	    for (unsigned a=0;a<func->numArgs;a++) {
		argTypes.push_back(mapType(func->types[a], TypeMap));
	    }
	}
	delete TypeMap;
    }

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
	    const struct cli_bc *bc = bcs->all_bcs[i];
	    generateLLVM(bc, M);
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
    bcs->engine = (struct cli_bcengine*) malloc(sizeof(struct cli_bcengine));
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
