/*
 *  JIT compile ClamAV bytecode.
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
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/CallingConv.h"
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
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/System/DataTypes.h"
#include "llvm/System/Mutex.h"
#include "llvm/System/Signals.h"
#include "llvm/System/Threading.h"
#include "llvm/Target/TargetSelect.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Support/TargetFolder.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/System/ThreadLocal.h"
#include <cstdlib>
#include <csetjmp>
#include <new>

#include "llvm/Config/config.h"
#if !defined(LLVM_MULTITHREADED) || !LLVM_MULTITHREADED
#error "Multithreading support must be available to LLVM!"
#endif

#ifdef HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "clamav-config.h"
#endif
#include "clamav.h"
#include "clambc.h"
#include "bytecode.h"
#include "bytecode_priv.h"
#include "type_desc.h"

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
static sys::ThreadLocal<const jmp_buf> MatchCounts;

void do_shutdown() {
    llvm_shutdown();
}

static void NORETURN jit_exception_handler(void)
{
    longjmp(*const_cast<jmp_buf*>(ExceptionReturn.get()), 1);
}

void llvm_error_handler(void *user_data, const std::string &reason)
{
    // Output it to stderr, it might exceed the 1k/4k limit of cli_errmsg
    errs() << MODULE << reason;
    jit_exception_handler();
}

class LLVMTypeMapper {
private:
    std::vector<PATypeHolder> TypeMap;
    LLVMContext &Context;
    unsigned numTypes;
    const Type *getStatic(uint16_t ty)
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
    LLVMTypeMapper(LLVMContext &Context, const struct cli_bc_type *types,
		   unsigned count, const Type *Hidden=0) : Context(Context), numTypes(count)
    {
	TypeMap.reserve(count);
	// During recursive type construction pointers to Type* may be
	// invalidated, so we must use a TypeHolder to an Opaque type as a
	// start.
	for (unsigned i=0;i<count;i++) {
	    TypeMap.push_back(OpaqueType::get(Context));
	}
	std::vector<const Type*> Elts;
	for (unsigned i=0;i<count;i++) {
	    const struct cli_bc_type *type = &types[i];
	    Elts.clear();
	    unsigned n = type->kind == DArrayType ? 1 : type->numElements;
	    for (unsigned j=0;j<n;j++) {
		Elts.push_back(get(type->containedTypes[j]));
	    }
	    const Type *Ty;
	    switch (type->kind) {
		case DFunctionType:
		{
		    assert(Elts.size() > 0 && "Function with no return type?");
		    const Type *RetTy = Elts[0];
		    if (Hidden)
			Elts[0] = Hidden;
		    else
			Elts.erase(Elts.begin());
		    Ty = FunctionType::get(RetTy, Elts, false);
		    break;
		}
		case DPointerType:
		    Ty = PointerType::getUnqual(Elts[0]);
		    break;
		case DStructType:
		    Ty = StructType::get(Context, Elts);
		    break;
		case DPackedStructType:
		    Ty = StructType::get(Context, Elts, true);
		    break;
		case DArrayType:
		    Ty = ArrayType::get(Elts[0], type->numElements);
		    break;
		default:
		    llvm_unreachable("type->kind");
	    }
	    // Make the opaque type a concrete type, doing recursive type
	    // unification if needed.
	    cast<OpaqueType>(TypeMap[i].get())->refineAbstractTypeTo(Ty);
	}
    }

    const Type *get(uint16_t ty)
    {
	ty &= 0x7fff;
	if (ty < 69)
	    return getStatic(ty);
	ty -= 69;
	assert(ty < numTypes && "TypeID out of range");
	return TypeMap[ty].get();
    }
};


class VISIBILITY_HIDDEN LLVMCodegen {
private:
    const struct cli_bc *bc;
    Module *M;
    LLVMContext &Context;
    ExecutionEngine *EE;
    FunctionPassManager &PM;
    LLVMTypeMapper *TypeMap;

    Function **apiFuncs;
    LLVMTypeMapper &apiMap;
    FunctionMapTy &compiledFunctions;
    Twine BytecodeID;

    TargetFolder Folder;
    IRBuilder<false, TargetFolder> Builder;

    std::vector<Value*> globals;
    DenseMap<unsigned, unsigned> GVoffsetMap;
    DenseMap<unsigned, const Type*> GVtypeMap;
    Value **Values;
    unsigned numLocals;
    unsigned numArgs;
    std::vector<MDNode*> mdnodes;

    Value *getOperand(const struct cli_bc_func *func, const Type *Ty, operand_t operand)
    {
	unsigned map[] = {0, 1, 2, 3, 3, 4, 4, 4, 4};
	if (operand < func->numValues)
	    return Values[operand];
	unsigned w = (Ty->getPrimitiveSizeInBits()+7)/8;
	return convertOperand(func, map[w], operand);
    }

    Value *convertOperand(const struct cli_bc_func *func, const Type *Ty, operand_t operand)
    {
	unsigned map[] = {0, 1, 2, 3, 3, 4, 4, 4, 4};
	if (operand < func->numArgs)
	    return Values[operand];
	if (operand < func->numValues) {
	    Value *V = Values[operand];
	    if (func->types[operand]&0x8000 && V->getType() == Ty) {
		return V;
	    }
	    V = Builder.CreateLoad(V);
	    if (V->getType() != Ty &&
		isa<PointerType>(V->getType()) &&
		isa<PointerType>(Ty))
		V = Builder.CreateBitCast(V, Ty);
	    if (V->getType() != Ty) {
		errs() << operand << " ";
		V->dump();
		Ty->dump();
		llvm_report_error("(libclamav) Type mismatch converting operand");
	    }
	    return V;
	}
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
	if (operand < func->numValues) {
	    if (func->types[operand]&0x8000)
		return Values[operand];
	    return Builder.CreateLoad(Values[operand]);
	}

	if (operand & 0x80000000) {
	    operand &= 0x7fffffff;
	    assert(operand < globals.size() && "Global index out of range");
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
	    default:
		llvm_unreachable("width");
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

    const Type* mapType(uint16_t typeID)
    {
	return TypeMap->get(typeID&0x7fffffff);
    }

    Constant *buildConstant(const Type *Ty, uint64_t *components, unsigned &c)
    {
        if (const PointerType *PTy = dyn_cast<PointerType>(Ty)) {
          Value *idxs[2] = {
	      ConstantInt::get(Type::getInt32Ty(Context), 0),
	      ConstantInt::get(Type::getInt32Ty(Context), components[c++])
	  };
	  unsigned idx = components[c++];
	  if (!idx)
	      return ConstantPointerNull::get(PTy);
	  assert(idx < globals.size());
	  GlobalVariable *GV = cast<GlobalVariable>(globals[idx]);
	  const Type *GTy = GetElementPtrInst::getIndexedType(GV->getType(), idxs, 2);
	  if (!GTy) {
	      errs() << "Type mismatch for GEP: " << *PTy->getElementType() <<
		  "; base is " << *GV << "\n";
	      llvm_report_error("(libclamav) Type mismatch converting constant");
	  }
	  return ConstantExpr::getPointerCast(
	      ConstantExpr::getInBoundsGetElementPtr(GV, idxs, 2),
	      PTy);
        }
	if (isa<IntegerType>(Ty)) {
	    return ConstantInt::get(Ty, components[c++]);
	}
	if (const ArrayType *ATy = dyn_cast<ArrayType>(Ty)) {
	   std::vector<Constant*> elements;
	   elements.reserve(ATy->getNumElements());
	   for (unsigned i=0;i<ATy->getNumElements();i++) {
	       elements.push_back(buildConstant(ATy->getElementType(), components, c));
	   }
	   return ConstantArray::get(ATy, elements);
	}
	if (const StructType *STy = dyn_cast<StructType>(Ty)) {
	   std::vector<Constant*> elements;
	   elements.reserve(STy->getNumElements());
	   for (unsigned i=0;i<STy->getNumElements();i++) {
	       elements.push_back(buildConstant(STy->getElementType(i), components, c));
	   }
	   return ConstantStruct::get(STy, elements);
	}
	Ty->dump();
	llvm_unreachable("invalid type");
	return 0;
    }


public:
    LLVMCodegen(const struct cli_bc *bc, Module *M, FunctionMapTy &cFuncs,
		ExecutionEngine *EE, FunctionPassManager &PM,
		Function **apiFuncs, LLVMTypeMapper &apiMap)
	: bc(bc), M(M), Context(M->getContext()), EE(EE),
	PM(PM), apiFuncs(apiFuncs),apiMap(apiMap),
	compiledFunctions(cFuncs), BytecodeID("bc"+Twine(bc->id)),
	Folder(EE->getTargetData()), Builder(Context, Folder) {

	for (unsigned i=0;i<cli_apicall_maxglobal - _FIRST_GLOBAL;i++) {
	    unsigned id = cli_globals[i].globalid;
	    GVoffsetMap[id] = cli_globals[i].offset;
	}
    }

    template <typename InputIterator>
    Value* createGEP(Value *Base, const Type *ETy, InputIterator Start, InputIterator End) {
	const Type *Ty = GetElementPtrInst::getIndexedType(Base->getType(), Start, End);
	if (!Ty || (ETy && (Ty != ETy && (!isa<IntegerType>(Ty) || !isa<IntegerType>(ETy))))) {
	    errs() << MODULE << "Wrong indices for GEP opcode: "
		<< " expected type: " << *ETy;
	    if (Ty)
		errs() << " actual type: " << *Ty;
	    errs() << " base: " << *Base << " indices: ";
	    for (InputIterator I=Start; I != End; I++) {
		errs() << **I << ", ";
	    }
	    errs() << "\n";
	    return 0;
	}
	return Builder.CreateGEP(Base, Start, End);
    }

    template <typename InputIterator>
    bool createGEP(unsigned dest, Value *Base, InputIterator Start, InputIterator End) {
	assert(dest >= numArgs && dest < numLocals+numArgs && "Instruction destination out of range");
	const Type *ETy = cast<PointerType>(cast<PointerType>(Values[dest]->getType())->getElementType())->getElementType();
	Value *V = createGEP(Base, ETy, Start, End);
	if (!V) {
	    errs() << "@ " << dest << "\n";
	    return false;
	}
	V = Builder.CreateBitCast(V, PointerType::getUnqual(ETy));
	Store(dest, V);
	return true;
    }

    MDNode *convertMDNode(unsigned i) {
	if (i < mdnodes.size()) {
	    if (mdnodes[i])
		return mdnodes[i];
	} else 
	    mdnodes.resize(i+1);
	assert(i < mdnodes.size());
	const struct cli_bc_dbgnode *node = &bc->dbgnodes[i];
	Value **Vals = new Value*[node->numelements];
	for (unsigned j=0;j<node->numelements;j++) {
	    const struct cli_bc_dbgnode_element* el = &node->elements[j];
	    Value *V;
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
		V = ConstantInt::get(IntegerType::get(Context, el->len),
				     el->constant);
	    }
	    Vals[j] = V;
	}
	MDNode *N = MDNode::get(Context, Vals, node->numelements);
	delete[] Vals;
	mdnodes[i] = N;
	return N;
    }

    bool generate() {
	TypeMap = new LLVMTypeMapper(Context, bc->types + 4, bc->num_types - 5);
	for (unsigned i=0;i<bc->dbgnode_cnt;i++) {
	    mdnodes.push_back(convertMDNode(i));
	}

	for (unsigned i=0;i<cli_apicall_maxglobal - _FIRST_GLOBAL;i++) {
	    unsigned id = cli_globals[i].globalid;
	    const Type *Ty = apiMap.get(cli_globals[i].type);
	    /*if (const ArrayType *ATy = dyn_cast<ArrayType>(Ty))
		Ty = PointerType::getUnqual(ATy->getElementType());*/
	    GVtypeMap[id] = Ty;
	}
	FunctionType *FTy = FunctionType::get(Type::getVoidTy(Context),
						    false);
	Function *FHandler = Function::Create(FTy, Function::InternalLinkage,
					      "clamjit.fail", M);
	FHandler->setDoesNotReturn();
	FHandler->setDoesNotThrow();
	FHandler->addFnAttr(Attribute::NoInline);
	EE->addGlobalMapping(FHandler, (void*)(intptr_t)jit_exception_handler);

	std::vector<const Type*> args;
	args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
	args.push_back(Type::getInt8Ty(Context));
	args.push_back(Type::getInt32Ty(Context));
	args.push_back(Type::getInt32Ty(Context));
	FunctionType* FuncTy_3 = FunctionType::get(Type::getVoidTy(Context),
						   args, false);
	Function *FMemset = Function::Create(FuncTy_3, GlobalValue::ExternalLinkage,
					     "llvm.memset.i32", M);
	FMemset->setDoesNotThrow();
	FMemset->setDoesNotCapture(1, true);

	args.clear();
	args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
	args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
	args.push_back(Type::getInt32Ty(Context));
	args.push_back(Type::getInt32Ty(Context));
	FunctionType* FuncTy_4 = FunctionType::get(Type::getVoidTy(Context),
						   args, false);
	Function *FMemmove = Function::Create(FuncTy_4, GlobalValue::ExternalLinkage,
					     "llvm.memmove.i32", M);
	FMemmove->setDoesNotThrow();
	FMemmove->setDoesNotCapture(1, true);

	Function *FMemcpy = Function::Create(FuncTy_4, GlobalValue::ExternalLinkage,
					     "llvm.memcpy.i32", M);
	FMemcpy->setDoesNotThrow();
	FMemcpy->setDoesNotCapture(1, true);

	FunctionType* DummyTy = FunctionType::get(Type::getVoidTy(Context), false);
	Function *FRealMemset = Function::Create(DummyTy, GlobalValue::ExternalLinkage,
						 "memset", M);
	EE->addGlobalMapping(FRealMemset, (void*)(intptr_t)memset);
	Function *FRealMemmove = Function::Create(DummyTy, GlobalValue::ExternalLinkage,
						 "memmove", M);
	EE->addGlobalMapping(FRealMemmove, (void*)(intptr_t)memmove);
	Function *FRealMemcpy = Function::Create(DummyTy, GlobalValue::ExternalLinkage,
						 "memcpy", M);
	EE->addGlobalMapping(FRealMemcpy, (void*)(intptr_t)memcpy);

	args.clear();
	args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
	args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
	args.push_back(EE->getTargetData()->getIntPtrType(Context));
	FunctionType* FuncTy_5 = FunctionType::get(Type::getInt32Ty(Context),
						   args, false);
	Function* FRealMemcmp = Function::Create(FuncTy_5, GlobalValue::ExternalLinkage, "memcmp", M);
	EE->addGlobalMapping(FRealMemcmp, (void*)(intptr_t)memcmp);

	// The hidden ctx param to all functions
	const Type *HiddenCtx = PointerType::getUnqual(Type::getInt8Ty(Context));

	globals.reserve(bc->num_globals);
	BitVector FakeGVs;
	FakeGVs.resize(bc->num_globals);
	globals.push_back(0);
	for (unsigned i=1;i<bc->num_globals;i++) {
	    const Type *Ty = mapType(bc->globaltys[i]);

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
				    C, "glob"+Twine(i));
	    globals.push_back(GV);
	}

	Function **Functions = new Function*[bc->num_func];
	for (unsigned j=0;j<bc->num_func;j++) {
	    PrettyStackTraceString CrashInfo("Generate LLVM IR functions");
	    // Create LLVM IR Function
	    const struct cli_bc_func *func = &bc->funcs[j];
	    std::vector<const Type*> argTypes;
	    argTypes.push_back(HiddenCtx);
	    for (unsigned a=0;a<func->numArgs;a++) {
		argTypes.push_back(mapType(func->types[a]));
	    }
	    const Type *RetTy = mapType(func->returnType);
	    FunctionType *FTy =  FunctionType::get(RetTy, argTypes,
							 false);
	    Functions[j] = Function::Create(FTy, Function::InternalLinkage,
					   BytecodeID+"f"+Twine(j), M);
	    Functions[j]->setDoesNotThrow();
	    Functions[j]->setCallingConv(CallingConv::Fast);
	}
	const Type *I32Ty = Type::getInt32Ty(Context);
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
	    assert(F->arg_size() == (unsigned)(func->numArgs + 1) && "Mismatched args");
	    ++I;
	    for (unsigned i=0;i<func->numArgs; i++) {
		assert(I != F->arg_end());
		Values[i] = &*I;
		++I;
	    }
	    for (unsigned i=func->numArgs;i<func->numValues;i++) {
		if (!func->types[i]) {
		    //instructions without return value, like store
		    Values[i] = 0;
		    continue;
		}
		Values[i] = Builder.CreateAlloca(mapType(func->types[i]));
	    }
	    numLocals = func->numLocals;
	    numArgs = func->numArgs;

	    if (FakeGVs.any()) {
		Argument *Ctx = F->arg_begin();
		for (unsigned i=0;i<bc->num_globals;i++) {
		    if (!FakeGVs[i])
			continue;
		    unsigned g = bc->globals[i][1];
		    unsigned offset = GVoffsetMap[g];
		    Constant *Idx = ConstantInt::get(Type::getInt32Ty(Context),
						     offset);
		    Value *GEP = Builder.CreateInBoundsGEP(Ctx, Idx);
		    const Type *Ty = GVtypeMap[g];
		    Ty = PointerType::getUnqual(PointerType::getUnqual(Ty));
		    Value *Cast = Builder.CreateBitCast(GEP, Ty);
		    Value *SpecialGV = Builder.CreateLoad(Cast);
		    SpecialGV->setName("g"+Twine(g-_FIRST_GLOBAL)+"_");
		    Value *C[] = {
			ConstantInt::get(Type::getInt32Ty(Context), 0),
			ConstantInt::get(Type::getInt32Ty(Context), bc->globals[i][0])
		    };
		    globals[i] = createGEP(SpecialGV, 0, C, C+2);
		    if (!globals[i]) {
			errs() << i << ":" << g << ":" << bc->globals[i][0] <<"\n";
			Ty->dump();
			llvm_report_error("(libclamav) unable to create fake global");
		    }
		    else if(GetElementPtrInst *GI = dyn_cast<GetElementPtrInst>(globals[i])) {
			GI->setIsInBounds(true);
			GI->setName("geped"+Twine(i)+"_");
		    }
		}
	    }

	    // Generate LLVM IR for each BB
	    for (unsigned i=0;i<func->numBB;i++) {
		bool unreachable = false;
		const struct cli_bc_bb *bb = &func->BB[i];
		Builder.SetInsertPoint(BB[i]);
		unsigned c = 0;
		for (unsigned j=0;j<bb->numInsts;j++) {
		    const struct cli_bc_inst *inst = &bb->insts[j];
		    Value *Op0, *Op1, *Op2;
		    // libclamav has already validated this.
		    assert(inst->opcode < OP_BC_INVALID && "Invalid opcode");
		    if (func->dbgnodes) {
			if (func->dbgnodes[c] != ~0u) {
			unsigned j = func->dbgnodes[c];
			assert(j < mdnodes.size());
			Builder.SetCurrentDebugLocation(mdnodes[j]);
			} else
			    Builder.SetCurrentDebugLocation(0);
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
			case OP_BC_GEPN:
			case OP_BC_STORE:
			case OP_BC_COPY:
			case OP_BC_RET:
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
					Op0->dump();
					Op1->dump();
					llvm_report_error("(libclamav) binop type mismatch");
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
			case OP_BC_UDIV:
			{
			    Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
			    InsertVerify(Bad, Fail, FHandler, F);
			    Store(inst->dest, Builder.CreateUDiv(Op0, Op1));
			    break;
			}
			case OP_BC_SDIV:
			{
			    //TODO: also verify Op0 == -1 && Op1 = INT_MIN
			    Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
			    InsertVerify(Bad, Fail, FHandler, F);
			    Store(inst->dest, Builder.CreateSDiv(Op0, Op1));
			    break;
			}
			case OP_BC_UREM:
			{
			    Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
			    InsertVerify(Bad, Fail, FHandler, F);
			    Store(inst->dest, Builder.CreateURem(Op0, Op1));
			    break;
			}
			case OP_BC_SREM:
			{
			    //TODO: also verify Op0 == -1 && Op1 = INT_MIN
			    Value *Bad = Builder.CreateICmpEQ(Op1, ConstantInt::get(Op1->getType(), 0));
			    InsertVerify(Bad, Fail, FHandler, F);
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
			case OP_BC_TRUNC:
			{
			    Value *Src = convertOperand(func, inst, inst->u.cast.source);
			    const Type *Ty = mapType(func->types[inst->dest]);
			    Store(inst->dest, Builder.CreateTrunc(Src,  Ty));
			    break;
			}
			case OP_BC_ZEXT:
			{
			    Value *Src = convertOperand(func, inst, inst->u.cast.source);
			    const Type *Ty = mapType(func->types[inst->dest]);
			    Store(inst->dest, Builder.CreateZExt(Src,  Ty));
			    break;
			}
			case OP_BC_SEXT:
			{
			    Value *Src = convertOperand(func, inst, inst->u.cast.source);
			    const Type *Ty = mapType(func->types[inst->dest]);
			    Store(inst->dest, Builder.CreateSExt(Src,  Ty));
			    break;
			}
			case OP_BC_BRANCH:
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
			case OP_BC_JMP:
			{
			    BasicBlock *Jmp = BB[inst->u.jump];
			    Builder.CreateBr(Jmp);
			    break;
			}
			case OP_BC_RET:
			{
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
			case OP_BC_SELECT:
			    Store(inst->dest, Builder.CreateSelect(Op0, Op1, Op2));
			    break;
			case OP_BC_COPY:
			{
			    Value *Dest = Values[inst->u.binop[1]];
			    const PointerType *PTy = cast<PointerType>(Dest->getType());
			    Op0 = convertOperand(func, PTy->getElementType(), inst->u.binop[0]);
			    Builder.CreateStore(Op0, Dest);
			    break;
			}
			case OP_BC_CALL_DIRECT:
			{
			    Function *DestF = Functions[inst->u.ops.funcid];
			    SmallVector<Value*, 2> args;
			    args.push_back(&*F->arg_begin()); // pass hidden arg
			    for (unsigned a=0;a<inst->u.ops.numOps;a++) {
				operand_t op = inst->u.ops.ops[a];
				args.push_back(convertOperand(func, DestF->getFunctionType()->getParamType(a+1), op));
			    }
			    CallInst *CI = Builder.CreateCall(DestF, args.begin(), args.end());
			    CI->setCallingConv(CallingConv::Fast);
			    if (CI->getType()->getTypeID() != Type::VoidTyID)
				Store(inst->dest, CI);
			    break;
			}
			case OP_BC_CALL_API:
			{
			    assert(inst->u.ops.funcid < cli_apicall_maxapi && "APICall out of range");
			    std::vector<Value*> args;
			    Function *DestF = apiFuncs[inst->u.ops.funcid];
			    args.push_back(&*F->arg_begin()); // pass hidden arg
			    for (unsigned a=0;a<inst->u.ops.numOps;a++) {
				operand_t op = inst->u.ops.ops[a];
				args.push_back(convertOperand(func, DestF->getFunctionType()->getParamType(a+1), op));
			    }
			    Store(inst->dest, Builder.CreateCall(DestF, args.begin(), args.end()));
			    break;
			}
			case OP_BC_GEP1:
			{
			    const Type *SrcTy = mapType(inst->u.three[0]);
			    Value *V = convertOperand(func, SrcTy, inst->u.three[1]);
			    Value *Op = convertOperand(func, I32Ty, inst->u.three[2]);
			    if (!createGEP(inst->dest, V, &Op, &Op+1))
				return false;
			    break;
			}
			case OP_BC_GEPN:
			{
			    std::vector<Value*> Idxs;
			    assert(inst->u.ops.numOps > 2);
			    const Type *SrcTy = mapType(inst->u.ops.ops[0]);
			    Value *V = convertOperand(func, SrcTy, inst->u.ops.ops[1]);
			    for (unsigned a=2;a<inst->u.ops.numOps;a++)
				Idxs.push_back(convertOperand(func, I32Ty, inst->u.ops.ops[a]));
			    if (!createGEP(inst->dest, V, Idxs.begin(), Idxs.end()))
				return false;
			    break;
			}
			case OP_BC_STORE:
			{
			    Value *Dest = convertOperand(func, inst, inst->u.binop[1]);
			    Value *V = convertOperand(func, inst, inst->u.binop[0]);
			    const Type *VPTy = PointerType::getUnqual(V->getType());
			    if (VPTy != Dest->getType())
				Dest = Builder.CreateBitCast(Dest, VPTy);
			    Builder.CreateStore(V, Dest);
			    break;
			}
			case OP_BC_LOAD:
			{
			    Op0 = Builder.CreateBitCast(Op0,
							Values[inst->dest]->getType());
			    Op0 = Builder.CreateLoad(Op0);
			    Store(inst->dest, Op0);
			    break;
			}
			case OP_BC_MEMSET:
			{
			    Value *Dst = convertOperand(func, inst, inst->u.three[0]);
			    Value *Val = convertOperand(func, Type::getInt8Ty(Context), inst->u.three[1]);
			    Value *Len = convertOperand(func, Type::getInt32Ty(Context), inst->u.three[2]);
			    CallInst *c = Builder.CreateCall4(FMemset, Dst, Val, Len,
								ConstantInt::get(Type::getInt32Ty(Context), 1));
			    c->setTailCall(true);
			    c->setDoesNotThrow();
			    break;
			}
			case OP_BC_MEMCPY:
			{
			    Value *Dst = convertOperand(func, inst, inst->u.three[0]);
			    Value *Src = convertOperand(func, inst, inst->u.three[1]);
			    Value *Len = convertOperand(func, Type::getInt32Ty(Context), inst->u.three[2]);
			    CallInst *c = Builder.CreateCall4(FMemcpy, Dst, Src, Len,
								ConstantInt::get(Type::getInt32Ty(Context), 1));
			    c->setTailCall(true);
			    c->setDoesNotThrow();
			    break;
			}
			case OP_BC_MEMMOVE:
			{
			    Value *Dst = convertOperand(func, inst, inst->u.three[0]);
			    Value *Src = convertOperand(func, inst, inst->u.three[1]);
			    Value *Len = convertOperand(func, Type::getInt32Ty(Context), inst->u.three[2]);
			    CallInst *c = Builder.CreateCall4(FMemmove, Dst, Src, Len,
								ConstantInt::get(Type::getInt32Ty(Context), 1));
			    c->setTailCall(true);
			    c->setDoesNotThrow();
			    break;
			}
			case OP_BC_MEMCMP:
			{
			    Value *Dst = convertOperand(func, inst, inst->u.three[0]);
			    Value *Src = convertOperand(func, inst, inst->u.three[1]);
			    Value *Len = convertOperand(func, EE->getTargetData()->getIntPtrType(Context), inst->u.three[2]);
			    CallInst *c = Builder.CreateCall3(FRealMemcmp, Dst, Src, Len);
			    c->setTailCall(true);
			    c->setDoesNotThrow();
			    Store(inst->dest, c);
			    break;
			}
			case OP_BC_ISBIGENDIAN:
			    Store(inst->dest, WORDS_BIGENDIAN ?
				  ConstantInt::getTrue(Context) :
				  ConstantInt::getFalse(Context));
			    break;
			case OP_BC_ABORT:
			    if (!unreachable) {
				CallInst *CI = Builder.CreateCall(FHandler);
				CI->setDoesNotReturn();
				CI->setDoesNotThrow();
				Builder.CreateUnreachable();
				unreachable = true;
			    }
			    break;
			default:
			    errs() << MODULE << "JIT doesn't implement opcode " <<
				inst->opcode << " yet!\n";
			    return false;
		    }
		}
	    }

	    if (verifyFunction(*F, PrintMessageAction)) {
		errs() << MODULE << "Verification failed\n";
		F->dump();
		// verification failed
		return false;
	    }
	    PM.run(*F);
	    delete [] Values;
	    delete [] BB;
	}

	DEBUG(M->dump());
	delete TypeMap;
	args.clear();
	args.push_back(PointerType::getUnqual(Type::getInt8Ty(Context)));
	FunctionType *Callable = FunctionType::get(Type::getInt32Ty(Context),
						   args, false);
	for (unsigned j=0;j<bc->num_func;j++) {
	    const struct cli_bc_func *func = &bc->funcs[j];
	    PrettyStackTraceString CrashInfo2("Native machine codegen");

	    // If prototype matches, add to callable functions
	    if (Functions[j]->getFunctionType() == Callable) {
		// All functions have the Fast calling convention, however
		// entrypoint can only be C, emit wrapper
		Function *F = Function::Create(Functions[j]->getFunctionType(),
					       Function::ExternalLinkage,
					       Functions[j]->getName()+"_wrap", M);
		F->setDoesNotThrow();
		BasicBlock *BB = BasicBlock::Create(Context, "", F);
		std::vector<Value*> args;
		for (Function::arg_iterator J=F->arg_begin(),
		     JE=F->arg_end(); J != JE; ++JE) {
		    args.push_back(&*J);
		}
		CallInst *CI = CallInst::Create(Functions[j], args.begin(), args.end(), "", BB);
		CI->setCallingConv(CallingConv::Fast);
		ReturnInst::Create(Context, CI, BB);

		if (verifyFunction(*F, PrintMessageAction) == 0) {
			// Codegen current function as executable machine code.
			void *code = EE->getPointerToFunction(F);

			compiledFunctions[func] = code;
		}
	  }
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
	if (func->numArgs)
	    errs() << MODULE << "Function has "
		<< (unsigned)func->numArgs << " arguments, it must have 0 to be called as entrypoint\n";
	return CL_EBYTECODE;
    }
    // execute;
    if (setjmp(env) == 0) {
	// setup exception handler to longjmp back here
	ExceptionReturn.set((const jmp_buf*)&env);
	uint32_t result = ((uint32_t (*)(struct cli_bc_ctx *))(intptr_t)code)(ctx);
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
  ExceptionReturn.set((const jmp_buf*)&env);
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

//	EE->RegisterJITEventListener(createOProfileJITEventListener());
	// Due to LLVM PR4816 only X86 supports non-lazy compilation, disable
	// for now.
	EE->DisableLazyCompilation();
	EE->DisableSymbolSearching();

	FunctionPassManager OurFPM(MP);
	// Set up the optimizer pipeline.  Start with registering info about how
	// the target lays out data structures.
	OurFPM.add(new TargetData(*EE->getTargetData()));
	// Promote allocas to registers.
	OurFPM.add(createPromoteMemoryToRegisterPass());
	OurFPM.doInitialization();

	//TODO: create a wrapper that calls pthread_getspecific
	const Type *HiddenCtx = PointerType::getUnqual(Type::getInt8Ty(bcs->engine->Context));

	LLVMTypeMapper apiMap(bcs->engine->Context, cli_apicall_types, cli_apicall_maxtypes, HiddenCtx);
	Function **apiFuncs = new Function *[cli_apicall_maxapi];
	for (unsigned i=0;i<cli_apicall_maxapi;i++) {
	    const struct cli_apicall *api = &cli_apicalls[i];
	    const FunctionType *FTy = cast<FunctionType>(apiMap.get(69+api->type));
	    Function *F = Function::Create(FTy, Function::ExternalLinkage,
					   api->name, M);
	    void *dest;
	    switch (api->kind) {
		case 0:
		    dest = (void*)(intptr_t)cli_apicalls0[api->idx];
		    break;
		case 1:
		    dest = (void*)(intptr_t)cli_apicalls1[api->idx];
		    break;
		default:
		    llvm_unreachable("invalid api type");
	    }
	    EE->addGlobalMapping(F, dest);
	    apiFuncs[i] = F;
	}

	for (unsigned i=0;i<bcs->count;i++) {
	    const struct cli_bc *bc = &bcs->all_bcs[i];
	    if (bc->state == bc_skip)
		continue;
	    LLVMCodegen Codegen(bc, M, bcs->engine->compiledFunctions, EE,
				OurFPM, apiFuncs, apiMap);
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
	delete [] apiFuncs;
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
    // If already initialized return
    if (llvm_is_multithreaded())
	return 0;
    llvm_install_error_handler(llvm_error_handler);
#ifdef CL_DEBUG
    sys::PrintStackTraceOnErrorSignal();
#else
    llvm::DisablePrettyStackTrace = true;
#endif
    atexit(do_shutdown);

#ifdef CL_DEBUG
    llvm::JITEmitDebugInfo = true;
#else
    llvm::JITEmitDebugInfo = false;
#endif
    llvm::DwarfExceptionHandling = false;
    llvm_start_multithreaded();

    // If we have a native target, initialize it to ensure it is linked in and
    // usable by the JIT.
    InitializeNativeTarget();
    return 0;
}

// Called once when loading a new set of BC files
int cli_bytecode_init_jit(struct cli_all_bc *bcs)
{
    //TODO: if !llvm_is_multi...
    bcs->engine = new(std::nothrow) struct cli_bcengine;
    if (!bcs->engine)
	return CL_EMEM;
    bcs->engine->EE = 0;
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

typedef struct lines {
    MemoryBuffer *buffer;
    std::vector<const char*> linev;
} linesTy;

static struct lineprinter {
    StringMap<linesTy*> files;
} LinePrinter;

void cli_bytecode_debug_printsrc(const struct cli_bc_ctx *ctx)
{
    if (!ctx->file || !ctx->directory || !ctx->line) {
	errs() << (ctx->directory ? "d":"null") << ":" << (ctx->file ? "f" : "null")<< ":" << ctx->line << "\n";
	return;
    }
    // acquire a mutex here
    sys::Mutex mtx(false);
    sys::SmartScopedLock<false> lock(mtx);

    std::string path = std::string(ctx->directory) + "/" + std::string(ctx->file);
    StringMap<linesTy*>::iterator I = LinePrinter.files.find(path);
    linesTy *lines;
    if (I == LinePrinter.files.end()) {
	lines = new linesTy;
	std::string ErrorMessage;
	lines->buffer = MemoryBuffer::getFile(path, &ErrorMessage);
	if (!lines->buffer) {
	    errs() << "Unable to open file '" << path << "'\n";
	    return ;
	}
	LinePrinter.files[path] = lines;
    } else {
	lines = I->getValue();
    }
    while (lines->linev.size() <= ctx->line+1) {
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
		lines->linev.push_back(p+1);
	}
    }
    if (ctx->line >= lines->linev.size()) {
	errs() << "Line number " << ctx->line << "out of file\n";
	return;
    }
    assert(ctx->line < lines->linev.size());
    SMDiagnostic diag(ctx->file, ctx->line ? ctx->line : -1,
		 ctx->col ? ctx->col-1 : -1,
		 "", std::string(lines->linev[ctx->line-1], lines->linev[ctx->line]-1));
    diag.Print("[trace]", errs());
}

int have_clamjit=1;
void cli_bytecode_printversion()
{
  cl::PrintVersionMessage();
}
