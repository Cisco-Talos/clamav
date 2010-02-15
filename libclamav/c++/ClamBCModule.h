#include "llvm/Support/raw_ostream.h"
namespace llvm {
    class Function;
    class Instruction;
    class Pass;
}
namespace ClamBCModule {
    static void stop(const char *msg, llvm::Function* F, llvm::Instruction* I) {
	llvm::errs() << msg << "\n";
    }
}
llvm::Pass *createClamBCRTChecks();
