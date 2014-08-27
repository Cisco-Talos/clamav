#if LLVM_VERSION < 30
#define constType const Type
#define constArrayType const ArrayType
#define constStructType const StructType
#define constPointerType const PointerType
#define constFunctionType const FunctionType
#define ARRAYREF(t,a,b) (a),(b)
#define ARRAYREFPARAM(t,a,b,n) a, b
#define ARRAYREFP(a,b,n) a, b
#define ARRAYREFVECTOR(t,a) (a).begin(),(a).end()
#define HINT(n)
#define OPT(n)
#else
#define constType Type
#define constArrayType ArrayType
#define constStructType StructType
#define constPointerType PointerType
#define constFunctionType FunctionType
#define ARRAYREF(t,a,b) ArrayRef<t>(a,b)
#define ARRAYREFPARAM(t,a,b,n) ArrayRef<t> n
#define ARRAYREFP(a,b,n) n
#define ARRAYREFVECTOR(t,a) ArrayRef<t>(a)
#define HINT(n) n,
#define OPT(n) ,n
#endif
