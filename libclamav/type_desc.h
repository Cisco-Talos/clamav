enum derived_t {
  FunctionType,
  PointerType,
  StructType,
  PackedStructType,
  ArrayType
};

struct cli_bc_type {
    enum derived_t kind;
    uint16_t *containedTypes;
    unsigned numElements;
};

typedef int32_t (*cli_apicall_int2)(int32_t, int32_t);
typedef int32_t (*cli_apicall_pointer)(void*, uint32_t);

struct cli_apicall {
    const char *name;
    const struct cli_bc_type *type;
    uint8_t kind;
};

extern const struct cli_bc_type cli_apicall_types[];

extern const struct cli_apicall cli_apicalls[];
extern const cli_apicall_int2 cli_apicalls0[];
extern const cli_apicall_pointer cli_apicalls1[];
extern const unsigned cli_apicall_maxapi;
