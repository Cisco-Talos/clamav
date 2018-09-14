#define ERROR(base) error_msg(base->last_error(base))

const char *error_msg(int error) {
    static char buf[32];
    switch (error) {
    case MSPACK_ERR_OK:         return "no error";
    case MSPACK_ERR_ARGS:       return "bad arguments to library function";
    case MSPACK_ERR_OPEN:       return "error opening file";
    case MSPACK_ERR_READ:       return "read error";
    case MSPACK_ERR_WRITE:      return "write error";
    case MSPACK_ERR_SEEK:       return "seek error";
    case MSPACK_ERR_NOMEMORY:   return "out of memory";
    case MSPACK_ERR_SIGNATURE:  return "bad signature";
    case MSPACK_ERR_DATAFORMAT: return "error in data format";
    case MSPACK_ERR_CHECKSUM:   return "checksum error";
    case MSPACK_ERR_CRUNCH:     return "compression error";
    case MSPACK_ERR_DECRUNCH:   return "decompression error";
    }

    snprintf(buf, sizeof(buf), "unknown error %d", error);
    return buf;
}
