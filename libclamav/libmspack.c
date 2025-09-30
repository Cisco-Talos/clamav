/*
 * Author: 웃 Sebastian Andrzej Siewior
 * Summary: Glue code for libmspack handling.
 *
 * Acknowledgements: ClamAV uses Stuart Caie's libmspack to parse as number of
 *                   Microsoft file formats.
 * ✉ sebastian @ breakpoint ̣cc
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>

#include <mspack.h>

#include "clamav.h"
#include "fmap.h"
#include "scanners.h"
#include "others.h"
#include "clamav_rust.h"

enum mspack_type {
    FILETYPE_DUNNO,
    FILETYPE_FMAP,
    FILETYPE_FILENAME,
};

struct mspack_name {
    fmap_t *fmap;
    off_t org;
};

struct mspack_system_ex {
    struct mspack_system ops;
    uint64_t max_size;
};

struct mspack_handle {
    enum mspack_type type;

    fmap_t *fmap;
    off_t org;
    off_t offset;

    FILE *f;
    uint64_t max_size;
};

static struct mspack_file *mspack_fmap_open(struct mspack_system *self,
                                            const char *filename, int mode)
{
    struct mspack_name *mspack_name;
    struct mspack_handle *mspack_handle;
    struct mspack_system_ex *self_ex;
    const char *fmode;
    const struct mspack_system *mptr = self;

    if (!filename) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        return NULL;
    }
    mspack_handle = malloc(sizeof(*mspack_handle));
    if (!mspack_handle) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        return NULL;
    }
    memset(mspack_handle, 0, sizeof(*mspack_handle));

    switch (mode) {
        case MSPACK_SYS_OPEN_READ:
            mspack_handle->type = FILETYPE_FMAP;

            mspack_name           = (struct mspack_name *)filename;
            mspack_handle->fmap   = mspack_name->fmap;
            mspack_handle->org    = mspack_name->org;
            mspack_handle->offset = 0;

            return (struct mspack_file *)mspack_handle;

        case MSPACK_SYS_OPEN_WRITE:
            fmode = "wb";
            break;
        case MSPACK_SYS_OPEN_UPDATE:
            fmode = "r+b";
            break;
        case MSPACK_SYS_OPEN_APPEND:
            fmode = "ab";
            break;
        default:
            cli_dbgmsg("%s() wrong mode\n", __func__);
            goto out_err;
    }

    mspack_handle->type = FILETYPE_FILENAME;

    mspack_handle->f = fopen(filename, fmode);
    if (!mspack_handle->f) {
        cli_dbgmsg("%s() failed %d\n", __func__, __LINE__);
        goto out_err;
    }

    self_ex                 = (struct mspack_system_ex *)((char *)mptr - offsetof(struct mspack_system_ex, ops));
    mspack_handle->max_size = self_ex->max_size;
    return (struct mspack_file *)mspack_handle;

out_err:
    memset(mspack_handle, 0, (sizeof(*mspack_handle)));
    free(mspack_handle);
    mspack_handle = NULL;
    return NULL;
}

static void mspack_fmap_close(struct mspack_file *file)
{
    struct mspack_handle *mspack_handle = (struct mspack_handle *)file;

    if (!mspack_handle)
        return;

    if (mspack_handle->type == FILETYPE_FILENAME)
        if (mspack_handle->f)
            fclose(mspack_handle->f);

    memset(mspack_handle, 0, (sizeof(*mspack_handle)));
    free(mspack_handle);
    mspack_handle = NULL;
    return;
}

static int mspack_fmap_read(struct mspack_file *file, void *buffer, int bytes)
{
    struct mspack_handle *mspack_handle = (struct mspack_handle *)file;
    size_t offset;
    size_t count;
    int ret;

    if (bytes < 0) {
        cli_dbgmsg("%s() %d\n", __func__, __LINE__);
        return -1;
    }
    if (!mspack_handle) {
        cli_dbgmsg("%s() %d\n", __func__, __LINE__);
        return -1;
    }

    if (mspack_handle->type == FILETYPE_FMAP) {
        /* Use fmap */
        offset = mspack_handle->offset + mspack_handle->org;

        count = fmap_readn(mspack_handle->fmap, buffer, offset, (size_t)bytes);
        if (count == (size_t)-1) {
            cli_dbgmsg("%s() %d requested %d bytes, read failed (-1)\n", __func__, __LINE__, bytes);
            return -1;
        } else if ((int)count < bytes) {
            cli_dbgmsg("%s() %d requested %d bytes, read %zu bytes\n", __func__, __LINE__, bytes, count);
        }

        mspack_handle->offset += (off_t)count;

        return (int)count;
    } else {
        /* Use file descriptor */
        count = fread(buffer, (size_t)bytes, 1, mspack_handle->f);
        if (count < 1) {
            cli_dbgmsg("%s() %d requested %d bytes, read failed (%zu)\n", __func__, __LINE__, bytes, count);
            return -1;
        }

        ret = (int)count;

        return ret;
    }
}

static int mspack_fmap_write(struct mspack_file *file, void *buffer, int bytes)
{
    struct mspack_handle *mspack_handle = (struct mspack_handle *)file;
    size_t count;
    uint64_t max_size;

    if (bytes < 0 || !mspack_handle) {
        cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
        return -1;
    }

    if (mspack_handle->type == FILETYPE_FMAP) {
        cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
        return -1;
    }

    if (!bytes)
        return 0;

    max_size = mspack_handle->max_size;
    if (!max_size)
        return bytes;

    max_size = max_size < (uint64_t)bytes ? max_size : (uint64_t)bytes;

    mspack_handle->max_size -= max_size;

    count = fwrite(buffer, max_size, 1, mspack_handle->f);
    if (count < 1) {
        cli_dbgmsg("%s() err %d <%zu %d>\n", __func__, __LINE__, count, bytes);
        return -1;
    }

    return bytes;
}

static int mspack_fmap_seek(struct mspack_file *file, off_t offset, int mode)
{
    struct mspack_handle *mspack_handle = (struct mspack_handle *)file;

    if (!mspack_handle) {
        cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
        return -1;
    }

    if (mspack_handle->type == FILETYPE_FMAP) {
        off_t new_pos;

        switch (mode) {
            case MSPACK_SYS_SEEK_START:
                new_pos = offset;
                break;
            case MSPACK_SYS_SEEK_CUR:
                new_pos = mspack_handle->offset + offset;
                break;
            case MSPACK_SYS_SEEK_END:
                new_pos = mspack_handle->fmap->len + offset;
                break;
            default:
                cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
                return -1;
        }
        if (new_pos < 0 || new_pos > (off_t)mspack_handle->fmap->len) {
            cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
            return -1;
        }

        mspack_handle->offset = new_pos;
        return 0;
    }

    switch (mode) {
        case MSPACK_SYS_SEEK_START:
            mode = SEEK_SET;
            break;
        case MSPACK_SYS_SEEK_CUR:
            mode = SEEK_CUR;
            break;
        case MSPACK_SYS_SEEK_END:
            mode = SEEK_END;
            break;
        default:
            cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
            return -1;
    }

    return fseek(mspack_handle->f, offset, mode);
}

static off_t mspack_fmap_tell(struct mspack_file *file)
{
    struct mspack_handle *mspack_handle = (struct mspack_handle *)file;

    if (!mspack_handle)
        return -1;

    if (mspack_handle->type == FILETYPE_FMAP)
        return mspack_handle->offset;

    return (off_t)ftell(mspack_handle->f);
}

static void mspack_fmap_message(struct mspack_file *file, const char *fmt, ...)
{
    UNUSEDPARAM(file);

    if (UNLIKELY(cli_debug_flag)) {
        va_list args;
        char buff[BUFSIZ];
        size_t len = sizeof("LibClamAV debug: ") - 1;

        memset(buff, 0, BUFSIZ);

        /* Add the prefix */
        memcpy(buff, "LibClamAV debug: ", len);

        va_start(args, fmt);
        vsnprintf(buff + len, sizeof(buff) - len - 2, fmt, args);
        va_end(args);

        /* Add a newline and a null terminator */
        buff[strlen(buff)]     = '\n';
        buff[strlen(buff) + 1] = '\0';

        clrs_eprint(buff);
    }
}

static void *mspack_fmap_alloc(struct mspack_system *self, size_t num)
{
    UNUSEDPARAM(self);
    void *addr = malloc(num);
    if (addr) {
        memset(addr, 0, num);
    }
    return addr;
}

static void mspack_fmap_free(void *mem)
{
    if (mem) {
        free(mem);
        mem = NULL;
    }
    return;
}

static void mspack_fmap_copy(void *src, void *dst, size_t num)
{
    memcpy(dst, src, num);
}

static struct mspack_system mspack_sys_fmap_ops = {
    .open    = mspack_fmap_open,
    .close   = mspack_fmap_close,
    .read    = mspack_fmap_read,
    .write   = mspack_fmap_write,
    .seek    = mspack_fmap_seek,
    .tell    = mspack_fmap_tell,
    .message = mspack_fmap_message,
    .alloc   = mspack_fmap_alloc,
    .free    = mspack_fmap_free,
    .copy    = mspack_fmap_copy,
};

cl_error_t cli_mscab_header_check(cli_ctx *ctx, size_t offset, size_t *size)
{
    cl_error_t status = CL_EFORMAT;

    struct mscab_decompressor *cab_d = NULL;
    struct mscabd_cabinet *cab_h     = NULL;
    struct mspack_name mspack_fmap   = {0};
    struct mspack_system_ex ops_ex   = {0};

    if (NULL == ctx || NULL == size) {
        cli_dbgmsg("%s() invalid argument\n", __func__);
        status = CL_EARG;
        goto done;
    }

    *size            = 0;
    mspack_fmap.fmap = ctx->fmap;

    if (offset > INT32_MAX) {
        cli_dbgmsg("%s() offset too large %zu\n", __func__, offset);
        status = CL_EFORMAT;
        goto done;
    }

    mspack_fmap.org = (off_t)offset;

    ops_ex.ops = mspack_sys_fmap_ops;

    cab_d = mspack_create_cab_decompressor(&ops_ex.ops);
    if (NULL == cab_d) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        status = CL_EUNPACK;
        goto done;
    }

    cab_h = cab_d->open(cab_d, (char *)&mspack_fmap);
    if (NULL == cab_h) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        status = CL_EFORMAT;
        goto done;
    }

    *size = (size_t)cab_h->length;

    cli_dbgmsg("%s(): Successfully read CAB header for CAB of size %zu\n", __func__, *size);
    status = CL_SUCCESS;

done:
    if (NULL != cab_d) {
        if (NULL != cab_h) {
            cab_d->close(cab_d, cab_h);
        }
        mspack_destroy_cab_decompressor(cab_d);
    }

    return status;
}

cl_error_t cli_scanmscab(cli_ctx *ctx, size_t sfx_offset)
{
    cl_error_t ret                   = CL_SUCCESS;
    struct mscab_decompressor *cab_d = NULL;
    struct mscabd_cabinet *cab_h     = NULL;
    struct mscabd_file *cab_f        = NULL;
    int files;
    struct mspack_name mspack_fmap = {0};
    struct mspack_system_ex ops_ex = {0};

    char *tmp_fname      = NULL;
    bool tempfile_exists = false;

    mspack_fmap.fmap = ctx->fmap;

    if (sfx_offset > INT32_MAX) {
        cli_dbgmsg("%s() offset too large %zu\n", __func__, sfx_offset);
        ret = CL_EFORMAT;
        goto done;
    }

    mspack_fmap.org = (off_t)sfx_offset;

    memset(&ops_ex, 0, sizeof(struct mspack_system_ex));
    ops_ex.ops = mspack_sys_fmap_ops;

    cab_d = mspack_create_cab_decompressor(&ops_ex.ops);
    if (!cab_d) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        ret = CL_EUNPACK;
        goto done;
    }

    cab_d->set_param(cab_d, MSCABD_PARAM_FIXMSZIP, 1);
#if MSCABD_PARAM_SALVAGE
    cab_d->set_param(cab_d, MSCABD_PARAM_SALVAGE, 1);
#endif

    cab_h = cab_d->open(cab_d, (char *)&mspack_fmap);
    if (NULL == cab_h) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        ret = CL_EFORMAT;
        goto done;
    }

    files = 0;
    for (cab_f = cab_h->files; cab_f; cab_f = cab_f->next) {
        uint64_t max_size;

        ret = cli_matchmeta(ctx, cab_f->filename, 0, cab_f->length, 0,
                            files, 0);
        if (CL_SUCCESS != ret) {
            goto done;
        }

        if (ctx->engine->maxscansize) {
            if (ctx->scansize >= ctx->engine->maxscansize) {
                ret = CL_CLEAN;
                goto done;
            }
        }

        if (ctx->engine->maxfilesize > 0) {
            // max filesize has been set
            if ((ctx->engine->maxscansize > 0) &&
                (ctx->scansize + ctx->engine->maxfilesize >= ctx->engine->maxscansize)) {
                // ... but would exceed max scansize, shrink it.
                max_size = ctx->engine->maxscansize - ctx->scansize;
            } else {
                // ... and will work
                max_size = ctx->engine->maxfilesize;
            }
        } else {
            // max filesize not specified
            if ((ctx->engine->maxscansize > 0) &&
                (ctx->scansize + UINT32_MAX >= ctx->engine->maxscansize)) {
                // ... but UINT32_MAX would exceed max scansize, shrink it.
                max_size = ctx->engine->maxscansize - ctx->scansize;
            } else {
                // ... use UINT32_MAX
                max_size = UINT32_MAX;
            }
        }

        tmp_fname = cli_gentemp(ctx->this_layer_tmpdir);
        if (!tmp_fname) {
            ret = CL_EMEM;
            goto done;
        }

        ops_ex.max_size = max_size;

        /* scan */
        ret = cab_d->extract(cab_d, cab_f, tmp_fname);
        if (ret) {
            /* Failed to extract. Try to scan what is there */
            cli_dbgmsg("%s() failed to extract %d\n", __func__, ret);
        }
        tempfile_exists = true; // probably

        ret = cli_magic_scan_file(tmp_fname, ctx, cab_f->filename, LAYER_ATTRIBUTES_NONE);
        if (CL_EOPEN == ret) {
            // okay so the file didn't actually get extracted. That's okay, we'll move on.
            tempfile_exists = false;
            ret             = CL_SUCCESS;
        } else if (CL_SUCCESS != ret) {
            goto done;
        }

        if (!ctx->engine->keeptmp && tempfile_exists) {
            if (cli_unlink(tmp_fname)) {
                ret = CL_EUNLINK;
                goto done;
            }
        }

        free(tmp_fname);
        tmp_fname = NULL;

        files++;
    }

done:

    if (NULL != tmp_fname) {
        if (!ctx->engine->keeptmp && tempfile_exists) {
            (void)cli_unlink(tmp_fname);
        }

        free(tmp_fname);
    }

    if (NULL != cab_d) {
        if (NULL != cab_h) {
            cab_d->close(cab_d, cab_h);
        }
        mspack_destroy_cab_decompressor(cab_d);
    }

    return ret;
}

cl_error_t cli_scanmschm(cli_ctx *ctx)
{
    cl_error_t ret                     = CL_SUCCESS;
    struct mschm_decompressor *mschm_d = NULL;
    struct mschmd_header *mschm_h      = NULL;
    struct mschmd_file *mschm_f        = NULL;
    int files;
    struct mspack_name mspack_fmap = {
        .fmap = ctx->fmap,
    };
    struct mspack_system_ex ops_ex;

    char *tmp_fname      = NULL;
    bool tempfile_exists = false;

    memset(&ops_ex, 0, sizeof(struct mspack_system_ex));
    ops_ex.ops = mspack_sys_fmap_ops;

    mschm_d = mspack_create_chm_decompressor(&ops_ex.ops);
    if (!mschm_d) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        ret = CL_EUNPACK;
        goto done;
    }

    mschm_h = mschm_d->open(mschm_d, (char *)&mspack_fmap);
    if (!mschm_h) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        ret = CL_EFORMAT;
        goto done;
    }

    files = 0;
    for (mschm_f = mschm_h->files; mschm_f; mschm_f = mschm_f->next) {
        uint64_t max_size;

        ret = cli_matchmeta(ctx, mschm_f->filename, 0, mschm_f->length,
                            0, files, 0);
        if (CL_SUCCESS != ret) {
            goto done;
        }

        if (ctx->engine->maxscansize) {
            if (ctx->scansize >= ctx->engine->maxscansize) {
                ret = CL_CLEAN;
                goto done;
            }
        }

        if (ctx->engine->maxfilesize > 0) {
            // max filesize has been set
            if ((ctx->engine->maxscansize > 0) &&
                (ctx->scansize + ctx->engine->maxfilesize >= ctx->engine->maxscansize)) {
                // ... but would exceed max scansize, shrink it.
                max_size = ctx->engine->maxscansize - ctx->scansize;
            } else {
                // ... and will work
                max_size = ctx->engine->maxfilesize;
            }
        } else {
            // max filesize not specified
            if ((ctx->engine->maxscansize > 0) &&
                (ctx->scansize + UINT32_MAX >= ctx->engine->maxscansize)) {
                // ... but UINT32_MAX would exceed max scansize, shrink it.
                max_size = ctx->engine->maxscansize - ctx->scansize;
            } else {
                // ... use UINT32_MAX
                max_size = UINT32_MAX;
            }
        }

        tmp_fname = cli_gentemp(ctx->this_layer_tmpdir);
        if (!tmp_fname) {
            ret = CL_EMEM;
            break;
        }

        ops_ex.max_size = max_size;

        /* scan */
        ret = mschm_d->extract(mschm_d, mschm_f, tmp_fname);
        if (ret) {
            /* Failed to extract. Try to scan what is there */
            cli_dbgmsg("%s() failed to extract %d\n", __func__, ret);
        }
        tempfile_exists = true; // probably

        ret = cli_magic_scan_file(tmp_fname, ctx, mschm_f->filename, LAYER_ATTRIBUTES_NONE);
        if (CL_EOPEN == ret) {
            // okay so the file didn't actually get extracted. That's okay, we'll move on.
            tempfile_exists = false;
            ret             = CL_SUCCESS;
        } else if (CL_SUCCESS != ret) {
            goto done;
        }

        if (!ctx->engine->keeptmp && tempfile_exists) {
            if (cli_unlink(tmp_fname)) {
                ret = CL_EUNLINK;
                goto done;
            }
        }

        free(tmp_fname);
        tmp_fname = NULL;

        files++;
    }

done:

    if (NULL != tmp_fname) {
        if (!ctx->engine->keeptmp && tempfile_exists) {
            (void)cli_unlink(tmp_fname);
        }

        free(tmp_fname);
    }

    if (NULL != mschm_d) {
        if (NULL != mschm_h) {
            mschm_d->close(mschm_d, mschm_h);
        }
        mspack_destroy_chm_decompressor(mschm_d);
    }

    return ret;
}
