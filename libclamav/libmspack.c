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
	off_t max_size;
};

struct mspack_handle {
	enum mspack_type type;

	fmap_t *fmap;
	off_t org;
	off_t offset;

	FILE *f;
	off_t max_size;
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
	memset(mspack_handle, 0, (sizeof(*mspack_handle)));
	if (!mspack_handle) {
		cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
		return NULL;
	}
	memset(mspack_handle, 0, sizeof(*mspack_handle));

	switch (mode) {
	case MSPACK_SYS_OPEN_READ:
		mspack_handle->type = FILETYPE_FMAP;

		mspack_name = (struct mspack_name *)filename;
		mspack_handle->fmap = mspack_name->fmap;
		mspack_handle->org = mspack_name->org;
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

	self_ex = (struct mspack_system_ex *)((char *)mptr - offsetof(struct mspack_system_ex,ops));
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
	off_t offset;
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
		offset = mspack_handle->offset + mspack_handle->org;

		ret = fmap_readn(mspack_handle->fmap, buffer, offset, bytes);
		if (ret != bytes) {
			cli_dbgmsg("%s() %d %d, %d\n", __func__, __LINE__, bytes, ret);
			return ret;
		}

		mspack_handle->offset += bytes;
		return bytes;
	}
	count = fread(buffer, bytes, 1, mspack_handle->f);
	if (count < 1) {
		cli_dbgmsg("%s() %d %d, %zd\n", __func__, __LINE__, bytes, count);
		return -1;
	}
	return bytes;
}

static int mspack_fmap_write(struct mspack_file *file, void *buffer, int bytes)
{
	struct mspack_handle *mspack_handle = (struct mspack_handle *)file;
	size_t count;
	off_t max_size;

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

	max_size = max_size < (off_t) bytes ? max_size : (off_t) bytes;
 
	mspack_handle->max_size -= max_size;

	count = fwrite(buffer, max_size, 1, mspack_handle->f);
	if (count < 1) {
		cli_dbgmsg("%s() err %m <%zd %d>\n", __func__, count, bytes);
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

	return (off_t) ftell(mspack_handle->f);
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
		strncpy(buff, "LibClamAV debug: ", len);
		
		va_start(args, fmt);
		vsnprintf(buff + len, sizeof(buff) - len - 2, fmt, args);
		va_end(args);
	
		/* Add a newline and a null terminator */
		buff[strlen(buff)] = '\n';
		buff[strlen(buff) + 1] = '\0';
	
		fputs(buff, stderr);
	}
}

static void *mspack_fmap_alloc(struct mspack_system *self, size_t num)
{
	UNUSEDPARAM(self);
	void * addr = malloc(num);
	if (addr) {
		memset(addr, 0, num);
	}
	return addr;
}

static void mspack_fmap_free(void *mem)
{
    if(mem) {
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
	.open = mspack_fmap_open,
	.close = mspack_fmap_close,
	.read = mspack_fmap_read,
	.write = mspack_fmap_write,
	.seek = mspack_fmap_seek,
	.tell = mspack_fmap_tell,
	.message = mspack_fmap_message,
	.alloc = mspack_fmap_alloc,
	.free = mspack_fmap_free,
	.copy = mspack_fmap_copy,
};

static int cli_scanfile(const char *filename, cli_ctx *ctx)
{
	int fd, ret = 0;

	/* internal version of cl_scanfile with arec/mrec preserved */
	fd = safe_open(filename, O_RDONLY|O_BINARY);
	if (fd < 0)
		return ret;

	ret = cli_magic_scandesc(fd, filename, ctx);

	close(fd);
	return ret;
}

int cli_scanmscab(cli_ctx *ctx, off_t sfx_offset)
{
	struct mscab_decompressor *cab_d;
	struct mscabd_cabinet *cab_h;
	struct mscabd_file *cab_f;
	int ret = 0;
    int files;
	int virus_num = 0;
	struct mspack_name mspack_fmap = {
		.fmap	= *ctx->fmap,
		.org	= sfx_offset,
	};
	struct mspack_system_ex ops_ex;
	memset(&ops_ex, 0, sizeof(struct mspack_system_ex));
 	ops_ex.ops = mspack_sys_fmap_ops;

	cab_d = mspack_create_cab_decompressor(&ops_ex.ops);
	if (!cab_d) {
		cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
		return CL_EUNPACK;
	}

	cab_d->set_param(cab_d, MSCABD_PARAM_FIXMSZIP, 1);
#if MSCABD_PARAM_SALVAGE
	cab_d->set_param(cab_d, MSCABD_PARAM_SALVAGE, 1);
#endif

	cab_h = cab_d->open(cab_d, (char *)&mspack_fmap);
	if (!cab_h) {
		ret = CL_EFORMAT;
		cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
		goto out_dest;
	}
	files = 0;
	for (cab_f = cab_h->files; cab_f; cab_f = cab_f->next) {
		off_t max_size;
		char *tmp_fname = NULL;

		ret = cli_matchmeta(ctx, cab_f->filename, 0, cab_f->length, 0,
				files, 0, NULL);
		if (ret) {
			if (ret == CL_VIRUS) {
				virus_num++;
				if (!SCAN_ALLMATCHES)
					break;
			}
			goto out_close;
		}

		if (ctx->engine->maxscansize) {
			if (ctx->scansize >= ctx->engine->maxscansize) {
				ret = CL_CLEAN;
				break;
			}
		}

		if (ctx->engine->maxscansize &&
				ctx->scansize + ctx->engine->maxfilesize >=
				ctx->engine->maxscansize)
			max_size = ctx->engine->maxscansize -
				ctx->scansize;
		else
			max_size = ctx->engine->maxfilesize ?
				ctx->engine->maxfilesize :
				0xffffffff;

		tmp_fname = cli_gentemp(ctx->engine->tmpdir);
		if (!tmp_fname) {
			ret = CL_EMEM;
			break;
		}

		ops_ex.max_size = max_size;
		/* scan */
		ret = cab_d->extract(cab_d, cab_f, tmp_fname);
		if (ret)
			/* Failed to extract. Try to scan what is there */
			cli_dbgmsg("%s() failed to extract %d\n", __func__, ret);

		ret = cli_scanfile(tmp_fname, ctx);
		if (ret == CL_VIRUS)
			virus_num++;

		if (!ctx->engine->keeptmp) {
			if (!access(tmp_fname, R_OK) && cli_unlink(tmp_fname)) {
				free(tmp_fname);
				ret = CL_EUNLINK;
				break;
			}
		}
		free(tmp_fname);
		files++;
		if (ret == CL_VIRUS && SCAN_ALLMATCHES)
			continue;
		if (ret)
			break;
	}

out_close:
	cab_d->close(cab_d, cab_h);
out_dest:
	mspack_destroy_cab_decompressor(cab_d);
	if (virus_num)
		return CL_VIRUS;
	return ret;
}

int cli_scanmschm(cli_ctx *ctx)
{
	struct mschm_decompressor *mschm_d;
	struct mschmd_header *mschm_h;
	struct mschmd_file *mschm_f;
	int ret = CL_CLEAN; // Default CLEAN in case CHM contains no files.
	int files;
	int virus_num = 0;
	struct mspack_name mspack_fmap = {
		.fmap = *ctx->fmap,
	};
	struct mspack_system_ex ops_ex;
	memset(&ops_ex, 0, sizeof(struct mspack_system_ex));
 	ops_ex.ops = mspack_sys_fmap_ops;

	mschm_d = mspack_create_chm_decompressor(&ops_ex.ops);
	if (!mschm_d) {
		cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
		return CL_EUNPACK;
	}

	mschm_h = mschm_d->open(mschm_d, (char *)&mspack_fmap);
	if (!mschm_h) {
		ret = CL_EFORMAT;
		cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
		goto out_dest;
	}
	files = 0;
	for (mschm_f = mschm_h->files; mschm_f;	mschm_f = mschm_f->next) {
		off_t max_size;
		char *tmp_fname;

		ret = cli_matchmeta(ctx, mschm_f->filename, 0, mschm_f->length,
				0, files, 0, NULL);
		if (ret) {
			if (ret == CL_VIRUS) {
				virus_num++;
				if (!SCAN_ALLMATCHES)
					break;
			}
			goto out_close;
		}

		if (ctx->engine->maxscansize) {
			if (ctx->scansize >= ctx->engine->maxscansize) {
				ret = CL_CLEAN;
				break;
			}
		}

		if (ctx->engine->maxscansize &&
				ctx->scansize + ctx->engine->maxfilesize >=
				ctx->engine->maxscansize)
			max_size = ctx->engine->maxscansize -
				ctx->scansize;
		else
			max_size = ctx->engine->maxfilesize ?
				ctx->engine->maxfilesize :
				0xffffffff;

		ops_ex.max_size = max_size;

		tmp_fname = cli_gentemp(ctx->engine->tmpdir);
		if (!tmp_fname) {
			ret = CL_EMEM;
			break;
		}

		/* scan */
		ret = mschm_d->extract(mschm_d, mschm_f, tmp_fname);
		if (ret)
			/* Failed to extract. Try to scan what is there */
			cli_dbgmsg("%s() failed to extract %d\n", __func__, ret);

		ret = cli_scanfile(tmp_fname, ctx);
		if (ret == CL_VIRUS)
			virus_num++;

		if (!ctx->engine->keeptmp) {
			if (!access(tmp_fname, R_OK) && cli_unlink(tmp_fname)) {
				free(tmp_fname);
				ret = CL_EUNLINK;
				break;
			}
		}
		free(tmp_fname);
		files++;
		if (ret == CL_VIRUS && SCAN_ALLMATCHES)
			continue;
		if (ret)
			break;
	}

out_close:
	mschm_d->close(mschm_d, mschm_h);
out_dest:
	mspack_destroy_chm_decompressor(mschm_d);
	if (virus_num)
		return CL_VIRUS;
	return ret;
}
