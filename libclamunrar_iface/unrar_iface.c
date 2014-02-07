/*
 *  Interface to libclamunrar
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Authors: Trog, Torok Edvin, Tomasz Kojm
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "libclamunrar/unrar.h"

#include "unrar_iface.h"

#if WORDS_BIGENDIAN == 0
#define unrar_endian_convert_16(v)	(v)
#define unrar_endian_convert_32(v)    (v)
#else
static uint16_t unrar_endian_convert_16(uint16_t v)
{
    return ((v >> 8) + (v << 8));
}
static uint32_t unrar_endian_convert_32(uint32_t v)
{
    return ((v >> 24) | ((v & 0x00FF0000) >> 8) | ((v & 0x0000FF00) << 8) | (v << 24));
}
#endif

/* FIXME: allow this to be controlled from unrar_open or so */
#ifdef RAR_DEBUG_MODE
#define unrar_dbgmsg printf
#else
static void unrar_dbgmsg(const char* fmt,...){}
#endif

static void *read_header(int fd, header_type hdr_type)
{
	unsigned char encrypt_ver;


    switch(hdr_type) {
	case MAIN_HEAD: {
		unrar_main_header_t *main_hdr;

	    main_hdr = (unrar_main_header_t *) malloc(sizeof(unrar_main_header_t));
	    if(!main_hdr)
		return NULL;

	    if(read(fd, main_hdr, SIZEOF_NEWMHD) != SIZEOF_NEWMHD) {
		free(main_hdr);
		return NULL;
	    }
	    main_hdr->flags = unrar_endian_convert_16(main_hdr->flags);
	    main_hdr->head_size = unrar_endian_convert_16(main_hdr->head_size);
	    main_hdr->head_crc = unrar_endian_convert_16(main_hdr->head_crc);
	    if(main_hdr->flags & MHD_ENCRYPTVER) {
		if(read(fd, &encrypt_ver, sizeof(unsigned char)) != sizeof(unsigned char)) {
		    free(main_hdr);
                    return NULL;
		}
		unrar_dbgmsg("UNRAR: RAR Encrypt version: %d\n", encrypt_ver);
            }
	    return main_hdr;
	}
	case FILE_HEAD: {
		unrar_fileheader_t *file_hdr;

	    file_hdr = (unrar_fileheader_t *) malloc(sizeof(unrar_fileheader_t));
	    if(!file_hdr)
		return NULL;

	    if(read(fd, file_hdr, SIZEOF_NEWLHD) != SIZEOF_NEWLHD) {
		free(file_hdr);
		return NULL;
	    }
	    file_hdr->flags = unrar_endian_convert_16(file_hdr->flags);
	    file_hdr->head_size = unrar_endian_convert_16(file_hdr->head_size);
	    file_hdr->pack_size = unrar_endian_convert_32(file_hdr->pack_size);
	    file_hdr->unpack_size = unrar_endian_convert_32(file_hdr->unpack_size);
	    file_hdr->file_crc = unrar_endian_convert_32(file_hdr->file_crc);
	    file_hdr->name_size = unrar_endian_convert_16(file_hdr->name_size);
	    if(file_hdr->flags & 0x100) {
		if(read(fd, (char *) file_hdr + SIZEOF_NEWLHD, 8) != 8) {
		    free(file_hdr);
		    return NULL;
		}
		file_hdr->high_pack_size = unrar_endian_convert_32(file_hdr->high_pack_size);
		file_hdr->high_unpack_size = unrar_endian_convert_32(file_hdr->high_unpack_size);
	    } else {
		file_hdr->high_pack_size = 0;
		file_hdr->high_unpack_size = 0;
	    }
	    return file_hdr;
	}
	case COMM_HEAD: {
		unrar_comment_header_t *comment_hdr;

	    comment_hdr = (unrar_comment_header_t *) malloc(sizeof(unrar_comment_header_t));
	    if(!comment_hdr)
		return NULL;

	    if(read(fd, comment_hdr, SIZEOF_COMMHEAD) != SIZEOF_COMMHEAD) {
		free(comment_hdr);
		return NULL;
	    }
	    comment_hdr->unpack_size = unrar_endian_convert_16(comment_hdr->unpack_size);
	    comment_hdr->comm_crc = unrar_endian_convert_16(comment_hdr->comm_crc);
	    return comment_hdr;
	}
	default:
	    unrar_dbgmsg("UNRAR: ERROR: Unknown header type requested\n");
	    return NULL;
    }
    return NULL;
}

static unrar_fileheader_t *read_block(int fd, header_type hdr_type)
{
	unrar_fileheader_t *file_header;
	off_t offset;


    for (;;) {
	offset = lseek(fd, 0, SEEK_CUR);
    if (offset == -1) {
        unrar_dbgmsg("UNRAR: seek: call to lseek() failed in read_block\n");
        return NULL;
    }
	file_header = read_header(fd, FILE_HEAD);
	if(!file_header)
	    return NULL;

	file_header->start_offset = offset;
	file_header->next_offset = offset + file_header->head_size;
	if(file_header->flags & LONG_BLOCK)
	    file_header->next_offset += file_header->pack_size;

	if(file_header->next_offset <= offset) {
	    free(file_header);
	    return NULL;
	}

	/* Check if the block is of the requested type */
	if(file_header->head_type == hdr_type) {
	    /* TODO check what to do with SUBBLOCKS */
	    break;
	}

	unrar_dbgmsg("UNRAR: Found block type: 0x%x\n", file_header->head_type);
	unrar_dbgmsg("UNRAR: Head Size: %.4x\n", file_header->head_size);
	if(lseek(fd, file_header->next_offset, SEEK_SET) != file_header->next_offset) {
	    unrar_dbgmsg("seek: %ld\n", file_header->next_offset);
	    return NULL;
	}

	free(file_header);
    }

    unrar_dbgmsg("UNRAR: read_block out offset=%ld\n", lseek(fd, 0, SEEK_CUR));
    unrar_dbgmsg("UNRAR: Found file block.\n");
    unrar_dbgmsg("UNRAR: Pack Size: %u\n", file_header->pack_size);
    unrar_dbgmsg("UNRAR: UnPack Version: 0x%.2x\n", file_header->unpack_ver);
    unrar_dbgmsg("UNRAR: Pack Method: 0x%.2x\n", file_header->method);
    file_header->filename = (unsigned char *) malloc(file_header->name_size+1);
    if(!file_header->filename) {
	free(file_header);
	return NULL;
    }
    if(read(fd, file_header->filename, file_header->name_size) != file_header->name_size) {
	free(file_header->filename);
	free(file_header);
	return NULL;
    }
    file_header->filename[file_header->name_size] = '\0';
    unrar_dbgmsg("Filename: %s\n", file_header->filename);

    return file_header;
}

static int is_rar_archive(int fd)
{
	mark_header_t mark;
	const mark_header_t rar_hdr[2] = {{{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00}}, {{'U', 'n', 'i', 'q', 'u', 'E', '!'}}};


    if(read(fd, &mark, SIZEOF_MARKHEAD) != SIZEOF_MARKHEAD)
	return FALSE;

    if(memcmp(&mark, &rar_hdr[0], SIZEOF_MARKHEAD) == 0)
	return TRUE;

    if(memcmp(&mark, &rar_hdr[1], SIZEOF_MARKHEAD) == 0)
	return TRUE;

    unrar_dbgmsg("UNRAR: Not a RAR archive\n");
    return FALSE;
}

static void unpack_free_data(unpack_data_t *unpack_data)
{
	if (!unpack_data) {
		return;
	}
	/*init_filters(unpack_data);*/
	rarvm_free(&unpack_data->rarvm_data);
}

static unsigned int copy_file_data(int ifd, int ofd, unsigned int len)
{
	unsigned char data[8192];
	unsigned int todo, count, rem;

    rem = len;
    while(rem > 0) {
	todo = MIN(8192, rem);
	count = read(ifd, data, todo);
	if(count != todo)
	    return len-rem;

	if(write(ofd, data, count) != (ssize_t) count)
	    return len-rem-count;

	rem -= count;
    }
    return len;
}

int unrar_open(int fd, const char *dirname, unrar_state_t *state)
{
	int ofd, retval;
	char filename[1024];
	unpack_data_t *unpack_data;
	unrar_main_header_t *main_hdr;
	off_t offset;


    if(!state)
	return UNRAR_ERR;

    if(!is_rar_archive(fd))
	return UNRAR_ERR;

    main_hdr = read_header(fd, MAIN_HEAD);
    if(!main_hdr)
	return UNRAR_ERR;

    unrar_dbgmsg("UNRAR: Head CRC: %.4x\n", main_hdr->head_crc);
    unrar_dbgmsg("UNRAR: Head Type: %.2x\n", main_hdr->head_type);
    unrar_dbgmsg("UNRAR: Flags: %.4x\n", main_hdr->flags);
    unrar_dbgmsg("UNRAR: Head Size: %.4x\n", main_hdr->head_size);

    if(main_hdr->flags & MHD_PASSWORD) {
	free(main_hdr);
	return UNRAR_PASSWD;
    }

    snprintf(filename,1024,"%s"PATHSEP"comments", dirname);
    if(mkdir(filename,0700)) {
	unrar_dbgmsg("UNRAR: Unable to create comment temporary directory\n");
	free(main_hdr);
	return UNRAR_ERR;
    }
    state->comment_dir = strdup(filename);
    if(!state->comment_dir) {
	free(main_hdr);
	return UNRAR_EMEM;
    }

    if(main_hdr->head_size < SIZEOF_NEWMHD) {
	free(main_hdr);
	free(state->comment_dir);
	return UNRAR_ERR;
    }

    unpack_data = (unpack_data_t *) calloc(1, sizeof(unpack_data_t));
    if(!unpack_data) {
	free(main_hdr);
	free(state->comment_dir);
	unrar_dbgmsg("UNRAR: malloc failed for unpack_data\n");
	return UNRAR_EMEM;
    }
    unpack_data->rarvm_data.mem = NULL;
    unpack_data->old_filter_lengths = NULL;
    unpack_data->PrgStack.array = unpack_data->Filters.array = NULL;
    unpack_data->PrgStack.num_items = unpack_data->Filters.num_items = 0;
    unpack_data->unp_crc = 0xffffffff;
    unpack_data->max_size = 0;

    ppm_constructor(&unpack_data->ppm_data);

    if(main_hdr->flags & MHD_COMMENT) {
	unrar_comment_header_t *comment_header;
	unrar_dbgmsg("UNRAR: RAR main comment\n");
	offset = lseek(fd, 0, SEEK_CUR);
        if (offset == -1) {
            unrar_dbgmsg("UNRAR: seek: lseek() call failed in unrar_open\n");
            free(main_hdr);
            free(state->comment_dir);
            free(unpack_data);
            return UNRAR_ERR;
        }
	unrar_dbgmsg("UNRAR: Offset: %x\n", offset);
	comment_header = read_header(fd, COMM_HEAD);
	if(comment_header) {
	    unrar_dbgmsg("UNRAR: Comment type: 0x%.2x\n", comment_header->head_type);
	    unrar_dbgmsg("UNRAR: Head size: 0x%.4x\n", comment_header->head_size);
	    unrar_dbgmsg("UNRAR: UnPack Size: 0x%.4x\n", comment_header->unpack_size);
	    unrar_dbgmsg("UNRAR: UnPack Version: 0x%.2x\n", comment_header->unpack_ver);
	    unrar_dbgmsg("UNRAR: Pack Method: 0x%.2x\n", comment_header->method);
	    snprintf(filename, 1024, "%s"PATHSEP"main.cmt", state->comment_dir);
	    ofd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0600);
	    if(ofd < 0) {
		unrar_dbgmsg("UNRAR: ERROR: Failed to open output file\n");
		free(comment_header);
		free(main_hdr);
		ppm_destructor(&unpack_data->ppm_data);
		rar_init_filters(unpack_data);
		unpack_free_data(unpack_data);
		free(unpack_data);
		free(state->comment_dir);
		return UNRAR_ERR;
	    } else {
		if(comment_header->method == 0x30) {
		    unrar_dbgmsg("UNRAR: Copying stored comment (not packed)\n");
		    copy_file_data(fd, ofd, comment_header->unpack_size);
		} else {
		    unpack_data->ofd = ofd;
		    unpack_data->dest_unp_size = comment_header->unpack_size;
		    unpack_data->pack_size = comment_header->head_size - SIZEOF_COMMHEAD;
                    retval = rar_unpack(fd, comment_header->unpack_ver, FALSE, unpack_data);
		    unpack_free_data(unpack_data);
		}
		close(ofd);
	    }
	    free(comment_header);
	}
        if (lseek(fd, offset, SEEK_SET) == -1) {
            unrar_dbgmsg("UNRAR: seek: call to lseek() failed in unrar_open: %ld\n", offset);
            free(main_hdr);
            ppm_destructor(&unpack_data->ppm_data);
            rar_init_filters(unpack_data);
            unpack_free_data(unpack_data);
            free(unpack_data);
            free(state->comment_dir);
            return UNRAR_ERR;
        }
    }

    if(main_hdr->head_size > SIZEOF_NEWMHD) {
	if(!lseek(fd, main_hdr->head_size - SIZEOF_NEWMHD, SEEK_CUR)) {
	    free(main_hdr);
	    ppm_destructor(&unpack_data->ppm_data);
	    rar_init_filters(unpack_data);
	    unpack_free_data(unpack_data);
	    free(unpack_data);
	    free(state->comment_dir);
	    return UNRAR_ERR;
	}
    }

    state->unpack_data = unpack_data;
    state->main_hdr = main_hdr;
    state->metadata_tail = state->metadata = NULL;
    state->file_count = 1;
    state->fd = fd;

    return UNRAR_OK;
}

int unrar_extract_next_prepare(unrar_state_t *state, const char *dirname)
{
	char filename[1024];
	int ofd;
	unrar_metadata_t *new_metadata;


    state->file_header = read_block(state->fd, FILE_HEAD);
    if(!state->file_header)
	return UNRAR_BREAK; /* end of archive */

    new_metadata = (unrar_metadata_t *) malloc(sizeof(unrar_metadata_t));
    if(!new_metadata)
	return UNRAR_EMEM;

    new_metadata->pack_size = state->file_header->high_pack_size * 0x100000000ULL + state->file_header->pack_size;
    new_metadata->unpack_size = state->file_header->high_unpack_size * 0x100000000ULL + state->file_header->unpack_size;
    new_metadata->crc = state->file_header->file_crc;
    new_metadata->method = state->file_header->method;
    new_metadata->filename = strdup((const char*)state->file_header->filename);
    if(!new_metadata->filename) {
	free(new_metadata);
	return UNRAR_EMEM;
    }
    new_metadata->next = NULL;
    new_metadata->encrypted = FALSE;
    if(state->metadata_tail == NULL) {
	state->metadata_tail = state->metadata = new_metadata;
    } else {
	state->metadata_tail->next = new_metadata;
	state->metadata_tail = new_metadata;
    }
    if(state->file_header->flags & LHD_COMMENT) {
	unrar_comment_header_t *comment_header;

	unrar_dbgmsg("UNRAR: File comment present\n");
	comment_header = read_header(state->fd, COMM_HEAD);
	if(comment_header) {
	    unrar_dbgmsg("UNRAR: Comment type: 0x%.2x\n", comment_header->head_type);
	    unrar_dbgmsg("UNRAR: Head size: 0x%.4x\n", comment_header->head_size);
	    unrar_dbgmsg("UNRAR: UnPack Size: 0x%.4x\n", comment_header->unpack_size);
	    unrar_dbgmsg("UNRAR: UnPack Version: 0x%.2x\n", comment_header->unpack_ver);
	    unrar_dbgmsg("UNRAR: Pack Method: 0x%.2x\n", comment_header->method);

	    if((comment_header->unpack_ver < 15) || (comment_header->unpack_ver > 29) || (comment_header->method > 0x30)) {
		unrar_dbgmsg("UNRAR: Can't process file comment - skipping\n");
	    } else {
		snprintf(filename, 1024, "%s"PATHSEP"%lu.cmt", state->comment_dir, state->file_count);
		ofd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0600);
		if(ofd < 0) {
		    unrar_dbgmsg("UNRAR: ERROR: Failed to open output file\n");
		} else {
		    unrar_dbgmsg("UNRAR: Copying file comment (not packed)\n");
		    copy_file_data(state->fd, ofd, comment_header->unpack_size);
		    close(ofd);
		}
	    }
	    free(comment_header);
	}
    }

    return UNRAR_OK;
}

int unrar_extract_next(unrar_state_t *state, const char *dirname)
{
	int ofd;
	int retval;
	unpack_data_t *unpack_data;


    if(lseek(state->fd, state->file_header->start_offset+state->file_header->head_size, SEEK_SET) != state->file_header->start_offset+state->file_header->head_size) {
	unrar_dbgmsg("UNRAR: Seek failed: %ld\n", state->file_header->start_offset+state->file_header->head_size);
	free(state->file_header->filename);
	free(state->file_header);
	return UNRAR_ERR;
    }

    if(state->file_header->flags & LHD_PASSWORD) {
	unrar_dbgmsg("UNRAR: PASSWORDed file: %s\n", state->file_header->filename);
	state->metadata_tail->encrypted = TRUE;
    } else if(state->file_header->flags & (LHD_SPLIT_BEFORE | LHD_SPLIT_AFTER)) {
	unrar_dbgmsg("UNRAR: Skipping split file\n");

    } else if((state->main_hdr->flags & MHD_VOLUME) && (state->main_hdr->flags & MHD_SOLID)) {
	unrar_dbgmsg("UNRAR: Skipping file inside multi-volume solid archive\n");

    } else {
	snprintf(state->filename, 1024, "%s"PATHSEP"%lu.ura", dirname, state->file_count);
	ofd = open(state->filename, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, 0600);
	if(ofd < 0) {
	    free(state->file_header->filename);
	    free(state->file_header);
	    unrar_dbgmsg("UNRAR: ERROR: Failed to open output file\n");
	    return UNRAR_ERR;
	}
	unpack_data = (unpack_data_t *) state->unpack_data;
	state->ofd = unpack_data->ofd = ofd;
	unpack_data->max_size = state->maxfilesize;
	if(state->file_header->method == 0x30) {
	    unrar_dbgmsg("UNRAR: Copying stored file (not packed)\n");
	    copy_file_data(state->fd, ofd, state->file_header->pack_size);
	} else {
	    unpack_data->dest_unp_size = state->file_header->unpack_size;
	    unpack_data->pack_size = state->file_header->pack_size;
	    if(state->file_header->unpack_ver <= 15) {
		retval = rar_unpack(state->fd, 15, (state->file_count>1) && ((state->main_hdr->flags&MHD_SOLID)!=0), unpack_data);
	    } else {
		if((state->file_count == 1) && (state->file_header->flags & LHD_SOLID)) {
		    unrar_dbgmsg("UNRAR: Bad header. First file can't be SOLID.\n");
		    unrar_dbgmsg("UNRAR: Clearing flag and continuing.\n");
		    state->file_header->flags -= LHD_SOLID;
		}
		retval = rar_unpack(state->fd, state->file_header->unpack_ver, state->file_header->flags & LHD_SOLID, unpack_data);
	    }
	    unrar_dbgmsg("UNRAR: Expected File CRC: 0x%x\n", state->file_header->file_crc);
	    unrar_dbgmsg("UNRAR: Computed File CRC: 0x%x\n", unpack_data->unp_crc^0xffffffff);
	    if(unpack_data->unp_crc != 0xffffffff) {
		if(state->file_header->file_crc != (unpack_data->unp_crc^0xffffffff)) {
		    unrar_dbgmsg("UNRAR: RAR CRC error. If the file is not corrupted, please report at http://bugs.clamav.net/\n");
		}
	    }
	    if(!retval) {
		unrar_dbgmsg("UNRAR: Corrupt file detected\n");
		if(state->file_header->flags & LHD_SOLID) {
		    unrar_dbgmsg("UNRAR: SOLID archive, can't continue\n");
		    free(state->file_header->filename);
		    free(state->file_header);
		    return UNRAR_ERR;
		}
	    }
	}
    }

    if(lseek(state->fd, state->file_header->next_offset, SEEK_SET) != state->file_header->next_offset) {
	unrar_dbgmsg("UNRAR: ERROR: seek failed: %ld\n", state->file_header->next_offset);
	free(state->file_header->filename);
	free(state->file_header);
	return UNRAR_ERR;
    }

    free(state->file_header->filename);
    free(state->file_header);
    unpack_free_data(state->unpack_data);
    state->file_count++;
    return UNRAR_OK;
}

void unrar_close(unrar_state_t *state)
{
	unpack_data_t *unpack_data = state->unpack_data;

    ppm_destructor(&unpack_data->ppm_data);
    free(state->main_hdr);
    rar_init_filters(state->unpack_data);
    unpack_free_data(state->unpack_data);
    free(state->unpack_data);
    free(state->comment_dir);
}
