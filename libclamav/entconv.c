/*
 *  HTML Entity & Encoding normalization.
 *
 *  Copyright (C) 2006 Török Edvin <edwin@clamav.net>
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
 *
 */
#include "clamav-config.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>


#ifdef CL_THREAD_SAFE
#include <pthread.h>
#endif

#ifndef CL_DEBUG
#define NDEBUG
#endif

#include <assert.h>

#include "clamav.h"
#include "others.h"
#include "htmlnorm.h"
#include "hashtab.h"
#include "entconv.h"
#include "entitylist.h"
#include "cltypes.h"

#ifdef HAVE_ICONV
#include <iconv.h>
#endif

#include "encoding_aliases.h"

#define MODULE_NAME "entconv: "

#define MAX_LINE 1024

#ifndef EILSEQ
#define EILSEQ 84
#endif

#ifndef HAVE_ICONV
typedef struct {
	enum encodings encoding;
	size_t size;
} * iconv_t;
#endif

/* TODO: gcc refuses to inline because it consider call unlikely and code size grows */
static inline unsigned char* u16_normalize(uint16_t u16, unsigned char* out, const ssize_t limit)
{
	assert(limit > 0 && "u16_normalize must be called with positive limit");
	/* \0 is just ignored */
	if(u16 > 0 && u16 < 0xff) {
		assert((uint8_t)u16 != 0);
		*out++ = (uint8_t)u16;
	}
	else {
		/* normalize only >255 to speed up */
		char buf[10];
		const ssize_t max_num_length = sizeof(buf)-1;
		size_t i = sizeof(buf)-1;

		if(limit <=  max_num_length) {
			/* not enough space available */
			return NULL;
		}
		/* inline version of
		 * out += snprintf(out, max_num_length, "&#%d;", u16) */
		buf[i] = '\0';
		while(u16 && i > 0 ) {
			buf[--i] = '0' + (u16 % 10);
			u16 /= 10;
		}
		*out++ = '&';
		*out++ = '#';
		while(buf[i]) *out++ = buf[i++];
		*out++ = ';';
	}
	return out;
}

const char* entity_norm(struct entity_conv* conv,const unsigned char* entity)
{
	struct element* e = hashtab_find(conv->ht, (const char*)entity, strlen((const char*)entity));
	if(e && e->key) {
		const uint16_t val = e->data;
		unsigned char* out = u16_normalize(val, conv->entity_buff, sizeof(conv->entity_buff)-1);
		if(out) {
			*out++ = '\0';
		}
		return (const char*) out;
	}
	return NULL;
}

/* sane default, must be larger, than the longest possible return string,
 * which is
 * &#xxx;*/
#define MIN_BUFFER_SIZE 32

#define LINEMODE_LIMIT 16384

int init_entity_converter(struct entity_conv* conv, size_t buffer_size)
{
	if(buffer_size < MIN_BUFFER_SIZE) {
		cli_warnmsg("Entity converter: Supplied buffer size:%lu, smaller than minimum required: %d\n",(unsigned long)buffer_size,MIN_BUFFER_SIZE);
		return CL_ENULLARG;
	}
	if(conv) {
		conv->encoding = NULL;
		conv->encoding_symbolic = E_UNKNOWN;
		conv->bom_cnt = 0;
		conv->buffer_cnt = 0;
		conv->bytes_read = 0;
		conv->partial = 0;
		conv->buffer_size = buffer_size;
		conv->priority = NOPRIO;
		/* start in linemode */
		conv->linemode = 1;
		conv->linemode_processed = 0;

		conv->tmp_area.offset = 0;
		conv->tmp_area.length = 0;
		conv->tmp_area.buffer  =  cli_malloc(buffer_size);
		if(!conv->tmp_area.buffer) {
			return CL_EMEM;
		}

		conv->out_area.offset = 0;
		conv->out_area.length = buffer_size;
		conv->out_area.buffer = cli_malloc(buffer_size);
		if(!conv->out_area.buffer) {
			free(conv->tmp_area.buffer);
			return CL_EMEM;
		}

		conv->buffer_size = buffer_size;
		conv->norm_area.offset = 0;
		conv->norm_area.length = 0;
		conv->norm_area.buffer = cli_malloc(buffer_size);
		if(!conv->norm_area.buffer) {
			free(conv->tmp_area.buffer);
			free(conv->out_area.buffer);
			return CL_EMEM;
		}

		conv->ht = &entities_htable;
		conv->msg_zero_shown = 0;

		conv->iconv_struct = cli_calloc(1, sizeof(iconv_t));
		if(!conv->iconv_struct) {
			free(conv->tmp_area.buffer);
			free(conv->out_area.buffer);
			free(conv->norm_area.buffer);
			return CL_EMEM;
		}
		return 0;
	}
	else 
		return CL_ENULLARG;
}

static size_t encoding_bytes(const char* fromcode, enum encodings* encoding)
{
	/* special case for these unusual byteorders */
	struct element * e = hashtab_find(&aliases_htable,fromcode,strlen(fromcode));
	if(e && e->key) {
		*encoding = e->data;
	} else {
		*encoding = E_OTHER;
	}

	switch(*encoding) {
		case E_UCS4:
		case E_UCS4_1234:
		case E_UCS4_4321:
		case E_UCS4_2143:
		case E_UCS4_3412:
			return 4;
		case E_UTF16:
		case E_UTF16_BE:
		case E_UTF16_LE:
			return 2;
		case E_UTF8:
		case E_UNKNOWN:
		case E_OTHER:
		default:
			return 1;
	}
}

#ifndef HAVE_ICONV
static iconv_t iconv_open(const char *tocode, const char* fromcode)
{
	iconv_t iconv = cli_malloc(sizeof(*iconv));
	if(!iconv)
		return NULL;
	cli_dbgmsg(MODULE_NAME "Internal iconv\n");
	/* TODO: check that tocode is UTF16BE */
	iconv->size = encoding_bytes(fromcode,&iconv->encoding);
	return iconv;
}

static int iconv_close(iconv_t cd)
{
	if(cd)
		free(cd);
	return 0;
}


static int iconv(iconv_t iconv_struct,char **inbuf, size_t *inbytesleft,
		char** outbuf, size_t *outbytesleft)
{
	const size_t maxcopy = (*inbytesleft > *outbytesleft ? *outbytesleft  : *inbytesleft) & ~(iconv_struct->size - 1);
	const uint8_t* input = (const uint8_t*)*inbuf;
	uint8_t* output = (uint8_t*)*outbuf;
	size_t i;

	/*,maxcopy is aligned to data size */
	/* output is always utf16be !*/
	switch(iconv_struct->encoding) {
		case E_UCS4:
		case E_UCS4_1234:
			{
				for(i=0;i < maxcopy; i += 4) {
					if(!input[i+2] && !input[i+3]) {
						output[i/2] = input[i+1]; /* is compiler smart enough to replace /2, with >>1 ? */
						output[i/2+1] = input[i];
					}
					else {
						cli_dbgmsg(MODULE_NAME "Warning: unicode character out of utf16 range!\n");
						output[i/2] = 0xff;
						output[i/2+1] = 0xff;
					}
				}
				break;
			}
		case E_UCS4_4321:
			{
				const uint16_t *in = (const uint16_t*)input;/*UCS4_4321, and UTF16_BE have same endianness, no need for byteswap here*/
				uint16_t *out = (uint16_t*)output;
				for(i=0;i<maxcopy/2; i+=2) {
					if(!in[i]) {
						out[i/2] = in[i+1];
					}
					else {
						out[i/2] = 0xffff;
					}
				}
				break;
			}
		case E_UCS4_2134: 
			{
				const uint16_t *in = (const uint16_t*)input;
				uint16_t* out = (uint16_t*)output;
				for(i=0;i<maxcopy/2;i+=2) {
					if(!in[i+1])
						out[i/2] = in[i];
					else
						out[i/2] = 0xffff;
				}
				break;
			}
		case E_UCS4_3412:
			{
				for(i=0;i < maxcopy;i += 4) {
					if(!input[i] && !input[i+1]) {
						output[i/2] = input[i+3];
						output[i/2+1] = input[i+2];
					}
					else {
						output[i/2] = 0xff;
						output[i/2+1] = 0xff;
					}
				}
				break;
			}
		case E_UTF16:
		case E_UTF16_LE:
			{
				for(i=0;i < maxcopy;i += 2) {
					output[i] = input[i+1];
					output[i+1] = input[i];
				}
				break;
			}
		case E_UTF16_BE:
			memcpy(output,input,maxcopy);
			break;
		case E_UNKNOWN:
		case E_OTHER:
			{
				const size_t max_copy = *inbytesleft > (*outbytesleft/2) ? (*outbytesleft/2) : *inbytesleft;
				for(i=0;i<max_copy;i++) {
					output[i*2]   = 0;
					output[i*2+1] = input[i];
				}
				*outbytesleft -= max_copy*2;
				*inbytesleft  -= max_copy;
				*inbuf += max_copy;
				*outbuf += max_copy*2;
				if(*inbytesleft)
					return E2BIG;
				return 0;
			}
		case E_UTF8:
			{
				const size_t maxread  = *inbytesleft;
				const size_t maxwrite = *outbytesleft;
				size_t j;
				for(i=0,j=0 ; i < maxread && j < maxwrite;) {
					if(input[i] < 0x7F)  {
						output[j++] = 0;
						output[j++] = input[i++];
							}
					else if( (input[i]&0xE0) == 0xC0 ) {
						if ((input[i+1]&0xC0) == 0x80) {
							/* 2 bytes long 110yyyyy zzzzzzzz -> 00000yyy yyzzzzzz*/
							output[j++] = ((input[i] & 0x1F) >> 2) & 0x07;
							output[j++] = ((input[i] & 0x1F) << 6) | (input[i+1] & 0x3F);
						}
						else {
							cli_dbgmsg(MODULE_NAME "invalid UTF8 character encountered\n");
							break;
						}
						i+=2;
					}
					else if( (input[i]&0xE0) == 0xE0) {
						if( (input[i+1]&0xC0) == 0x80 && (input[i+2]&0xC0) == 0x80) {
							/* 3 bytes long 1110xxxx 10yyyyyy 10zzzzzzzz -> xxxxyyyy yyzzzzzz*/
							output[j++] = (input[i] << 4) | ((input[i+1] >> 2) & 0x0F);
							output[j++] = (input[i+1] << 6) | (input[i+2] & 0x3F);
						}
						else {
							cli_dbgmsg(MODULE_NAME "invalid UTF8 character encountered\n");
							break;
						}
						i+=3;
					}
					else if( (input[i]&0xF8) == 0xF0) {
						if((input[i+1]&0xC0) == 0x80 && (input[i+2]&0xC0) == 0x80 && (input[i+3]&0xC0) == 0x80) {
							/* 4 bytes long 11110www 10xxxxxx 10yyyyyy 10zzzzzz -> 000wwwxx xxxxyyyy yyzzzzzz*/
							cli_dbgmsg(MODULE_NAME "UTF8 character out of UTF16 range encountered");
							output[j++] = 0xff;
							output[j++] = 0xff;

							/*out[j++] = ((input[i] & 0x07) << 2) | ((input[i+1] >> 4) & 0x3);
							out[j++] = (input[i+1] << 4) | ((input[i+2] >> 2) & 0x0F);
							out[j++] = (input[i+2] << 6) | (input[i+2] & 0x3F);*/
						}
						else {
							cli_dbgmsg(MODULE_NAME "invalid UTF8 character encountered\n");
							break;
						}
						i+=4;
					}
					else {
						cli_dbgmsg(MODULE_NAME "invalid UTF8 character encountered\n");
						break;
					}							
				}
				*inbytesleft -= i;
				*outbytesleft -= j;
				*inbuf += i;
				*outbuf += j;
				if(*inbytesleft && *outbytesleft) {
					errno = EILSEQ;/* we had an early exit */
					return -1;
				}
				if(*inbytesleft) {
					errno = E2BIG;
					return -1;
				}
				return 0;
			}
	}
	
	*outbytesleft -= maxcopy;
	*inbytesleft  -= maxcopy;
	*inbuf += maxcopy;
	*outbuf += maxcopy;
	if(*inbytesleft) {
		errno = E2BIG;
		return -1;
	}
	return  0;
}

#else



#endif

/* new iconv() version */
static inline void process_bom(struct entity_conv* conv)
{
	const unsigned char* bom = conv->bom;
	const char* encoding = NULL;
	int has_bom = 0;
	uint8_t enc_bytes = 1;/* default is UTF8, which has a minimum of 1 bytes*/

	/* undecided 32-bit encodings are treated as ucs4, and
	 * 16 bit as utf16*/
	switch(bom[0]) {
		case 0x00:
			if(bom[1] == 0x00) {
				if(bom[2] == 0xFE && bom[3] == 0xFF) {
					encoding = UCS4_1234;/* UCS-4 big-endian*/
					has_bom = 1;
				}
				else if(bom[2] == 0xFF && bom[3] == 0xFE) {
					encoding = UCS4_2143;/* UCS-4 unusual order 2143 */
					has_bom = 1;
				}
				else if(bom[2] == 0x00 && bom[3] == 0x3C) {
					/* undecided, treat as ucs4 */
					encoding = UCS4_1234;
				}
				else if(bom[2] == 0x3C && bom[3] == 0x00) {
					encoding = UCS4_2143;
				}
			}/* 0x00 0x00 */
			else if(bom[1] == 0x3C) {
				if(bom[2] == 0x00) {
					if(bom[3] == 0x00) {
						encoding = UCS4_3412;
					}
					else if(bom[3] == 0x3F) {
						encoding = UTF16_BE;
						enc_bytes = 2;
					}
				}/*0x00 0x3C 0x00*/
			}/*0x00 0x3C*/
			break;
		case 0xFF:
			if(bom[1] == 0xFE) {
				if(bom[2] == 0x00 && bom[3] == 0x00) {
					encoding = UCS4_4321;
					has_bom = 1;
				}
				else {
					encoding = UTF16_LE;
					has_bom = 1;
					enc_bytes = 2;
				}
			}/*0xFF 0xFE*/
			break;
		case 0xFE:
			if(bom[1] == 0xFF) {
					if(bom[2] == 0x00 && bom[3] == 0x00) {
						encoding = UCS4_3412;
						has_bom = 1;
					}
					else {
						encoding = UTF16_BE;
						has_bom = 1;
						enc_bytes = 2;
					}
			}/*0xFE 0xFF*/
			break;
		case 0xEF:
			if(bom[1] == 0xBB && bom[2] == 0xBF)  {
					encoding = UTF8;
					has_bom = 1;
					/*enc_bytes = 4;- default, maximum 4 bytes*/
			}/*0xEF 0xBB 0xBF*/
			break;
		case 0x3C:
				if(bom[1] == 0x00) {
					if(bom[2] == 0x00 && bom[3] == 0x00) {
						encoding = UCS4_4321;
					}
					else if(bom[2] == 0x3F && bom[3] == 0x00) {
						encoding = UTF16_LE;
						enc_bytes = 2;
					}
				}/*0x3C 0x00*/
				else if(bom[1] == 0x3F && bom[2] == 0x78 && bom[3]==0x6D) {
					encoding = NULL;
					enc_bytes = 1;
				}/*0x3C 3F 78 6D*/
				break;
		case 0x4C:
				if(bom[1] == 0x6F && bom[2] == 0xA7 && bom[3] == 0x94) {
					cli_dbgmsg(MODULE_NAME "EBCDIC encoding is not supported in line mode\n");
					encoding = NULL;
					enc_bytes = 1;
				}/*4C 6F A7 94*/
				break;
	}/*switch*/
	if(encoding) {
		cli_dbgmsg(MODULE_NAME "encoding detected as :%s\n", encoding);
		process_encoding_set(conv, (const unsigned char*)encoding, has_bom ? BOM : NOBOM_AUTODETECT);
	}
	conv->enc_bytes = enc_bytes;
	conv->has_bom = has_bom;
}

/*()-./012345678:ABCDEFGHIJKLMNOPQRSTUVWXY_abcdefghijklmnopqrstuvwxy*/
static const uint8_t encname_chars[256] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* checks that encoding is sane, and normalizes to uppercase */
static char* normalize_encoding(const unsigned char* enc)
{
	char* norm;
	size_t i, len;

	if(!enc)
		return NULL;
	len = strlen((const char*)enc);
	if(len > 32)
		return NULL;
	for(i=0;i<len;i++) {
		if(!encname_chars[enc[i]])
			return NULL;
	}
	norm = cli_malloc( len+1 );
	if(!norm)
		return NULL;
	for(i=0;i < len; i++)
		norm[i] = toupper(enc[i]);
	norm[len]='\0';
	return norm;
}

static int encoding_norm_done(struct entity_conv* conv)
{
	if(conv->encoding) {
		free(conv->encoding);
		conv->encoding = NULL;
	}
	conv->buffer_size = 0;
	if(conv->tmp_area.buffer) {
		free(conv->tmp_area.buffer);
		conv->tmp_area.buffer = NULL;
	}
	if(conv->out_area.buffer) {
		free(conv->out_area.buffer);
		conv->out_area.buffer = NULL;
	}
	if(conv->norm_area.buffer) {
		free(conv->norm_area.buffer);
		conv->norm_area.buffer = NULL;
	}
	return 0;
}

int entity_norm_done(struct entity_conv* conv)
{
	return encoding_norm_done(conv);
}

static unsigned short bom_length(struct entity_conv* conv)
{
	if(conv->has_bom) {
		switch(conv->enc_bytes) {
			case 1:
				if(conv->encoding_symbolic == E_UTF8) {
					return 3;
				}
				break;
			case 2:
				return 2;
			case 4:
				return 4;
		}
	}
	return 0;
}
/* sarge leaks on iconv_open/iconv_close, so lets not open/close so many times,
 * just keep on each thread its own pool of iconvs*/

struct iconv_cache {
	iconv_t* tab;
	size_t     len;
	size_t   last;
	struct   hashtable hashtab;
};

static void iconv_cache_init(struct iconv_cache* cache)
{
/*	cache->tab = NULL;
	cache->len = 0;
	cache->used = 0; - already done by memset*/
	cli_dbgmsg(MODULE_NAME "Initializing iconv pool:%p\n",(void*)cache);
	hashtab_init(&cache->hashtab, 32);
}

static void iconv_cache_destroy(struct iconv_cache* cache)
{
	size_t i;
	cli_dbgmsg(MODULE_NAME "Destroying iconv pool:%p\n",(void*)cache);
	for(i=0;i < cache->last;i++) {
		cli_dbgmsg(MODULE_NAME "closing iconv:%p\n",cache->tab[i]);
		iconv_close(cache->tab[i]);
	}
	hashtab_clear(&cache->hashtab);
	free(cache->hashtab.htable);
	free(cache->tab);
	free(cache);
}


#ifdef CL_THREAD_SAFE
static pthread_key_t iconv_pool_tls_key;
static pthread_once_t iconv_pool_tls_key_once = PTHREAD_ONCE_INIT;

/* destructor called for all threads that exit via pthread_exit, or cancellation. Unfortunately that doesn't include
 * the main thread, so we have to call this manually for the main thread.*/

static int cache_atexit_registered = 0;

static void iconv_pool_tls_instance_destroy(void* ptr)
{
	if(ptr) {
		iconv_cache_destroy(ptr);
	}
}

static void iconv_cache_cleanup_main(void)
{
	struct iconv_cache* cache = pthread_getspecific(iconv_pool_tls_key);
	if(cache) {
		iconv_pool_tls_instance_destroy(cache);
		pthread_setspecific(iconv_pool_tls_key,NULL);
	}
	pthread_key_delete(iconv_pool_tls_key);
}

static void iconv_pool_tls_key_alloc(void)
{
	pthread_key_create(&iconv_pool_tls_key, iconv_pool_tls_instance_destroy);
	if(!cache_atexit_registered) {
		cli_dbgmsg(MODULE_NAME "iconv:registering atexit\n");
		if(atexit(iconv_cache_cleanup_main)) {
			cli_dbgmsg(MODULE_NAME "failed to register atexit\n");
		}
		cache_atexit_registered = 1;
	}
}

static void init_iconv_pool_ifneeded(void)
{
	pthread_once(&iconv_pool_tls_key_once, iconv_pool_tls_key_alloc);
}

static inline struct iconv_cache* cache_get_tls_instance(void)
{
	struct iconv_cache* cache = pthread_getspecific(iconv_pool_tls_key);
	if(!cache) {
		cache = cli_calloc(1,sizeof(*cache));
		if(!cache) {
			cli_dbgmsg(MODULE_NAME "!Out of memory allocating TLS iconv instance\n");
			return NULL;
		}
		iconv_cache_init(cache);
		pthread_setspecific(iconv_pool_tls_key, cache);
	}
	return cache;
}

#else

static struct iconv_cache* global_iconv_cache = NULL;
static int    iconv_global_inited = 0;


static void iconv_cache_cleanup_main(void)
{
	iconv_cache_destroy(global_iconv_cache);
}

static inline void init_iconv_pool_ifneeded() 
{
	if(!iconv_global_inited) {
		global_iconv_cache = cli_calloc(1,sizeof(*global_iconv_cache));
		if(global_iconv_cache) {
			iconv_cache_init(global_iconv_cache);
			atexit(iconv_cache_cleanup_main);
			iconv_global_inited = 1;
		}
	}
}


static inline struct iconv_cache* cache_get_tls_instance(void)
{
	return global_iconv_cache;
}

#endif

static iconv_t iconv_open_cached(const char* fromcode)
{
	struct iconv_cache * cache;
	size_t idx;
	const size_t fromcode_len = strlen((const char*)fromcode);
	struct element * e;
	iconv_t  iconv_struct;

	init_iconv_pool_ifneeded();
	cache = cache_get_tls_instance();/* gets TLS iconv pool */
	if(!cache) {
		cli_dbgmsg(MODULE_NAME "!Unable to get TLS iconv cache!\n");
		errno = EINVAL;
		return (iconv_t)-1;
	}

	e = hashtab_find(&cache->hashtab, fromcode, fromcode_len);
	if(e && (e->data < 0 || (size_t)e->data > cache->len)) {
		e = NULL;
	}
	if(e) {
		return cache->tab[e->data];
	}
	cli_dbgmsg(MODULE_NAME "iconv not found in cache, for encoding:%s\n",fromcode);
	iconv_struct = iconv_open("UTF-16BE",(const char*)fromcode);
	if(iconv_struct != (iconv_t)-1) {
	idx = cache->last++;
	if(idx >= cache->len) {
		cache->len += 16;
		cache->tab = cli_realloc2(cache->tab, cache->len*sizeof(cache->tab[0]));
		if(!cache->tab) {
			cli_dbgmsg(MODULE_NAME "!Out of mem in iconv-pool\n");
			errno = ENOMEM;
			return (iconv_t)-1;
		}
	}

	hashtab_insert(&cache->hashtab, fromcode, fromcode_len, idx);
		cache->tab[idx] = iconv_struct;
	cli_dbgmsg(MODULE_NAME "iconv_open(),for:%s -> %p\n",fromcode,(void*)cache->tab[idx]);
	return cache->tab[idx];
}
	return (iconv_t)-1;
}

void process_encoding_set(struct entity_conv* conv,const unsigned char* encoding,enum encoding_priority prio)
{
	char *tmp_encoding;
	enum encodings tmp;
	size_t new_size,old_size;

	if(!encoding && prio == SWITCH_TO_BLOCKMODE) {
		if(conv->linemode) {
			cli_dbgmsg(MODULE_NAME "Switching to block-mode, bytes processed in line-mode: %u\n", conv->linemode_processed);
			conv->linemode = 0;
		}
		return;
	}

	cli_dbgmsg(MODULE_NAME "Request to set encoding for %p to %s, priority: %d\n", (void*)conv, encoding, prio);

	if(conv->priority == CONTENT_TYPE || conv->encoding || conv->encoding_symbolic == E_ICONV) {
		cli_dbgmsg(MODULE_NAME "won't override encoding due to priorities\n");
		return;
		/* Content-type in header is highest priority, no overrides possible.
		 * Also no overrides after an encoding has been set.*/
	}

	/* validate encoding name, and normalize to uppercase */
	if(!(tmp_encoding = normalize_encoding(encoding))) {
		cli_dbgmsg(MODULE_NAME "encoding name is not valid, ignoring\n");
		return;
	}

	/* don't allow to change between unicode encodings that have different byte-size */
	if(prio == META) {
		/* need to consider minimum size of an encoding here */
		old_size =  conv->enc_bytes;
		new_size = encoding_bytes(tmp_encoding,&tmp);
		if(old_size != new_size)  {
			/* on x86 gcc wants %u for size_t, on x86_64 it wants %lu for size_t. So just cast to unsigned long to make warnings go away. */
			cli_dbgmsg(MODULE_NAME "refusing to override encoding - new encoding size differs: %s(%lu) != %s(%lu)\n", conv->encoding, (unsigned long)old_size, tmp_encoding, (unsigned long)new_size);
			free(tmp_encoding);
			return;
		}
	}

	conv->encoding = tmp_encoding;
	cli_dbgmsg(MODULE_NAME "New encoding for %p:%s\n", (void*)conv, conv->encoding);
	*(iconv_t*)conv->iconv_struct = iconv_open_cached( conv->encoding );
	if(*(iconv_t*)conv->iconv_struct == (iconv_t)-1) {
		cli_dbgmsg(MODULE_NAME "Encoding not accepted by iconv_open()%s, falling back to default!\n", conv->encoding);
		/* message shown only once/file */
		/* what can we do? short-circuit iconv */
		free(conv->encoding);
		conv->encoding = NULL;
		/* we will process using whatever we currently have for encoding_symbolic.
		 * If encoding was already set to iconv, we shouldn't be here.*/
		assert(conv->encoding_symbolic != E_ICONV);
	} else {
		cli_dbgmsg(MODULE_NAME "Switching to block-mode, bytes processed in line-mode: %u\n", conv->linemode_processed);
		conv->encoding_symbolic = E_ICONV;
		conv->priority = prio;
		conv->linemode = 0;
	}
}

static int in_iconv_u16(m_area_t* in_m_area, iconv_t* iconv_struct, m_area_t* out_m_area)
{
	char   tmp4[4];
	size_t inleft = in_m_area->length - in_m_area->offset;
	size_t rc, alignfix;
	char*  input   = (char*)in_m_area->buffer + in_m_area->offset;
	size_t outleft = out_m_area->length > 0 ? out_m_area->length : 0;/*TODO: use real buffer size not last one*/
	char* out      = (char*)out_m_area->buffer;

	if(!inleft) {
		/* EOF */
		out_m_area->offset = out_m_area->length = 0;
	}
	/* convert encoding conv->tmp_area. conv->out_area */
	alignfix = inleft%4;/* iconv gives an error if we give him 3 bytes to convert, 
			       and we are using ucs4, ditto for utf16, and 1 byte*/
	inleft -= alignfix;

	if(!inleft && alignfix) {
		/* EOF, and we have less than 4 bytes to convert */
		memset(tmp4, 0, 4);
		memcpy(tmp4, input, alignfix);
		input = tmp4;
		inleft = 4;
	}

	rc = (size_t)-1;
	while (inleft && (outleft >= 2) && rc == (size_t)-1) { /* iconv doesn't like inleft to be 0 */
		assert(*iconv_struct != (iconv_t)-1);
		rc = iconv(*iconv_struct, (char**) &input,  &inleft, (char**) &out, &outleft);
		if(rc == (size_t)-1 && errno != E2BIG) {
			cli_dbgmsg("iconv error:%s, silently resuming (%lu, %lu, %ld, %ld)\n",
					strerror(errno), inleft, outleft, input - (char*)in_m_area->buffer,
					out - (char*)out_m_area->buffer);
			/* output raw byte, and resume at next byte */
			if(outleft < 2) break;
			outleft -= 2;
			*out++ = 0;
			*out++ = *input++;
			inleft--;
		}
	}
	in_m_area->offset = in_m_area->length - inleft;
	if(out_m_area->length >= 0 && out_m_area->length >= (off_t)outleft) {
		out_m_area->length -= (off_t)outleft;
	} else {
		cli_dbgmsg(MODULE_NAME "outleft overflown, ignoring\n");
		out_m_area->length = 0;
	}
	out_m_area->offset  = 0;
	return 0;
}


#define NORMALIZE_CHAR(c, out, limit, linemode) \
{\
	        if (linemode && c == '\n') {\
			i++;\
			break;\
		} else {\
			unsigned char* out_new = u16_normalize(c, out, limit);\
			if(out_new) {\
				limit -= out_new - out;\
			}\
			out = out_new;\
		}\
}

/* don't use CLI_ISCONTAINED2 here, because values are signed, and gcc4.3
 * assumes signed overflow doesn't occur when optimizing (see -Wstrict-overflow) */
#define LIMIT_LENGTH(siz, siz_limit) ((siz) <= (siz_limit) ? (siz) : (siz_limit))
#define OFFSET_INBOUNDS(offset, length) ((offset) >= 0 && (length) >= 0 && (offset) < (length))

/* EOF marker is m_area->length == 0 */

/* reads input from either @m_area or @stream, and returns an m_area_t pointing to the data read.
 * When we can't read anything due to EOF ->length will be set to 0.
 * bounds checks offset and length*/
static inline m_area_t* read_raw(struct entity_conv* conv, m_area_t* m_area, FILE* stream)
{
	if(!m_area) {
		size_t iread;

		m_area = &conv->tmp_area;
		if(OFFSET_INBOUNDS(m_area->offset, m_area->length)) {
			return m_area;
		}
		/* offset out of bounds -> all the buffer was processed, fill it again */
		iread = fread(m_area->buffer, 1, conv->buffer_size, stream);
		m_area->length = LIMIT_LENGTH(iread, conv->buffer_size);
		m_area->offset = 0;
		if(ferror(stream)) {
			cli_errmsg("Error while reading HTML stream\n");
		}
	} else {
		if(!OFFSET_INBOUNDS(m_area->offset, m_area->length)) {
			cli_dbgmsg(MODULE_NAME "EOF reached\n");
			m_area->offset = m_area->length; /* EOF marker */
		}
	}
	return m_area;
}

static inline uint16_t get_u16(const unsigned char* buf, const size_t i)
{
	return ((uint16_t)buf[i] << 8) | buf[i+1];
}

unsigned char* encoding_norm_readline(struct entity_conv* conv, FILE* stream_in, m_area_t* in_m_area)
{
	unsigned char* out = conv->out_area.buffer;
	if(!conv || !conv->out_area.buffer || !conv->tmp_area.buffer || !out) {
		return NULL;
	}
	if(!(in_m_area = read_raw(conv, in_m_area, stream_in))) {
		/* error encountered */
		return NULL;
	}
	else {
		const off_t input_limit  = in_m_area->length;
		const unsigned char* input = in_m_area->buffer;
		off_t input_offset = in_m_area->offset;
		off_t limit = conv->out_area.length - 1;
		off_t limit_prev = limit;
		off_t i = 0;

		/* read_raw() ensures this condition */
		assert((!input_limit && !input_offset) || (input_offset >=0 && input_limit > 0 && input_offset <= input_limit));

		if(!conv->bom_cnt && input_offset + 4 < input_limit) {/* detect Byte Order Mark */
			size_t bom_len;
			memcpy(conv->bom, input, 4);
			process_bom(conv);
			bom_len = bom_length(conv);
			in_m_area->offset = input_offset = input_offset + bom_len;
			conv->bom_cnt = 1;
		}

		if(conv->linemode && conv->linemode_processed > LINEMODE_LIMIT) {
			cli_dbgmsg(MODULE_NAME "Line-mode limit exceeded (%u), switching to block-mode\n", conv->linemode_processed);
			conv->linemode = 0;
		}

		switch(conv->encoding_symbolic) {
			case E_ICONV:/* only in block-mode */
				/* normalize already converted characters from a previous pass
				 * (output buffer was full, and we couldn't normalize more in previous pass) */
				for(i = conv->norm_area.offset;i < conv->norm_area.length && limit > 0 && out; i += 2) {
					const uint16_t c = get_u16(conv->norm_area.buffer, i);
					NORMALIZE_CHAR(c, out, limit, 0);
				}
				conv->norm_area.offset = i;
			        if(limit > 0) {
					conv->norm_area.length = conv->buffer_size;
					in_iconv_u16(in_m_area, conv->iconv_struct, &conv->norm_area);

					/*in_iconv_u16 always fills entire norm_area buffer starting from 0. */
					for(i = 0;i < conv->norm_area.length && limit >  0 && out; i += 2) {
						const uint16_t c = get_u16(conv->norm_area.buffer, i);
						NORMALIZE_CHAR(c, out, limit, 0);
					}
					if(i) {
						conv->norm_area.offset = i;
					}
				}
				if(limit == limit_prev) {
					/* output pointer didn't move => EOF */
					return NULL;
				}
				break;
				/* out_area must have enough space to allow all bytes in norm_area normalized,
				 * if we norm with &x;, then we need 7* space. */
			default:
				cli_dbgmsg(MODULE_NAME "Unhandled encoding:%d\n",conv->encoding_symbolic);
				conv->encoding_symbolic = E_OTHER;
			case E_UNKNOWN:
			case E_OTHER:
				if(!input_limit) {
					/* nothing to do, EOF */
					return NULL;
				}
				for(i = input_offset; i < input_limit && limit > 0; i++) {
					const unsigned char c = input[i];
					if(conv->linemode && c == '\n') {
						i++;
						break;
					}
					*out++ = c;
					limit--;
				}
				in_m_area->offset = i;
		}


		if(conv->linemode) {
			conv->linemode_processed += i - input_offset;
		}

		if(limit < 0) limit = 0;
/*		assert((unsigned)(conv->out_area.length - limit - 1) < conv->buffer_size);
		assert(conv->out_area.length - limit - 1 >= 0); */
		conv->out_area.buffer[conv->out_area.length - limit - 1] = '\0';
		return conv->out_area.buffer;
	}
}

