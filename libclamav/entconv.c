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

#include "clamav.h"
#include "others.h"
#include "htmlnorm.h"
#include "hashtab.h"
#include "entconv.h"
#include "entitylist.h"
#include "cltypes.h"

#ifdef HAVE_ICONV_H
#include <iconv.h>
#endif
#include "encoding_aliases.h"


#define MAX_LINE 1024

#ifndef EILSEQ
#define EILSEQ 84
#endif

unsigned char* entity_norm(const struct entity_conv* conv,const unsigned char* entity)
{
	struct element* e = hashtab_find(conv->ht,entity,strlen((const char*)entity));
	if(e && e->key) {
		const int val = e->data;
		if(val == '<')/* this was an escaped <, so output it escaped*/
			return (unsigned char*)cli_strdup("&lt;");
		else if(val == '>')/* see above */
			return (unsigned char*)cli_strdup("&gt;");
		else if(val<127) {
			unsigned char *e_out = cli_malloc(2);

			if(!e_out)
			    return NULL;

			e_out[0] = (unsigned char)val;
			e_out[1] = '\0';
			return e_out;
		}
		else if(val==160)
			return (unsigned char*)cli_strdup(" ");
		else {
			unsigned char *ent_out = cli_malloc(10);

			if(!ent_out)
			    return NULL;

			snprintf((char*)ent_out,9,"&#%d;",val);
			ent_out[9] = '\0';
			return ent_out;
		}
	}
	else
		return NULL;
}

/* sane default, must be larger, than the longest possible return string,
 * which is
 * &#xxx;*/
#define MIN_BUFFER_SIZE 32

int init_entity_converter(struct entity_conv* conv,const unsigned char* encoding,size_t buffer_size)
{
	if(buffer_size < MIN_BUFFER_SIZE) {
		cli_warnmsg("Entity converter: Supplied buffer size:%lu, smaller than minimum required: %d\n",(unsigned long)buffer_size,MIN_BUFFER_SIZE);
		return CL_ENULLARG;
	}
	if(conv) {
		conv->encoding = (unsigned char*) cli_strdup("ISO-8859-1");
		conv->autodetected = OTHER;
		conv->bom_cnt = 0;
		conv->buffer_cnt = 0;
		conv->bytes_read = 0;
		conv->partial = 0;
		conv->entity_buffcnt = 0;
		conv->buffer_size = buffer_size;
		conv->priority = NOPRIO;

		conv->tmp_area.offset = 0;
		conv->tmp_area.length = 0;
		conv->tmp_area.buffer  =  cli_malloc(buffer_size);
		if(!conv->tmp_area.buffer) {
			return CL_EMEM;
		}

		conv->out_area.offset = 0;
		conv->out_area.length = 0;
		conv->out_area.buffer = cli_malloc(buffer_size);
		if(!conv->out_area.buffer) {
			free(conv->tmp_area.buffer);
			return CL_EMEM;
		}

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

		return 0;
	}
	else 
		return CL_ENULLARG;
}

static size_t encoding_bytes(const unsigned char* fromcode, enum encodings* encoding)
{
	const unsigned char* from = (const unsigned char*) fromcode;
	/* special case for these unusual byteorders */
	*encoding=E_OTHER;
	if(from == UCS4_2143)
		*encoding = E_UCS4_2134;
	else if (from == UCS4_3412)
		*encoding = E_UCS4_3412;
	else {
		struct element * e = hashtab_find(&aliases_htable,from,strlen((const char*)fromcode));
		if(e && e->key) {
			*encoding = e->data;
		}
	}

	switch(*encoding) {
		case E_UCS4:
		case E_UCS4_1234:
		case E_UCS4_4321:
		case E_UCS4_2134:
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

#ifndef HAVE_ICONV_H
typedef struct {
	enum encodings encoding;
	size_t size;
} * iconv_t;

static iconv_t iconv_open(const char *tocode, const char* fromcode)
{
	iconv_t iconv = cli_malloc(sizeof(*iconv));
	if(!iconv)
		return NULL;
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
						cli_dbgmsg("Warning: unicode character out of utf16 range!\n");
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
							cli_dbgmsg("invalid UTF8 character encountered\n");
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
							cli_dbgmsg("invalid UTF8 character encountered\n");
							break;
						}
						i+=3;
					}
					else if( (input[i]&0xF8) == 0xF0) {
						if((input[i+1]&0xC0) == 0x80 && (input[i+2]&0xC0) == 0x80 && (input[i+3]&0xC0) == 0x80) {
							/* 4 bytes long 11110www 10xxxxxx 10yyyyyy 10zzzzzz -> 000wwwxx xxxxyyyy yyzzzzzz*/
							cli_dbgmsg("UTF8 character out of UTF16 range encountered");
							output[j++] = 0xff;
							output[j++] = 0xff;

							/*out[j++] = ((input[i] & 0x07) << 2) | ((input[i+1] >> 4) & 0x3);
							out[j++] = (input[i+1] << 4) | ((input[i+2] >> 2) & 0x0F);
							out[j++] = (input[i+2] << 6) | (input[i+2] & 0x3F);*/
						}
						else {
							cli_dbgmsg("invalid UTF8 character encountered\n");
							break;
						}
						i+=4;
					}
					else {
						cli_dbgmsg("invalid UTF8 character encountered\n");
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
	const unsigned char* encoding = OTHER;
	int has_bom = 0;
	uint8_t enc_bytes = 4;/* default is UTF8, which has a maximum of 4 bytes*/

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
					encoding = UNDECIDED_32_1234;
				} 
				else if(bom[2] == 0x3C && bom[3] == 0x00) {
					encoding = UNDECIDED_32_2143;
				}
			}/* 0x00 0x00 */
			else if(bom[1] == 0x3C) {
				if(bom[2] == 0x00) {
					if(bom[3] == 0x00) {
						encoding = UNDECIDED_32_3412;
					}
					else if(bom[3] == 0x3F) {
						encoding = UNDECIDED_16_BE;
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
						encoding = UNDECIDED_32_4321;
					}
					else if(bom[2] == 0x3F && bom[3] == 0x00) {
						encoding = UNDECIDED_16_LE;
						enc_bytes = 2;
					}
				}/*0x3C 0x00*/
				else if(bom[1] == 0x3F && bom[2] == 0x78 && bom[3]==0x6D) {
					encoding = UNDECIDED_8;
					enc_bytes = 1;
				}/*0x3C 3F 78 6D*/
				break;
		case 0x4C: 
				if(bom[1] == 0x6F && bom[2] == 0xA7 && bom[3] == 0x94) {
					encoding = EBCDIC;
					enc_bytes = 1;
				}/*4C 6F A7 94*/
				break;
	}/*switch*/
	conv->autodetected = encoding;
	conv->enc_bytes = enc_bytes;
	conv->has_bom = has_bom;
}

static unsigned char* normalize_encoding(const unsigned char* enc)
{
	unsigned char* norm; 
	size_t i;
	const size_t len = strlen((const char*)enc);
	norm = cli_malloc( len+1);
	if(!norm)
		return NULL;
	if(enc == OTHER)
		enc = (const unsigned char*)"ISO-8859-1";
	for(i=0;i < strlen((const char*)enc); i++)
		norm[i] = toupper(enc[i]);
	norm[len]='\0';
	return norm;
}

static const unsigned char* encoding_name(unsigned char* encoding)
{
	if(!encoding)
		return (const unsigned char*)"ISO-8859-1";
	else
		return encoding;
}

void process_encoding_set(struct entity_conv* conv,const unsigned char* encoding,enum encoding_priority prio)
{
	unsigned char *tmp_encoding;
	enum encodings tmp;
	size_t new_size,old_size;

	cli_dbgmsg("Setting encoding for %p  to %s, priority: %d\n",(void*)conv, encoding, prio);
	if(encoding == OTHER)
		return;
	if(conv->priority == CONTENT_TYPE)
		return;/* Content-type in header is highest priority, no overrides possible*/
	if(conv->priority ==  BOM && prio == NOBOM_AUTODETECT)
		return;

	tmp_encoding = normalize_encoding(encoding);/* FIXME: better obey priorities*/
	if(prio == META) {
	old_size = encoding_bytes(conv->encoding,&tmp);
	new_size = encoding_bytes(tmp_encoding,&tmp);
	if(old_size != new_size)  {
		/* on x86 gcc wants %u for size_t, on x86_64 it wants %lu for size_t. So just cast to unsigned long to make warnings go away. */
		cli_dbgmsg("process_encoding_set: refusing to override encoding - new encoding size differs: %s(%lu) != %s(%lu)\n",conv->encoding,(unsigned long)old_size,tmp_encoding,(unsigned long)new_size);
		free(tmp_encoding);
		return;
	}
	}
	free(conv->encoding);
	conv->encoding = tmp_encoding;
	cli_dbgmsg("New encoding for %p:%s\n",(void*)conv,conv->encoding);
	/* reset stream */
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

static size_t read_raw(FILE *stream, m_area_t *m_area, int max_len, unsigned char* outbuff)
{

	/* Try and use the memory buffer first */
	if (m_area) {
		size_t area_maxcopy;
		const unsigned char* src;
		size_t copied;
		if(m_area->offset >= m_area->length)
			return 0;
		area_maxcopy = (m_area->length > m_area->offset + max_len) ? max_len : m_area->length - m_area->offset;
		src = m_area->buffer + m_area->offset;
		m_area->offset += area_maxcopy;
		copied = area_maxcopy;
		while(area_maxcopy && *src != '\n') {
			*outbuff++ = *src++;
			area_maxcopy--;
		}
		if(area_maxcopy > 3) {
			/*copy 3 more bytes, just in case its ucs4 */
			*outbuff++ = *src++;
			*outbuff++ = *src++;
			*outbuff++ = *src++;
			area_maxcopy -= 3;
		}
		m_area->offset -= area_maxcopy;
		copied -= area_maxcopy;
		return copied;
	} else {
		if (!stream) {
			cli_dbgmsg("No HTML stream\n");
			return 0;
		}
		else {
			const size_t iread = fread(outbuff, 1, max_len, stream);
			size_t i;
			if(ferror(stream)) {
				cli_errmsg("Error while reading HTML stream\n");
			}
			for(i=0; i < iread; i++)
				if(outbuff[i] == '\n') {
					return i+3 > iread ?  iread : i+3;
				}
			return iread;
		}
	}
}

static void output_first(struct entity_conv* conv,unsigned char** out, unsigned char** in,size_t* inleft)
{
	if(conv->has_bom) {
		switch(conv->enc_bytes) {
			case 1:
				if(conv->autodetected == UTF8) {
					*in += 3;
					*inleft -= 3;
				}
				break;
			case 2:
				*in += 2;
				*inleft -= 2;
				break;
			case 4:
				*in += 4;
				*inleft -= 4;
				break;
		}
	}
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
	cli_dbgmsg("Initializing iconv pool:%p\n",(void*)cache);
	hashtab_init(&cache->hashtab, 32);
}

static void iconv_cache_destroy(struct iconv_cache* cache)
{
	size_t i;
	cli_dbgmsg("Destroying iconv pool:%p\n",(void*)cache);
	for(i=0;i < cache->last;i++) {
		cli_dbgmsg("closing iconv:%p\n",cache->tab[i]);
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
		cli_dbgmsg("iconv:registering atexit\n");
		if(atexit(iconv_cache_cleanup_main)) {
			cli_dbgmsg("failed to register atexit\n");
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
			cli_dbgmsg("!Out of memory allocating TLS iconv instance\n");
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

static iconv_t iconv_open_cached(const unsigned char* fromcode)
{
	struct iconv_cache * cache;
	size_t idx;
	const size_t fromcode_len = strlen((const char*)fromcode);
	struct element * e;
	iconv_t  iconv_struct;

	init_iconv_pool_ifneeded();
	cache = cache_get_tls_instance();/* gets TLS iconv pool */
	if(!cache) {
		cli_dbgmsg("!Unable to get TLS iconv cache!\n");
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
	cli_dbgmsg("iconv not found in cache, for encoding:%s\n",fromcode);
	iconv_struct = iconv_open("UTF-16BE",(const char*)fromcode);
	if(iconv_struct != (iconv_t)-1) {
	idx = cache->last++;
	if(idx >= cache->len) {
		cache->len += 16;
		cache->tab = cli_realloc2(cache->tab, cache->len*sizeof(cache->tab[0]));
		if(!cache->tab) {
			cli_dbgmsg("!Out of mem in iconv-pool\n");
			errno = ENOMEM;
			return (iconv_t)-1;
		}
	}

	hashtab_insert(&cache->hashtab, fromcode, fromcode_len, idx);
		cache->tab[idx] = iconv_struct;
	cli_dbgmsg("iconv_open(),for:%s -> %p\n",fromcode,(void*)cache->tab[idx]);
	return cache->tab[idx];
}
	return (iconv_t)-1;
}


/* tmp_m_area and conv->out_area are of size maxlen */
unsigned char* encoding_norm_readline(struct entity_conv* conv, FILE* stream_in, m_area_t* in_m_area, const size_t maxlen)
{
	if(!conv || !conv->out_area.buffer || !conv->tmp_area.buffer || maxlen<2 )
		return NULL;
	else {
		/* stream_in|in_m_area ->(read_raw) conv->tmp_area -> (iconv) conv->out_area -> (normalize) conv->norm_area -> (cli_readline) return value*/
		const size_t tmp_move = conv->tmp_area.length - conv->tmp_area.offset;
		const size_t tmp_available = conv->buffer_size - tmp_move;
		const size_t max_read = maxlen < tmp_available ? maxlen : tmp_available;
		unsigned char* tmpbuff = &conv->tmp_area.buffer[tmp_move];
	
		const size_t out_move = conv->out_area.length < conv->out_area.offset ? 0 : conv->out_area.length - conv->out_area.offset;
		size_t outleft = conv->buffer_size - out_move;
		unsigned char* out = &conv->out_area.buffer[out_move];

		const size_t norm_move = conv->norm_area.length - conv->norm_area.offset;

		unsigned char* norm;
		const unsigned char* norm_end;
		iconv_t iconv_struct;

		size_t rc, inleft;
		ssize_t i;

		signed char alignfix;

		/* move whatever left in conv->tmp_area to beginning */
		if(tmp_move)
			memmove(conv->tmp_area.buffer, conv->tmp_area.buffer + conv->tmp_area.offset, tmp_move);
		conv->tmp_area.offset = 0;

		/* read raw data from stream, or in_m_area into conv->tmp_area*/
		conv->tmp_area.length = tmp_move + read_raw(stream_in, in_m_area, max_read, tmpbuff);

		/* move whatever left in conv->out_area to beginning */
		if(out_move)
			memmove(conv->out_area.buffer, conv->out_area.buffer + conv->out_area.offset, out_move);
		conv->out_area.offset = 0;

		tmpbuff = conv->tmp_area.buffer;
		inleft = conv->tmp_area.length;
		if(!conv->bom_cnt && conv->tmp_area.length >= 4) {/* detect Byte Order Mark */
			memcpy( conv->bom, tmpbuff, 4);
			process_bom(conv);
			process_encoding_set(conv,conv->autodetected,conv->has_bom ? BOM : NOBOM_AUTODETECT);
			output_first(conv,&out,&tmpbuff,&inleft);
			conv->bom_cnt++;
		}

		/* convert encoding conv->tmp_area. conv->out_area */
		alignfix = inleft%4;/* iconv gives an error if we give him 3 bytes to convert, 
				       and we are using ucs4, ditto for utf16, and 1 byte*/
		inleft -= alignfix;

		if(!inleft && alignfix) {
			size_t k;
			for(k=0;k+alignfix < 4;k++)
				tmpbuff[alignfix+k] = '\0';
			inleft = 4;
			alignfix = -inleft;
		}

		iconv_struct = iconv_open_cached(encoding_name(conv->encoding));

		if(iconv_struct == (iconv_t)-1) {
			cli_dbgmsg("Iconv init problem for encoding:%s, falling back to iso encoding!\n",encoding_name(conv->encoding));
			/* message shown only once/file */
			/* what can we do? just fall back for it being an ISO-8859-1 */
		        free(conv->encoding);
			conv->encoding = (unsigned char*) cli_strdup("ISO-8859-1");
			iconv_struct = iconv_open_cached(conv->encoding);
			if(iconv_struct == (iconv_t)-1) {
				cli_dbgmsg("fallback failed... bail out\n");
				return cli_readline(NULL,&conv->tmp_area,maxlen);
			}
		}

		if(inleft && outleft > conv->buffer_size/2 ) /* iconv doesn't like inleft to be 0 */ {
			rc = iconv(iconv_struct, (char**) &tmpbuff,  &inleft, (char**) &out, &outleft);	
		}
		else
			rc = 0;

#if 0
		 iconv_close(iconv_struct);/* - don't close, we are using a cached instance */
#endif

		if(rc==(size_t)-1 && errno != E2BIG) {
				cli_dbgmsg("iconv error:%s, silently resuming (%ld,%ld,%lu,%lu)\n",strerror(errno),(long)(out-conv->out_area.buffer),(long)(tmpbuff-conv->tmp_area.buffer),(unsigned long)inleft,(unsigned long)outleft);
				/* output raw byte, and resume at next byte */
				*out++ = 0;
				*out++ = *tmpbuff++;
				inleft--;
/*				return cli_readline(NULL, &conv->norm_area, maxlen);*/
		}

		conv->tmp_area.length = inleft + (alignfix > 0 ? alignfix : 0);
		conv->out_area.length = out - conv->out_area.buffer - out_move;

		conv->tmp_area.offset = tmpbuff - conv->tmp_area.buffer;
		conv->tmp_area.length += conv->tmp_area.offset;


		/* move whatever left in conv->norm_area to beginning */
		if(norm_move) {
			if(norm_move < conv->buffer_size/2) {
			memmove(conv->norm_area.buffer, conv->norm_area.buffer + conv->norm_area.offset, norm_move);
		conv->norm_area.offset = 0;
				norm = conv->norm_area.buffer + norm_move;
			}
			else {
				/* don't modify offset here */
				norm = conv->norm_area.buffer + conv->norm_area.length;
			}
		}
		else {
			conv->norm_area.offset = 0;
			norm = conv->norm_area.buffer;	
		}

		/* now do the real normalization */
		out = conv->out_area.buffer;/* skip over utf16 bom, FIXME: check if iconv really outputted a BOM */
		norm_end = conv->norm_area.buffer + conv->buffer_size;
		if(conv->out_area.length>0 && out[0] == 0xFF && out[1] == 0xFE)
			i = 2;
		else
			i = 0;
		for(; i < conv->out_area.length; i += 2) {
			uint16_t u16 = ( ((uint16_t)out[i]) << 8 ) | out[i+1];
			if(!u16) {
				if(alignfix >= 0 && !conv->msg_zero_shown) /* if alignfix is negative, this 0 byte is on-purpose, its padding */ {
					conv->msg_zero_shown = 1;
					cli_dbgmsg("Skipping null character in html stream\n");
			}
			}
			else if(u16 < 0x80) {
				if(norm >= norm_end)
					break;
				if((unsigned char)u16 ==0)
					cli_dbgmsg("Impossible\n");
				*norm++ = (unsigned char)u16;
			}
			else if (u16 == 160)  {/*nbsp*/
				if(norm >= norm_end)
					break;
				*norm++ = 0x20;
			}
			else {
				char buff[10];
				int len;

				snprintf(buff,9,"&#%d;",u16);
				buff[9] = '\0';
				len = strlen(buff);
				if((norm_end - norm) <= len)
					/* prevent buffer overflow */
					break;
				memcpy((char*)norm, buff, len);
				norm += len;
			}	
		}
		conv->out_area.offset = i; /* so that we can resume next time from here */

		conv->norm_area.length = norm - conv->norm_area.buffer;
/*
		conv->norm_area.buffer[conv->buffer_size-1]=0;DONT DO THIS
		if( (o =strstr(conv->norm_area.buffer,"Content")) && strstr(conv->norm_area.buffer,"text/x-"))
			printf("%s\n",o);*/
		/* final cli_readline from conv->norm_area */
		return cli_readline(NULL, &conv->norm_area, maxlen);
	}
}

