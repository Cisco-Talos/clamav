/*
 * Based on libpst version 0.5.1, written by Dave Smith, dave.s at earthcorp.com
 *	http://alioth.debian.org/projects/libpst/
 * For copyright information on that code, refer to libpst
 *
 * Portions Copyright (C) 2006 Nigel Horne <njh@bandsman.co.uk>
 *	NJH changes: tidy up, remove most code warnings, fixed segfaults,
 *		started on the memory leaks, but still a few to fix,
 *		don't trust the "raw data size" of LZFU encoded attachments,
 *		don't read unitiliased data if a read fails
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
 * Notice that this code has yet to be sanitised, and audited. Use at your
 *	peril
 * FIXME: lots of memory leaks on error returns
 * FIXME: rfc*_datetime_format routines are not thread safe
 * FIXME: valgrind has a field day on this code :-(
 *
 * TODO: This code works by converting into an mbox - it would be better to
 *	save the attachments directly rather than encode to base64, then have
 *	cli_mbox decode it
 * TODO: Remove the vcard handling
 */
static	char	const	rcsid[] = "$Id: pst.c,v 1.16 2006/05/01 17:36:05 nigelhorne Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"	/* must come first */
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <time.h>

#include "clamav.h"
#include "others.h"

#include "pst.h"

#define	DWORD	unsigned int

#define DEBUG_VERSION 1

#define	LE64_CPU(x)	x = le64_to_host(x);
#define	LE32_CPU(x)	x = le32_to_host(x);
#define	LE16_CPU(x)	x = le16_to_host(x);

typedef struct {
	unsigned int dwLowDateTime;
	unsigned int dwHighDateTime;
} FILETIME;

typedef struct _pst_entryid_struct {
  int32_t u1;
  char entryid[16];
  int32_t id;
} pst_entryid;

typedef struct _pst_desc_struct {
  u_int32_t d_id;
  u_int32_t desc_id;
  u_int32_t list_id;
  u_int32_t parent_id;
} pst_desc;

typedef struct _pst_index_struct{
  u_int32_t id;
  int32_t offset;
  u_int16_t size;
  int16_t u1;
} pst_index;

typedef struct _pst_index_tree {
  u_int32_t id;
  int32_t offset;
  size_t size;
  int32_t u1;
  struct _pst_index_tree * next;
} pst_index_ll;

typedef struct _pst_index2_tree {
  int32_t id2;
  pst_index_ll *id;
  struct _pst_index2_tree * next;
} pst_index2_ll;

typedef struct _pst_desc_tree {
  u_int32_t id;
  pst_index_ll * list_index;
  pst_index_ll * desc;
  int32_t no_child;
  struct _pst_desc_tree * prev;
  struct _pst_desc_tree * next;
  struct _pst_desc_tree * parent;
  struct _pst_desc_tree * child;
  struct _pst_desc_tree * child_tail;
} pst_desc_ll;

typedef struct _pst_item_email_subject {
  int32_t off1;
  int32_t off2;
  char *subj;
} pst_item_email_subject;

typedef struct _pst_item_email {
  FILETIME *arrival_date;
  int32_t autoforward; /* 1 = true, 0 = not set, -1 = false */
  char *body;
  char *cc_address;
  char *common_name;
  int32_t  conv_index;
  int32_t  conversion_prohib;
  int32_t  delete_after_submit; /* 1 = true, 0 = false */
  int32_t  delivery_report; /* 1 = true, 0 = false */
  char *encrypted_body;
  int32_t  encrypted_body_size;
  char *encrypted_htmlbody;
  int32_t encrypted_htmlbody_size;
  int32_t  flag;
  char *header;
  char *htmlbody;
  int32_t  importance;
  char *in_reply_to;
  int32_t  message_cc_me; /* 1 = true, 0 = false */
  int32_t  message_recip_me; /* 1 = true, 0 = false */
  int32_t  message_to_me; /* 1 = true, 0 = false */
  char *messageid;
  int32_t  orig_sensitivity;
  char *outlook_recipient;
  char *outlook_recipient2;
  char *outlook_sender;
  char *outlook_sender_name;
  char *outlook_sender2;
  int32_t  priority;
  char *proc_subject;
  int32_t  read_receipt;
  char *recip_access;
  char *recip_address;
  char *recip2_access;
  char *recip2_address;
  int32_t  reply_requested;
  char *reply_to;
  char *return_path_address;
  int32_t  rtf_body_char_count;
  int32_t  rtf_body_crc;
  char *rtf_body_tag;
  char *rtf_compressed;
  int32_t  rtf_in_sync; /* 1 = true, 0 = doesn't exist, -1 = false */
  int32_t  rtf_ws_prefix_count;
  int32_t  rtf_ws_trailing_count;
  char *sender_access;
  char *sender_address;
  char *sender2_access;
  char *sender2_address;
  int32_t  sensitivity;
  FILETIME *sent_date;
  pst_entryid *sentmail_folder;
  char *sentto_address;
  pst_item_email_subject *subject;
} pst_item_email;

typedef struct _pst_item_folder {
  int32_t  email_count;
  int32_t  unseen_email_count;
  int32_t  assoc_count;
  char subfolder;
} pst_item_folder;

typedef struct _pst_item_message_store {
  pst_entryid *deleted_items_folder;
  pst_entryid *search_root_folder;
  pst_entryid *top_of_personal_folder;
  pst_entryid *top_of_folder;
  int32_t valid_mask; /* what folders the message store contains */
  int32_t pwd_chksum;
} pst_item_message_store;

typedef struct _pst_item_contact {
  char *access_method;
  char *account_name;
  char *address1;
  char *address1_desc;
  char *address1_transport;
  char *address2;
  char *address2_desc;
  char *address2_transport;
  char *address3;
  char *address3_desc;
  char *address3_transport;
  char *assistant_name;
  char *assistant_phone;
  char *billing_information;
  FILETIME *birthday;
  char *business_address;
  char *business_city;
  char *business_country;
  char *business_fax;
  char *business_homepage;
  char *business_phone;
  char *business_phone2;
  char *business_po_box;
  char *business_postal_code;
  char *business_state;
  char *business_street;
  char *callback_phone;
  char *car_phone;
  char *company_main_phone;
  char *company_name;
  char *computer_name;
  char *customer_id;
  char *def_postal_address;
  char *department;
  char *display_name_prefix;
  char *first_name;
  char *followup;
  char *free_busy_address;
  char *ftp_site;
  char *fullname;
  int32_t  gender;
  char *gov_id;
  char *hobbies;
  char *home_address;
  char *home_city;
  char *home_country;
  char *home_fax;
  char *home_phone;
  char *home_phone2;
  char *home_po_box;
  char *home_postal_code;
  char *home_state;
  char *home_street;
  char *initials;
  char *isdn_phone;
  char *job_title;
  char *keyword;
  char *language;
  char *location;
  int32_t  mail_permission;
  char *manager_name;
  char *middle_name;
  char *mileage;
  char *mobile_phone;
  char *nickname;
  char *office_loc;
  char *org_id;
  char *other_address;
  char *other_city;
  char *other_country;
  char *other_phone;
  char *other_po_box;
  char *other_postal_code;
  char *other_state;
  char *other_street;
  char *pager_phone;
  char *personal_homepage;
  char *pref_name;
  char *primary_fax;
  char *primary_phone;
  char *profession;
  char *radio_phone;
  int32_t  rich_text;
  char *spouse_name;
  char *suffix;
  char *surname;
  char *telex;
  char *transmittable_display_name;
  char *ttytdd_phone;
  FILETIME *wedding_anniversary;
} pst_item_contact;

typedef struct _pst_item_attach {
  char *filename1;
  char *filename2;
  char *mimetype;
  char *data;
  size_t  size;
  int32_t  id2_val;
  int32_t  id_val; /* calculated from id2_val during creation of record */
  int32_t  method;
  int32_t  position;
  int32_t  sequence;
  struct _pst_item_attach *next;
} pst_item_attach;

typedef struct _pst_item_extra_field {
  char *field_name;
  char *value;
  struct _pst_item_extra_field *next;
} pst_item_extra_field;

typedef struct _pst_item_journal {
  FILETIME *end;
  FILETIME *start;
  char *type;
} pst_item_journal;

typedef struct _pst_item_appointment {
  FILETIME *end;
  char *location;
  FILETIME *reminder;
  FILETIME *start;
  char *timezonestring;
  int32_t showas;
  int32_t label;
} pst_item_appointment;

typedef struct _pst_item {
  struct _pst_item_email *email; /* data reffering to email */
  struct _pst_item_folder *folder; /* data reffering to folder */
  struct _pst_item_contact *contact; /* data reffering to contact */
  struct _pst_item_attach *attach; /* linked list of attachments */
  struct _pst_item_attach *current_attach; // pointer to current attachment
  struct _pst_item_message_store * message_store; // data referring to the message store
  struct _pst_item_extra_field *extra_fields; // linked list of extra headers and such
  struct _pst_item_journal *journal; // data reffering to a journal entry
  struct _pst_item_appointment *appointment; // data reffering to a calendar entry
  int32_t type;
  char *ascii_type;
  char *file_as;
  char *comment;
  int32_t  message_size;
  char *outlook_version;
  char *record_key; // probably 16 bytes long.
  size_t record_key_size;
  int32_t  response_requested;
  FILETIME *create_date;
  FILETIME *modify_date;
  int32_t private;
} pst_item;

typedef struct _pst_x_attrib_ll {
  int32_t type;
  int32_t mytype;
  int32_t map;
  void *data;
  struct _pst_x_attrib_ll *next;
} pst_x_attrib_ll;

typedef struct _pst_file {
  pst_index_ll *i_head, *i_tail;
  pst_index2_ll *i2_head;
  pst_desc_ll *d_head, *d_tail;
  pst_x_attrib_ll *x_head;
  int32_t index1;
  int32_t index1_count;
  int32_t index2;
  int32_t index2_count;
  FILE * fp;
  size_t size;
  unsigned char index1_depth;
  unsigned char index2_depth;
  unsigned char encryption;
  unsigned char id_depth_ok;
  unsigned char desc_depth_ok;
  unsigned char ind_type;
} pst_file;

typedef struct _pst_block_offset {
  int16_t from;
  int16_t to;
} pst_block_offset;

struct _pst_num_item {
  int32_t id;
  unsigned char *data;
  int32_t type;
  size_t size;
  char *extra;
};

typedef struct _pst_num_array {
  int32_t count_item;
  int32_t count_array;
  struct _pst_num_item ** items;
  struct _pst_num_array *next;
} pst_num_array;

struct holder {
  unsigned char **buf;
  FILE * fp;
  int32_t base64;
  char base64_extra_chars[3];
  int32_t base64_extra;
};

static	int32_t	pst_open(pst_file *pf, int desc);
static	int32_t	pst_close(pst_file *pf);
static	pst_desc_ll	*pst_getTopOfFolders(pst_file *pf, pst_item *root);
static	int32_t pst_attach_to_file_base64(pst_file *pf, pst_item_attach *attach, FILE* fp);
int32_t pst_load_index (pst_file *pf);
static	int32_t	pst_load_extended_attributes(pst_file *pf);

static	int32_t	_pst_build_id_ptr(pst_file *pf, int32_t offset, int32_t depth, int32_t start_val, int32_t end_val);
int32_t _pst_build_desc_ptr (pst_file *pf, int32_t offset, int32_t depth, int32_t *high_id,
			     int32_t start_id, int32_t end_val);
pst_item* _pst_getItem(pst_file *pf, pst_desc_ll *d_ptr);
static	void	*_pst_parse_item (pst_file *pf, pst_desc_ll *d_ptr);
static	pst_num_array	*_pst_parse_block(pst_file *pf, u_int32_t block_id, pst_index2_ll *i2_head);
int32_t _pst_process(pst_num_array *list, pst_item *item);
int32_t _pst_free_list(pst_num_array *list);
void _pst_freeItem(pst_item *item);
int32_t _pst_free_id2(pst_index2_ll * head);
int32_t _pst_free_id (pst_index_ll *head);
int32_t _pst_free_desc (pst_desc_ll *head);
int32_t _pst_free_xattrib(pst_x_attrib_ll *x);
int32_t _pst_getBlockOffset(char *buf, int32_t i_offset, int32_t offset, pst_block_offset *p);
pst_index2_ll * _pst_build_id2(pst_file *pf, pst_index_ll* list, pst_index2_ll* head_ptr);
pst_index_ll * _pst_getID(pst_file* pf, u_int32_t id);
static	pst_index_ll	*_pst_getID2(pst_index2_ll * ptr, u_int32_t id);
pst_desc_ll * _pst_getDptr(pst_file *pf, u_int32_t id);
static	size_t _pst_read_block_size(pst_file *pf, int32_t offset, size_t size, char ** buf, int32_t do_enc, unsigned char is_index);
int32_t _pst_decrypt(unsigned char *buf, size_t size, int32_t type);
static int32_t _pst_getAtPos(FILE* fp, int32_t pos, void *buf, u_int32_t size);
int32_t _pst_get (FILE *fp, void *buf, u_int32_t size);
size_t	_pst_ff_getIDblock_dec(pst_file *pf, u_int32_t id, unsigned char **b);
static	size_t _pst_ff_getIDblock(pst_file *pf, u_int32_t id, unsigned char** b);
size_t _pst_ff_getID2block(pst_file *pf, u_int32_t id2, pst_index2_ll *id2_head, unsigned char** buf);
static	size_t _pst_ff_getID2data(pst_file *pf, pst_index_ll *ptr, struct holder *h);
static	size_t _pst_ff_compile_ID(pst_file *pf, u_int32_t id, struct holder *h, int32_t size);

size_t	pst_fwrite(const void*ptr, size_t size, size_t nmemb, FILE*stream);
char * _pst_wide_to_single(char *wt, int32_t size);
static	unsigned	char	*lzfu_decompress(const unsigned char* rtfcomp, size_t *nbytes);

static	time_t	fileTimeToUnixTime(const FILETIME *filetime, DWORD *remainder);
static	const	char	*fileTimeToAscii(const FILETIME *filetime);
static	const	struct	tm	*fileTimeToStructTM(const FILETIME *filetime);
static	int	pst_decode(const char *dir, int desc);
static	char	*base64_encode(const unsigned char *data, size_t size);
static	int	chr_count(const char *str, char x);
static	const	char	*rfc2426_escape(const char *str);
static	size_t	write_email_body(FILE *f, const char *body);
static	char	*my_stristr(const char *haystack, const char *needle);

int
cli_pst(const char *dir, int desc)
{
	cli_warnmsg("PST files not yet supported\n");
	return CL_EFORMAT;
	/*return pst_decode(dir, desc);*/
}

static const char *
fileTimeToAscii(const FILETIME *filetime)
{
	time_t t1;

	t1 = fileTimeToUnixTime(filetime,0);
	return ctime(&t1);
}

static const struct tm *
fileTimeToStructTM(const FILETIME *filetime)
{
	time_t t1;

	t1 = fileTimeToUnixTime(filetime, 0);
	return gmtime(&t1);
}

/***********************************************************************
 * DOSFS_FileTimeToUnixTime
 *
 * Convert a FILETIME format to Unix time.
 * If not NULL, 'remainder' contains the fractional part of the filetime,
 * in the range of [0..9999999] (even if time_t is negative).
 */
static time_t
fileTimeToUnixTime(const FILETIME *filetime, DWORD *remainder)
{
#if USE_LONG_LONG
	long long int t = filetime->dwHighDateTime;
	t <<= 32;
	t += (uint32_t)filetime->dwLowDateTime;
	t -= 116444736000000000LL;
	if (t < 0) {
		if (remainder)
			*remainder = 9999999 - (-t - 1) % 10000000;
		return -1 - ((-t - 1) / 10000000);
	} else {
		if (remainder)
			*remainder = t % 10000000;
		return t / 10000000;
	}
#else  /* ISO version */
	uint32_t a0;			/* 16 bit, low    bits */
	uint32_t a1;			/* 16 bit, medium bits */
	uint32_t a2;			/* 32 bit, high   bits */
	uint32_t r;			/* remainder of division */
	unsigned int carry;		/* carry bit for subtraction */
	int negative;		/* whether a represents a negative value */

	/* Copy the time values to a2/a1/a0 */
	a2 =  (uint32_t)filetime->dwHighDateTime;
	a1 = ((uint32_t)filetime->dwLowDateTime ) >> 16;
	a0 = ((uint32_t)filetime->dwLowDateTime ) & 0xffff;

	/* Subtract the time difference */
	if (a0 >= 32768           ) a0 -=             32768        , carry = 0;
	else                        a0 += (1 << 16) - 32768        , carry = 1;

	if (a1 >= 54590    + carry) a1 -=             54590 + carry, carry = 0;
	else                        a1 += (1 << 16) - 54590 - carry, carry = 1;

	a2 -= 27111902 + carry;

	/* If a is negative, replace a by (-1-a) */
	negative = (a2 >= ((uint32_t)1) << 31);
	if (negative) {
		/* Set a to -a - 1 (a is a2/a1/a0) */
		a0 = 0xffff - a0;
		a1 = 0xffff - a1;
		a2 = ~a2;
	}

	/* Divide a by 10000000 (a = a2/a1/a0), put the rest into r.
	Split the divisor into 10000 * 1000 which are both less than 0xffff. */
	a1 += (a2 % 10000) << 16;
	a2 /=       10000;
	a0 += (a1 % 10000) << 16;
	a1 /=       10000;
	r   =  a0 % 10000;
	a0 /=       10000;

	a1 += (a2 % 1000) << 16;
	a2 /=       1000;
	a0 += (a1 % 1000) << 16;
	a1 /=       1000;
	r  += (a0 % 1000) * 10000;
	a0 /=       1000;

	/* If a was negative, replace a by (-1-a) and r by (9999999 - r) */
	if (negative) {
		/* Set a to -a - 1 (a is a2/a1/a0) */
		a0 = 0xffff - a0;
		a1 = 0xffff - a1;
		a2 = ~a2;

		r  = 9999999 - r;
	}

	if (remainder)
		*remainder = r;

	/* Do not replace this by << 32, it gives a compiler warning and it does
	not work. */
	return ((((time_t)a2) << 16) << 16) + (a1 << 16) + a0;
#endif
}

#define FILE_SIZE_POINTER 0xA8
#define INDEX_POINTER 0xC4
#define SECOND_POINTER 0xBC
#define INDEX_DEPTH 0x4C
#define SECOND_DEPTH 0x5C
// the encryption setting could be at 0x1CC. Will require field testing
#define ENC_OFFSET 0x1CD
// says the type of index we have
#define INDEX_TYPE_OFFSET 0x0A

// for the 64bit 2003 outlook PST we need new file offsets
// perhaps someone can figure out the header format for the pst files...
#define FILE_SIZE_POINTER_64 0xB8
#define INDEX_POINTER_64 0xF0
#define SECOND_POINTER_64 0xE0

#define PST_SIGNATURE 0x4E444221

#define PST_TYPE_NOTE 1
#define PST_TYPE_APPOINTMENT 8
#define PST_TYPE_CONTACT 9
#define PST_TYPE_JOURNAL 10
#define PST_TYPE_STICKYNOTE 11
#define PST_TYPE_TASK 12
#define PST_TYPE_OTHER 13
#define PST_TYPE_REPORT 14

// defines whether decryption is done on this bit of data
#define PST_NO_ENC 0
#define PST_ENC 1

// defines types of possible encryption
#define PST_COMP_ENCRYPT 1

// defines different types of mappings
#define PST_MAP_ATTRIB 1
#define PST_MAP_HEADER 2

// define my custom email attributes.
#define PST_ATTRIB_HEADER -1

// defines types of free/busy values for appointment->showas
#define PST_FREEBUSY_FREE 0
#define PST_FREEBUSY_TENTATIVE 1
#define PST_FREEBUSY_BUSY 2
#define PST_FREEBUSY_OUT_OF_OFFICE 3

// defines labels for appointment->label
#define PST_APP_LABEL_NONE        0 // None
#define PST_APP_LABEL_IMPORTANT   1 // Important
#define PST_APP_LABEL_BUSINESS    2 // Business
#define PST_APP_LABEL_PERSONAL    3 // Personal
#define PST_APP_LABEL_VACATION    4 // Vacation
#define PST_APP_LABEL_MUST_ATTEND 5 // Must Attend
#define PST_APP_LABEL_TRAVEL_REQ  6 // Travel Required
#define PST_APP_LABEL_NEEDS_PREP  7 // Needs Preparation
#define PST_APP_LABEL_BIRTHDAY    8 // Birthday
#define PST_APP_LABEL_ANNIVERSARY 9 // Anniversary
#define PST_APP_LABEL_PHONE_CALL  10// Phone Call

#ifndef	INT32_MAX	/* e.g. Old Linux */
#define	INT32_MAX	INT_MAX
#endif

struct _pst_table_ptr_struct{
  int32_t start;
  int32_t u1;
  int32_t offset;
};

typedef struct _pst_block_header {
  int16_t type;
  int16_t count;
} pst_block_header;

typedef struct _pst_id2_assoc {
	int32_t id2;
	int32_t id;
	int32_t table2;
} pst_id2_assoc;

// this is an array of the un-encrypted values. the un-encrypyed value is in the position
// of the encrypted value. ie the encrypted value 0x13 represents 0x02
//                     0     1     2     3     4     5     6     7
//                     8     9     a     b     c     d     e     f
static const unsigned char comp_enc [] = {
	0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48,
	0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94, 0x53, /*0x0f*/
	0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab,
	0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd, /*0x1f*/
	0x39, 0x05, 0x96, 0x30, 0xf5, 0x37, 0x60, 0x82,
	0x8c, 0xc9, 0x13, 0x4a, 0x6b, 0x1d, 0xf3, 0xfb, /*0x2f*/
	0x8f, 0x26, 0x97, 0xca, 0x91, 0x17, 0x01, 0xc4,
	0x32, 0x2d, 0x6e, 0x31, 0x95, 0xff, 0xd9, 0x23, /*0x3f*/
	0xd1, 0x00, 0x5e, 0x79, 0xdc, 0x44, 0x3b, 0x1a,
	0x28, 0xc5, 0x61, 0x57, 0x20, 0x90, 0x3d, 0x83, /*0x4f*/
	0xb9, 0x43, 0xbe, 0x67, 0xd2, 0x46, 0x42, 0x76,
	0xc0, 0x6d, 0x5b, 0x7e, 0xb2, 0x0f, 0x16, 0x29, /*0x5f*/
	0x3c, 0xa9, 0x03, 0x54, 0x0d, 0xda, 0x5d, 0xdf,
	0xf6, 0xb7, 0xc7, 0x62, 0xcd, 0x8d, 0x06, 0xd3, /*0x6f*/
	0x69, 0x5c, 0x86, 0xd6, 0x14, 0xf7, 0xa5, 0x66,
	0x75, 0xac, 0xb1, 0xe9, 0x45, 0x21, 0x70, 0x0c, /*0x7f*/
	0x87, 0x9f, 0x74, 0xa4, 0x22, 0x4c, 0x6f, 0xbf,
	0x1f, 0x56, 0xaa, 0x2e, 0xb3, 0x78, 0x33, 0x50, /*0x8f*/
	0xb0, 0xa3, 0x92, 0xbc, 0xcf, 0x19, 0x1c, 0xa7,
	0x63, 0xcb, 0x1e, 0x4d, 0x3e, 0x4b, 0x1b, 0x9b, /*0x9f*/
	0x4f, 0xe7, 0xf0, 0xee, 0xad, 0x3a, 0xb5, 0x59,
	0x04, 0xea, 0x40, 0x55, 0x25, 0x51, 0xe5, 0x7a, /*0xaf*/
	0x89, 0x38, 0x68, 0x52, 0x7b, 0xfc, 0x27, 0xae,
	0xd7, 0xbd, 0xfa, 0x07, 0xf4, 0xcc, 0x8e, 0x5f, /*0xbf*/
	0xef, 0x35, 0x9c, 0x84, 0x2b, 0x15, 0xd5, 0x77,
	0x34, 0x49, 0xb6, 0x12, 0x0a, 0x7f, 0x71, 0x88, /*0xcf*/
	0xfd, 0x9d, 0x18, 0x41, 0x7d, 0x93, 0xd8, 0x58,
	0x2c, 0xce, 0xfe, 0x24, 0xaf, 0xde, 0xb8, 0x36, /*0xdf*/
	0xc8, 0xa1, 0x80, 0xa6, 0x99, 0x98, 0xa8, 0x2f,
	0x0e, 0x81, 0x65, 0x73, 0xe4, 0xc2, 0xa2, 0x8a, /*0xef*/
	0xd4, 0xe1, 0x11, 0xd0, 0x08, 0x8b, 0x2a, 0xf2,
	0xed, 0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec
}; /*0xff*/

static int32_t
pst_open(pst_file *pf, int desc)
{
	int i;
	u_int32_t sig;

	if (pf == NULL) {
	    cli_errmsg("cannot be passed a NULL pst_file\n");
	    return CL_ENULLARG;
	}
	memset(pf, 0, sizeof(pst_file));

	i = dup(desc);
#ifdef  C_CYGWIN
	if ((pf->fp = fdopen(i, "rb")) == NULL) {
#else
	if ((pf->fp = fdopen(i, "r")) == NULL) {
#endif
		close(i);
		cli_errmsg("cannot open PST file. Error\n");
		return CL_EOPEN;
	}
	if (fread(&sig, sizeof(sig), 1, pf->fp) == 0) {
		fclose(pf->fp);
		cli_errmsg("cannot read signature from PST file. Closing on error\n");
		return CL_EIO;
	}

	/* architecture independant byte-swapping (little, big, pdp) */
	LE32_CPU(sig);

	cli_dbgmsg("sig = %X\n", sig);
	if (sig != PST_SIGNATURE) {
		fclose(pf->fp);
		cli_warnmsg("not a PST file that I know. Closing with error\n");
		return CL_EFORMAT;
	}
	_pst_getAtPos(pf->fp, INDEX_TYPE_OFFSET, &(pf->ind_type), sizeof(unsigned char));
	cli_dbgmsg("index_type = %i\n", pf->ind_type);
	if (pf->ind_type != 0x0E) {
		fclose(pf->fp);
		cli_warnmsg("unknown index structure. Could this be a new Outlook 2003 PST file?\n");
		return CL_EFORMAT;
	}

	_pst_getAtPos(pf->fp, ENC_OFFSET, &(pf->encryption), sizeof(unsigned char));
	cli_dbgmsg("encrypt = %i\n", pf->encryption);
	/*  pf->encryption = encrypt; */

	_pst_getAtPos(pf->fp, SECOND_POINTER-4, &(pf->index2_count), sizeof(pf->index2_count));
	_pst_getAtPos(pf->fp, SECOND_POINTER, &(pf->index2), sizeof(pf->index2));
	LE32_CPU(pf->index2_count);
	LE32_CPU(pf->index2);

	_pst_getAtPos(pf->fp, FILE_SIZE_POINTER, &(pf->size), sizeof(pf->size));
	LE32_CPU(pf->size);

	/*
	 * very tempting to leave these values set way too high and let the
	 * exploration of the tables set them...
	 */
	pf->index1_depth = pf->index2_depth = 255;

	cli_dbgmsg("Pointer2 is %#X, count %i[%#x], depth %#x\n",
		pf->index2, pf->index2_count, pf->index2_count, pf->index2_depth);

	_pst_getAtPos(pf->fp, INDEX_POINTER-4, &(pf->index1_count), sizeof(pf->index1_count));
	_pst_getAtPos(pf->fp, INDEX_POINTER, &(pf->index1), sizeof(pf->index1));
	LE32_CPU(pf->index1_count);
	LE32_CPU(pf->index1);

	cli_dbgmsg("Pointer1 is %#X, count %i[%#x], depth %#x\n",
		pf->index1, pf->index1_count, pf->index1_count, pf->index1_depth);
	pf->id_depth_ok = 0;
	pf->desc_depth_ok = 0;

	return CL_SUCCESS;
}

static int32_t
pst_close(pst_file *pf)
{
	if (pf->fp == NULL) {
		cli_warnmsg("cannot close NULL fp\n");
		return CL_ENULLARG;
	}
	if (fclose(pf->fp)) {
		cli_warnmsg("fclose returned non-zero value\n");
		return CL_EIO;
	}
	// we must free the id linklist and the desc tree
	_pst_free_id (pf->i_head);
	_pst_free_desc (pf->d_head);
	_pst_free_xattrib (pf->x_head);
	return CL_SUCCESS;
}

static pst_desc_ll *
pst_getTopOfFolders(pst_file *pf, pst_item *root)
{
	if (root == NULL || root->message_store == NULL) {
		cli_dbgmsg("There isn't a top of folder record here.\n");
		return NULL;
	} else if (root->message_store->top_of_personal_folder == NULL)
		// this is the OST way
		// ASSUMPTION: Top Of Folders record in PST files is *always* descid 0x2142
		return _pst_getDptr(pf, 0x2142);
	else
		return _pst_getDptr(pf, root->message_store->top_of_personal_folder->id);
}

static int32_t
pst_attach_to_file_base64(pst_file *pf, pst_item_attach *attach, FILE *fp)
{
	pst_index_ll *ptr;
	struct holder h = {NULL, fp, 1, "", 0};
	int32_t size;
	char *c;

	if (attach->id_val != -1) {
		ptr = _pst_getID(pf, attach->id_val);
    if (ptr != NULL) {
      size = _pst_ff_getID2data(pf, ptr, &h);
      // will need to encode any bytes left over
      c = base64_encode((const unsigned char *)h.base64_extra_chars, h.base64_extra);
      if(c) {
	      fputs(c, fp);
	      free(c);
	}
    } else {
      cli_dbgmsg ("Couldn't find ID pointer. Cannot save attachement to Base64\n");
      return 0;
    }
    attach->size = size;
  } else {
    // encode the attachment to the file
    c = base64_encode((const unsigned char *)attach->data, attach->size);
    if(c) {
	fputs(c, fp);
	free(c);
	}
    size = attach->size;
  }
  return 1;
}

int32_t pst_load_index (pst_file *pf) {
  int32_t x,y;
  if (pf == NULL) {
    cli_warnmsg("Cannot load index for a NULL pst_file\n");
    return -1;
  }

  x = _pst_build_id_ptr(pf, pf->index1, 0, -1, INT32_MAX);
  if (x == -1 || x == 4) {
    if (x == -1)
      pf->index1_depth = 0; //only do this for -1
    cli_dbgmsg("Re-calling _pst_build_id_ptr cause we started with too grand an idea!!!\n");
    if (_pst_build_id_ptr(pf, pf->index1, 0, 0x4, INT32_MAX) == -1) {
      //we must call twice for testing the depth of the index
      return -1;
    }
  }

  cli_dbgmsg("Second Table\n");
  y = -1;
  x = _pst_build_desc_ptr(pf, pf->index2, 0, &y, 0x21, INT32_MAX);
  if (x == -1 || x == 4) {
    if (x == -1)
      pf->index2_depth = 0; //only if -1 is return val

    if (_pst_build_desc_ptr(pf, pf->index2, 0, &y, 0x21, INT32_MAX) == -1) {
      // we must call twice for testing the depth of the index
      return -1;
    }
  }

  return 0;
}

typedef struct _pst_x_attrib {
  u_int16_t extended;
  u_int16_t zero;
  u_int16_t type;
  u_int16_t map;
} pst_x_attrib;

static int32_t
pst_load_extended_attributes(pst_file *pf)
{
  // for PST files this will load up ID2 0x61 and check it's "list" attribute.
  pst_desc_ll *p;
  pst_num_array *na;
  pst_index2_ll *list2;
  unsigned char * buffer=NULL, *headerbuffer=NULL;
  pst_x_attrib xattrib;
  int32_t bptr = 0, bsize, hsize, tint, err=0, x;
  pst_x_attrib_ll *ptr, *p_head=NULL, *p_sh=NULL, *p_sh2=NULL;
  char *wt;

  if ((p = _pst_getDptr(pf, 0x61)) == NULL) {
    cli_warnmsg("Cannot find DescID 0x61 for loading the Extended Attributes\n");
    return 0;
  }
	if (p->list_index != NULL)
		list2 = _pst_build_id2(pf, p->list_index, NULL);
	else
		list2 = NULL;

  if (p->desc == NULL) {
    cli_warnmsg("desc is NULL for item 0x61. Cannot load Extended Attributes\n");
    return 0;
  }
  if ((na = _pst_parse_block(pf, p->desc->id, list2)) == NULL) {
	_pst_free_id2(list2);
    cli_warnmsg("Cannot process desc block for item 0x61. Not loading extended Attributes\n");
    return 0;
  }
  x = 0;
  hsize = bsize = 0;
  while (x < na->count_item) {
    if (na->items[x]->id == 0x0003) {
      buffer = na->items[x]->data;
      bsize = na->items[x]->size;
    } else if (na->items[x]->id == 0x0004) {
      headerbuffer = na->items[x]->data;
      hsize = na->items[x]->size;
    }
    x++;
  }

	if (buffer == NULL) {
		_pst_free_list(na);
		_pst_free_id2(list2);

		cli_warnmsg("No extended attributes buffer found. Not processing\n");
		return 0;
	}

  memcpy(&xattrib, &(buffer[bptr]), sizeof(xattrib));
  LE16_CPU(xattrib.extended);
  LE16_CPU(xattrib.zero);
  LE16_CPU(xattrib.type);
  LE16_CPU(xattrib.map);
  bptr += sizeof(xattrib);

  while (xattrib.type != 0 && bptr < bsize) {
    ptr = (pst_x_attrib_ll*) cli_calloc(1, sizeof(pst_x_attrib_ll));
    ptr->type = xattrib.type;
    ptr->map = xattrib.map+0x8000;
    ptr->next = NULL;
    cli_dbgmsg("xattrib: ext = %#hx, zero = %#hx, type = %#hx, map = %#hx\n",
		 xattrib.extended, xattrib.zero, xattrib.type, xattrib.map);
    err=0;
    if (xattrib.type & 0x0001) { // if the Bit 1 is set
      // pointer to Unicode field in buffer
      if (xattrib.extended < hsize) {
	// copy the size of the header. It is 32 bit int
	memcpy(&tint, &(headerbuffer[xattrib.extended]), sizeof(tint));
	LE32_CPU(tint);
	wt = (char*) cli_calloc(1, tint+2); // plus 2 for a uni-code zero
	memcpy(wt, &(headerbuffer[xattrib.extended+sizeof(tint)]), tint);
	ptr->data = _pst_wide_to_single(wt, tint);
	free(wt);
	cli_dbgmsg("(converted from UTF-16): %s\n", ptr->data);
      } else {
	cli_dbgmsg("Cannot read outside of buffer [%i !< %i]\n", xattrib.extended, hsize);
      }
      ptr->mytype = PST_MAP_HEADER;
    } else {
      // contains the attribute code to map to.
      ptr->data = (int*)cli_calloc(1, sizeof(int32_t));
      *((int32_t*)ptr->data) = xattrib.extended;
      ptr->mytype = PST_MAP_ATTRIB;
    }

    if (err==0) {
      // add it to the list
      p_sh = p_head;
      p_sh2 = NULL;
      while (p_sh != NULL && ptr->map > p_sh->map) {
	p_sh2 = p_sh;
	p_sh = p_sh->next;
      }
      if (p_sh2 == NULL) {
	// needs to go before first item
	ptr->next = p_head;
	p_head = ptr;
      } else {
	// it will go after p_sh2
	ptr->next = p_sh2->next;
	p_sh2->next = ptr;
      }
    } else {
      free(ptr);
      ptr = NULL;
    }
    memcpy(&xattrib, &(buffer[bptr]), sizeof(xattrib));
    LE16_CPU(xattrib.extended);
    LE16_CPU(xattrib.zero);
    LE16_CPU(xattrib.type);
    LE16_CPU(xattrib.map);
    bptr += sizeof(xattrib);
  }
  pf->x_head = p_head;
	_pst_free_list(na);
	_pst_free_id2(list2);
  return 1;
}

#define BLOCK_SIZE 516

static int32_t
_pst_build_id_ptr(pst_file *pf, int32_t offset, int32_t depth, int32_t start_val, int32_t end_val)
{
  struct _pst_table_ptr_struct table, table2;
  pst_index_ll *i_ptr=NULL;
  pst_index pindex;
  //  int fpos = ftell(pf->fp);
  int32_t x, ret;
  int32_t old = start_val;
  char *buf = NULL, *bptr = NULL;

  if (pf->index1_depth - depth == 0) {
    // we must be at a leaf table. These are index items
    cli_dbgmsg("Reading Items\n");
    //    fseek(pf->fp, offset, SEEK_SET);
    x = 0;

    if (_pst_read_block_size(pf, offset, BLOCK_SIZE, &buf, 0, 0) < BLOCK_SIZE) {
	if(buf)
		free(buf);
	cli_warnmsg("Not read the full block size of the index. There is a problem\n");
	return -1;
    }
    bptr = buf;
    //    cli_dbgmsg(buf, BLOCK_SIZE, 12);
    memcpy(&pindex, bptr, sizeof(pindex));
    LE32_CPU(pindex.id);
    LE32_CPU(pindex.offset);
    LE16_CPU(pindex.size);
    LE16_CPU(pindex.u1);
    bptr += sizeof(pindex);

    while(pindex.id != 0 && x < 42 && bptr < buf+BLOCK_SIZE && (int32_t)pindex.id < end_val) {
      if (pindex.id & 0x02) {
	cli_dbgmsg("two-bit set!!\n");
      }
      if (start_val != -1 && (int32_t)pindex.id != start_val) {
	cli_dbgmsg("This item isn't right. Must be corruption, or I got it wrong!\n");
	cli_dbgmsg(buf, BLOCK_SIZE, 12);
	//	fseek(pf->fp, fpos, SEEK_SET);
	if (buf) free(buf);
	return -1;
      } else {
	start_val = -1;
	pf->id_depth_ok = 1;
      }
      // u1 could be a flag. if bit 0x2 is not set, it might be deleted
      //      if (pindex.u1 & 0x2 || pindex.u1 & 0x4) {
      // ignore the above condition. it doesn't appear to hold
      if (old > (int32_t)pindex.id) { // then we have back-slid on the new values
	if(buf)
		free(buf);
	cli_dbgmsg("Back slider detected - Old value [%#x] greater than new [%#x]. Progressing to next table\n", old, pindex.id);
	return 2;
      }
      old = pindex.id;
      i_ptr = (pst_index_ll*) cli_malloc(sizeof(pst_index_ll));
      i_ptr->id = pindex.id;
      i_ptr->offset = pindex.offset;
      i_ptr->u1 = pindex.u1;
      i_ptr->size = pindex.size;
      i_ptr->next = NULL;
      if (pf->i_tail != NULL)
	pf->i_tail->next = i_ptr;
      if (pf->i_head == NULL)
	pf->i_head = i_ptr;
      pf->i_tail = i_ptr;
      memcpy(&pindex, bptr, sizeof(pindex));
      LE32_CPU(pindex.id);
      LE32_CPU(pindex.offset);
      LE16_CPU(pindex.size);
      LE16_CPU(pindex.u1);
      bptr += sizeof(pindex);
    }
    //    fseek(pf->fp, fpos, SEEK_SET);
    if (x < 42) { // we have stopped prematurley. Why?
      if (pindex.id == 0) {
	cli_dbgmsg("Found index.id == 0\n");
      } else if (!(bptr < buf+BLOCK_SIZE)) {
	cli_dbgmsg("Read past end of buffer\n");
      } else if ((int32_t)pindex.id >= end_val) {
	cli_dbgmsg("pindex.id[%x] > end_val[%x]\n",
		    pindex.id, end_val);
      } else {
	cli_dbgmsg("Stopped for unknown reason\n");
      }
    }
    if (buf) free (buf);
    return 2;
  } else {
    // this is then probably a table of offsets to more tables.
    cli_dbgmsg("Reading Table Items\n");

    x = 0;
    ret = 0;

    if (_pst_read_block_size(pf, offset, BLOCK_SIZE, &buf, 0, 0) < BLOCK_SIZE) {
	if(buf)
		free(buf);
	cli_warnmsg("Not read the full block size of the index. There is a problem\n");
	return -1;
    }
    bptr = buf;
    //    cli_dbgmsg(buf, BLOCK_SIZE, 12);

    memcpy(&table, bptr, sizeof(table));
    LE32_CPU(table.start);
    LE32_CPU(table.u1);
    LE32_CPU(table.offset);
    bptr += sizeof(table);
    memcpy(&table2, bptr, sizeof(table));
    LE32_CPU(table2.start);
    LE32_CPU(table2.u1);
    LE32_CPU(table2.offset);

    if (start_val != -1 && table.start != start_val) {
      cli_dbgmsg("This table isn't right. Must be corruption, or I got it wrong!\n");
      cli_dbgmsg(buf, BLOCK_SIZE, 12);
      if (buf) free(buf);
      return -1;
    }

    while (table.start != 0 && bptr < buf+BLOCK_SIZE && table.start < end_val) {
      cli_dbgmsg("[%i] %i Table [start id = %#x, u1 = %#x, offset = %#x]\n", depth, ++x, table.start, table.u1, table.offset);

      if (table2.start <= table.start)
	// this should only be the case when we come to the end of the table
	// and table2.start == 0
	table2.start = end_val;

      if ((ret = _pst_build_id_ptr(pf, table.offset, depth+1, table.start, table2.start)) == -1 && pf->id_depth_ok == 0) {
	// it would appear that if the table below us isn't a table, but data, then we are actually the table. hmmm
	cli_dbgmsg("Setting max depth to %i\n", depth);
	pf->index1_depth = depth; //set max depth to this level
	if (buf) free (buf);
	//	fseek(pf->fp, fpos, SEEK_SET);
	return 4; // this will indicate that we want to be called again with the same parameters
      } else if (ret == 4) {
	//we shan't bother with checking return value?
	cli_dbgmsg("Seen that a max depth has been set. Calling build again\n");
	_pst_build_id_ptr(pf, table.offset, depth+1, table.start, table2.start);
      } else if (ret == 2) {
	cli_dbgmsg("child returned successfully\n");
      } else {
	cli_dbgmsg("child has returned without a known error [%i]\n", ret);
      }
      memcpy(&table, bptr, sizeof(table));
      LE32_CPU(table.start);
      LE32_CPU(table.u1);
      LE32_CPU(table.offset);
      bptr += sizeof(table);
      memcpy(&table2, bptr, sizeof(table));
      LE32_CPU(table2.start);
      LE32_CPU(table2.u1);
      LE32_CPU(table2.offset);
    }

    if (table.start == 0) {
      cli_dbgmsg("Table.start == 0\n");
    } else if (bptr >= buf+BLOCK_SIZE) {
      cli_dbgmsg("Read past end of buffer\n");
    } else if (table.start >= end_val) {
      cli_dbgmsg("Table.start[%x] > end_val[%x]\n",
		   table.start, end_val);
    } else {
      cli_dbgmsg("Table reading stopped for an unknown reason\n");
    }

    if (buf) free (buf);
    cli_dbgmsg("End of table of pointers\n");
    return 3;
  }
  cli_dbgmsg("ERROR ** Shouldn't be here!\n");

  return 1;
}

#define DESC_BLOCK_SIZE 520
int32_t _pst_build_desc_ptr (pst_file *pf, int32_t offset, int32_t depth, int32_t *high_id, int32_t start_id,
			     int32_t end_val) {
  struct _pst_table_ptr_struct table, table2;
  pst_desc desc_rec;
  pst_desc_ll *d_ptr=NULL, *d_par=NULL;
  int32_t i = 0, y, prev_id=-1;
  char *buf = NULL, *bptr;

  struct _pst_d_ptr_ll {
    pst_desc_ll * ptr;
    int32_t parent; // used for lost and found lists
    struct _pst_d_ptr_ll * next;
    struct _pst_d_ptr_ll * prev;
  } *d_ptr_head=NULL, *d_ptr_tail=NULL, *d_ptr_ptr=NULL, *lf_ptr=NULL, *lf_head=NULL, *lf_shd=NULL, *lf_tmp;
  // lf_ptr and lf_head are used for the lost/found list. If the parent isn't found yet, put it on this
  // list and check it each time you read a new item

  int32_t d_ptr_count = 0;

  if (pf->index2_depth-depth == 0) {
    /* leaf node */
    if (_pst_read_block_size(pf, offset, DESC_BLOCK_SIZE, &buf, 0, 0) < DESC_BLOCK_SIZE) {
	if (buf) free(buf);
      cli_dbgmsg("I didn't get all the index that I wanted. _pst_read_block_size returned less than requested\n");
      return -1;
    }
    bptr = buf;

    //cli_dbgmsg(buf, DESC_BLOCK_SIZE, 16);

    memcpy(&desc_rec, bptr, sizeof(desc_rec));
    LE32_CPU(desc_rec.d_id);
    LE32_CPU(desc_rec.desc_id);
    LE32_CPU(desc_rec.list_id);
    LE32_CPU(desc_rec.parent_id);
    bptr+= sizeof(desc_rec);

    if (end_val <= start_id) {
      cli_dbgmsg("The end value is BEFORE the start value. This function will quit. Soz. [start:%#x, end:%#x]\n",
		  start_id, end_val);
    }

    while (i < 0x1F && (int32_t)desc_rec.d_id < end_val && (prev_id == -1 || (int32_t)desc_rec.d_id > prev_id)) {
      i++;

      if (start_id != -1 && (int32_t)desc_rec.d_id != start_id) {
	cli_dbgmsg("Error: This table appears to be corrupt. Perhaps"
		    " we are looking too deep!\n");
	if (buf) free(buf);
	return -1;
      } else {
	start_id = -1;
	pf->desc_depth_ok = 1;
      }

      if (desc_rec.d_id == 0) {
	memcpy(&desc_rec, bptr, sizeof(desc_rec));
	LE32_CPU(desc_rec.d_id);
	LE32_CPU(desc_rec.desc_id);
	LE32_CPU(desc_rec.list_id);
	LE32_CPU(desc_rec.parent_id);
	bptr+=sizeof(desc_rec);
	continue;
      }
      prev_id = desc_rec.d_id;

      // When duplicates found, just update the info.... perhaps this is correct functionality
      cli_dbgmsg("Searching for existing record\n");

      if (desc_rec.d_id <= (uint32_t)*high_id && (d_ptr = _pst_getDptr(pf, desc_rec.d_id)) !=  NULL) {
	cli_dbgmsg("Updating Existing Values\n");
	d_ptr->list_index = _pst_getID(pf, desc_rec.list_id);
	d_ptr->desc = _pst_getID(pf, desc_rec.desc_id);
	cli_dbgmsg("\tdesc = %#x\tlist_index=%#x\n",
		    (d_ptr->desc==NULL?0:d_ptr->desc->id),
		    (d_ptr->list_index==NULL?0:d_ptr->list_index->id));
	if (d_ptr->parent != NULL && desc_rec.parent_id != d_ptr->parent->id) {
	  cli_dbgmsg("Parent of record has changed. Moving it\n");
	  //hmmm, we must move the record.
	  // first we must remove from current location
	  //   change previous record to point next to our next
	  //     if no previous, then use parent's child
	  //     if no parent then change pf->d_head;
	  //   change next's prev to our prev
	  //     if no next then change parent's child_tail
	  //     if no parent then change pf->d_tail
	  if (d_ptr->prev != NULL)
	    d_ptr->prev->next = d_ptr->next;
	  else if (d_ptr->parent != NULL)
	    d_ptr->parent->child = d_ptr->next;
	  else
	    pf->d_head = d_ptr->next;

	  if (d_ptr->next != NULL)
	    d_ptr->next->prev = d_ptr->prev;
	  else if (d_ptr->parent != NULL)
	    d_ptr->parent->child_tail = d_ptr->prev;
	  else
	    pf->d_tail = d_ptr->prev;

	  d_ptr->prev = NULL;
	  d_ptr->next = NULL;
	  d_ptr->parent = NULL;

	  // ok, now place in correct place
	  cli_dbgmsg("Searching for parent\n");
	  if (desc_rec.parent_id == 0) {
	    cli_dbgmsg("No Parent\n");
	    if (pf->d_tail != NULL)
	      pf->d_tail->next = d_ptr;
	    if (pf->d_head == NULL)
	      pf->d_head = d_ptr;
	    d_ptr->prev = pf->d_tail;
	    pf->d_tail = d_ptr;
	  } else {
	    // check in the quick list
	    d_ptr_ptr = d_ptr_head;
	    while (d_ptr_ptr != NULL && d_ptr_ptr->ptr->id != desc_rec.parent_id) {
	      d_ptr_ptr = d_ptr_ptr->next;
	    }

	    if (d_ptr_ptr == NULL && (d_par = _pst_getDptr(pf, desc_rec.parent_id)) == NULL) {
	      // check in the lost/found list
	      lf_ptr = lf_head;
	      while (lf_ptr != NULL && lf_ptr->ptr->id != desc_rec.parent_id) {
		lf_ptr = lf_ptr->next;
	      }
	      if (lf_ptr == NULL) {
		cli_dbgmsg("ERROR -- not found parent with id %#x. Adding to lost/found\n", desc_rec.parent_id);
		lf_ptr = (struct _pst_d_ptr_ll*) cli_malloc(sizeof(struct _pst_d_ptr_ll));
		lf_ptr->prev = NULL;
		lf_ptr->next = lf_head;
		lf_ptr->parent = desc_rec.parent_id;
		lf_ptr->ptr = d_ptr;
		lf_head = lf_ptr;
	      } else {
		d_par = lf_ptr->ptr;
	      }
	    }

	    if (d_ptr_ptr != NULL || d_par != NULL) {
	      if (d_ptr_ptr != NULL)
		d_par = d_ptr_ptr->ptr;
	      else {
		//add the d_par to the cache
		cli_dbgmsg("Update - Cache addition\n");
		d_ptr_ptr = (struct _pst_d_ptr_ll*) cli_malloc(sizeof(struct _pst_d_ptr_ll));
		d_ptr_ptr->prev = NULL;
		d_ptr_ptr->next = d_ptr_head;
		d_ptr_ptr->ptr = d_par;
		d_ptr_head = d_ptr_ptr;
		if (d_ptr_tail == NULL)
		  d_ptr_tail = d_ptr_ptr;
		d_ptr_count++;
		if (d_ptr_count > 100) {
		  //remove on from the end
		  d_ptr_ptr = d_ptr_tail;
		  d_ptr_tail = d_ptr_ptr->prev;
		  free (d_ptr_ptr);
		  d_ptr_count--;
		}
	      }
	      cli_dbgmsg("Found a parent\n");
	      d_par->no_child++;
	      d_ptr->parent = d_par;
	      if (d_par->child_tail != NULL)
		d_par->child_tail->next = d_ptr;
	      if (d_par->child == NULL)
		d_par->child = d_ptr;
	      d_ptr->prev = d_par->child_tail;
	      d_par->child_tail = d_ptr;
	    }
	  }
	}

      } else {
	if (*high_id < (int32_t)desc_rec.d_id) {
	  cli_dbgmsg("Updating New High\n");
	  *high_id = desc_rec.d_id;
	}
	cli_dbgmsg("New Record\n");
	d_ptr = (pst_desc_ll*) cli_malloc(sizeof(pst_desc_ll));
	//	cli_dbgmsg("Item pointer is %p\n", d_ptr);
	d_ptr->id = desc_rec.d_id;
	d_ptr->list_index = _pst_getID(pf, desc_rec.list_id);
	d_ptr->desc = _pst_getID(pf, desc_rec.desc_id);
	d_ptr->prev = NULL;
	d_ptr->next = NULL;
	d_ptr->parent = NULL;
	d_ptr->child = NULL;
	d_ptr->child_tail = NULL;
	d_ptr->no_child = 0;

	cli_dbgmsg("Searching for parent\n");
	if (desc_rec.parent_id == 0 || desc_rec.parent_id == desc_rec.d_id) {
	  if (desc_rec.parent_id == 0) {
	    cli_dbgmsg("No Parent\n");
	  } else {
	    cli_dbgmsg("Record is its own parent. What is this world coming to?\n");
	  }
	  if (pf->d_tail != NULL)
	    pf->d_tail->next = d_ptr;
	  if (pf->d_head == NULL)
	    pf->d_head = d_ptr;
	  d_ptr->prev = pf->d_tail;
	  pf->d_tail = d_ptr;
	} else {
	  d_ptr_ptr = d_ptr_head;
	  while (d_ptr_ptr != NULL && d_ptr_ptr->ptr->id != desc_rec.parent_id) {
	    d_ptr_ptr = d_ptr_ptr->next;
	  }

	  if (d_ptr_ptr == NULL && (d_par = _pst_getDptr(pf, desc_rec.parent_id)) == NULL) {
	    // check in the lost/found list
	    lf_ptr = lf_head;
	    while (lf_ptr != NULL && lf_ptr->ptr->id != desc_rec.parent_id) {
	      lf_ptr = lf_ptr->next;
	    }
	    if (lf_ptr == NULL) {
	      cli_dbgmsg("ERROR -- not found parent with id %#x. Adding to lost/found\n", desc_rec.parent_id);
	      lf_ptr = (struct _pst_d_ptr_ll*) cli_malloc(sizeof(struct _pst_d_ptr_ll));
	      lf_ptr->prev = NULL;
	      lf_ptr->next = lf_head;
	      lf_ptr->parent = desc_rec.parent_id;
	      lf_ptr->ptr = d_ptr;
	      lf_head = lf_ptr;
	    } else {
	      d_par = lf_ptr->ptr;
	    }
	  }

	  if (d_ptr_ptr != NULL || d_par != NULL) {
	    if (d_ptr_ptr != NULL)
	      d_par = d_ptr_ptr->ptr;
	    else {
	      //add the d_par to the cache
	      cli_dbgmsg("Normal - Cache addition\n");
	      d_ptr_ptr = (struct _pst_d_ptr_ll*) cli_malloc(sizeof(struct _pst_d_ptr_ll));
	      d_ptr_ptr->prev = NULL;
	      d_ptr_ptr->next = d_ptr_head;
	      d_ptr_ptr->ptr = d_par;
	      d_ptr_head = d_ptr_ptr;
	      if (d_ptr_tail == NULL)
		d_ptr_tail = d_ptr_ptr;
	      d_ptr_count++;
	      if (d_ptr_count > 100) {
		//remove one from the end
		d_ptr_ptr = d_ptr_tail;
		d_ptr_tail = d_ptr_ptr->prev;
		free (d_ptr_ptr);
		d_ptr_count--;
	      }
	    }

	    cli_dbgmsg("Found a parent\n");
	    d_par->no_child++;
	    d_ptr->parent = d_par;
	    if (d_par->child_tail != NULL)
	      d_par->child_tail->next = d_ptr;
	    if (d_par->child == NULL)
	      d_par->child = d_ptr;
	    d_ptr->prev = d_par->child_tail;
	    d_par->child_tail = d_ptr;
	  }
	}
      }
      // check here to see if d_ptr is the parent of any of the items in the lost / found list
      lf_ptr = lf_head; lf_shd = NULL;
      while (lf_ptr != NULL) {
	if (lf_ptr->parent == (int32_t)d_ptr->id) {
	  d_par = d_ptr;
	  d_ptr = lf_ptr->ptr;

	  d_par->no_child++;
	  d_ptr->parent = d_par;
	  if (d_par->child_tail != NULL)
	    d_par->child_tail->next = d_ptr;
	  if (d_par->child == NULL)
	    d_par->child = d_ptr;
	  d_ptr->prev = d_par->child_tail;
	  d_par->child_tail = d_ptr;
	  if (lf_shd == NULL)
	    lf_head = lf_ptr->next;
	  else
	    lf_shd->next = lf_ptr->next;
	  lf_tmp = lf_ptr->next;
	  free(lf_ptr);
	  lf_ptr = lf_tmp;
	} else {
	  lf_shd = lf_ptr;
	  lf_ptr = lf_ptr->next;
	}
      }
      memcpy(&desc_rec, bptr, sizeof(desc_rec));
      LE32_CPU(desc_rec.d_id);
      LE32_CPU(desc_rec.desc_id);
      LE32_CPU(desc_rec.list_id);
      LE32_CPU(desc_rec.parent_id);
      bptr+= sizeof(desc_rec);
    }
    //    fseek(pf->fp, fpos, SEEK_SET);
  } else {
    // hopefully a table of offsets to more tables
    if (_pst_read_block_size(pf, offset, DESC_BLOCK_SIZE, &buf, 0, 0) < DESC_BLOCK_SIZE) {
      cli_dbgmsg("didn't read enough desc index. _pst_read_block_size returned less than requested\n");
      return -1;
    }
    bptr = buf;
    //    cli_dbgmsg(buf, DESC_BLOCK_SIZE, 12);

    memcpy(&table, bptr, sizeof(table));
    LE32_CPU(table.start);
    LE32_CPU(table.u1);
    LE32_CPU(table.offset);
    bptr+=sizeof(table);
    memcpy(&table2, bptr, sizeof(table));
    LE32_CPU(table2.start);
    LE32_CPU(table2.u1);
    LE32_CPU(table2.offset);

    if (start_id != -1 && table.start != start_id) {
      cli_dbgmsg("This table isn't right. Perhaps we are too deep, or corruption\n");
      if (buf) free (buf);
      return -1;
    }

    y = 0;
    while(table.start != 0 /*&& y < 0x1F && table.start < end_val*/) {

      if (table2.start <= table.start) {
	// for the end of our table, table2.start may equal 0
	cli_dbgmsg("2nd value in index table is less than current value. Setting to higher value [%#x, %#x, %#x]\n",
		    table.start, table2.start, INT32_MAX);
	table2.start = INT32_MAX;
      }

      if ((i = _pst_build_desc_ptr(pf, table.offset, depth+1, high_id, table.start, table2.start)) == -1 && pf->desc_depth_ok == 0) { //the table beneath isn't a table
	pf->index2_depth = depth; //set the max depth to this level
	if (buf) free(buf);
	return 4;
      } else if (i == 4) { //repeat with last tried values, but lower depth
	_pst_build_desc_ptr(pf, table.offset, depth+1, high_id, table.start, table2.start);
      }

      memcpy(&table, bptr, sizeof(table));
      LE32_CPU(table.start);
      LE32_CPU(table.u1);
      LE32_CPU(table.offset);
      bptr+=sizeof(table);
      memcpy(&table2, bptr, sizeof(table));
      LE32_CPU(table2.start);
      LE32_CPU(table2.u1);
      LE32_CPU(table2.offset);
    }
    if (buf) free(buf);
    return 3;
  }
  // ok, lets try freeing the d_ptr_head cache here
  while (d_ptr_head != NULL) {
    d_ptr_ptr = d_ptr_head->next;
    free(d_ptr_head);
    d_ptr_head = d_ptr_ptr;
  }
  if (buf) free(buf);
  return 0;
}

static void *
_pst_parse_item(pst_file *pf, pst_desc_ll *d_ptr)
{
	pst_num_array * list;
	pst_index2_ll *id2_head = NULL;
	pst_index_ll *id_ptr = NULL;
	pst_item *item = NULL;
	pst_item_attach *attach = NULL;
	int x;

	if(d_ptr == NULL) {
		cli_errmsg("you cannot pass me a NULL! I don't want it!\n");
		return NULL;
	}

	if (d_ptr->list_index != NULL) {
		id2_head = _pst_build_id2(pf, d_ptr->list_index, NULL);
	}

	if (d_ptr->desc == NULL) {
		cli_errmsg("why is d_ptr->desc == NULL? I don't want to do anything else with this record\n");
		return NULL;
	}

	if((list = _pst_parse_block(pf, d_ptr->desc->id, id2_head)) == NULL) {
		cli_errmsg("_pst_parse_block() returned an error for d_ptr->desc->id [%#x]\n", d_ptr->desc->id);
		return NULL;
	}

	item = (pst_item*) cli_calloc(1, sizeof(pst_item));

	if (_pst_process(list, item)) {
		cli_dbgmsg("_pst_process() returned non-zero value. That is an error\n");
		_pst_free_list(list);
		return NULL;
	} else {
		_pst_free_list(list);
		list = NULL; /* _pst_process will free the items in the list */
	}

  if ((id_ptr = _pst_getID2(id2_head, 0x671)) != NULL) {
    // attachements exist - so we will process them
    while (item->attach != NULL) {
      attach = item->attach->next;
      free(item->attach);
      item->attach = attach;
    }

    cli_dbgmsg("ATTACHEMENT processing attachement\n");
    if ((list = _pst_parse_block(pf, id_ptr->id, id2_head)) == NULL) {
	_pst_free_id2(id2_head);
	_pst_free_list(list);
	cli_errmsg("error processing main attachment record\n");
	return NULL;
    }
    x = 0;
    while (x < list->count_array) {
      attach = (pst_item_attach*) cli_calloc (1, sizeof(pst_item_attach));
      attach->next = item->attach;
      item->attach = attach;
      x++;
    }
    item->current_attach = item->attach;

    if (_pst_process(list, item)) {
	_pst_free_list(list);
	_pst_free_id2(id2_head);
      cli_errmsg("_pst_process() failed with attachments\n");
      return NULL;
    }
    _pst_free_list(list);

    // now we will have initial information of each attachment stored in item->attach...
    // we must now read the secondary record for each based on the id2 val associated with
    // each attachment
    attach = item->attach;
    while (attach != NULL) {
      if ((id_ptr = _pst_getID2(id2_head, attach->id2_val)) != NULL) {
	// id_ptr is a record describing the attachment
	// we pass NULL instead of id2_head cause we don't want it to
	// load all the extra stuff here.
	if ((list = _pst_parse_block(pf, id_ptr->id, NULL)) == NULL) {
	  cli_warnmsg("ERROR error processing an attachment record\n");
	  attach = attach->next;
	  continue;
	}
	item->current_attach = attach;
	if (_pst_process(list, item)) {
	  cli_dbgmsg("ERROR _pst_process() failed with an attachment\n");
	  _pst_free_list(list);
	  attach = attach->next;
	  continue;
	}
	_pst_free_list(list);
	if ((id_ptr = _pst_getID2(id2_head, attach->id2_val)) != NULL) {
	  // id2_val has been updated to the ID2 value of the datablock containing the
	  // attachment data
	  attach->id_val = id_ptr->id;
	} else {
	  cli_dbgmsg("have not located the correct value for the attachment [%#x]\n",
		      attach->id2_val);
	}
      } else {
	cli_dbgmsg("ERROR cannot locate id2 value %#x\n", attach->id2_val);
      }
      attach = attach->next;
    }
    item->current_attach = item->attach; //reset back to first
  }

  _pst_free_id2(id2_head);


  return item;
}

static pst_num_array *
_pst_parse_block(pst_file *pf, u_int32_t block_id, pst_index2_ll *i2_head)
{
  unsigned char *buf = NULL;
  pst_num_array *na_ptr = NULL, *na_head = NULL;
  pst_block_offset block_offset;
  /*  pst_index_ll *rec = NULL; */
  u_int32_t size = 0, t_ptr = 0, fr_ptr = 0, to_ptr = 0, ind_ptr = 0, x = 0, stop = 0;
  u_int32_t num_recs = 0, count_rec = 0, ind2_ptr = 0, list_start = 0, num_list = 0, cur_list = 0;
  int32_t block_type, rec_size;
  size_t read_size=0;
  pst_x_attrib_ll *mapptr;

  struct {
    u_int16_t type;
    u_int16_t ref_type;
    u_int32_t value;
  } table_rec; //for type 1 ("BC") blocks
  struct {
    u_int16_t ref_type;
    u_int16_t type;
    u_int16_t ind2_off;
    u_int16_t u1;
  } table2_rec; //for type 2 ("7C") blocks
  struct {
    u_int16_t index_offset;
    u_int16_t type;
    u_int16_t offset;
  } block_hdr;
  struct {
    unsigned char seven_c;
    unsigned char item_count;
    u_int16_t u1;
    u_int16_t u2;
    u_int16_t u3;
    u_int16_t rec_size;
    u_int16_t b_five_offset;
    u_int16_t u5;
    u_int16_t ind2_offset;
    u_int16_t u6;
    u_int16_t u7;
    u_int16_t u8;
  } seven_c_blk;
  struct _type_d_rec {
    u_int32_t id;
    u_int32_t u1;
  } * type_d_rec;

  /*  cli_dbgmsg("About to read %i bytes from offset %#x\n", block->size, block->offset); */

  if ((read_size = _pst_ff_getIDblock_dec(pf, block_id, &buf)) == 0) {
    cli_warnmsg("Error reading block id %#x\n", block_id);
    if (buf) free (buf);
    return NULL;
  }
  cli_dbgmsg("pointer to buf is %p\n", buf);

  memcpy(&block_hdr, &(buf[0]), sizeof(block_hdr));
  LE16_CPU(block_hdr.index_offset);
  LE16_CPU(block_hdr.type);
  LE16_CPU(block_hdr.offset);

  ind_ptr = block_hdr.index_offset;

  if (block_hdr.type == 0xBCEC) { //type 1
    block_type = 1;

    _pst_getBlockOffset((char *)buf, ind_ptr, block_hdr.offset, &block_offset);
    fr_ptr = block_offset.from;

    memcpy(&table_rec, &(buf[fr_ptr]), sizeof(table_rec));
    LE16_CPU(table_rec.type);
    LE16_CPU(table_rec.ref_type);
    LE32_CPU(table_rec.value);

    if (table_rec.type != 0x02B5) {
      cli_warnmsg("Unknown second block constant - %#X for id %#x\n", table_rec.type, block_id);
      if (buf) free (buf);
      return NULL;
    }

    _pst_getBlockOffset((char *)buf, ind_ptr, table_rec.value, &block_offset);
    list_start = fr_ptr = block_offset.from;
    to_ptr = block_offset.to;
    num_list = (to_ptr - fr_ptr)/sizeof(table_rec);
    num_recs = 1; /* only going to one object in these blocks */
    rec_size = 0; /* doesn't matter cause there is only one object */
  } else if (block_hdr.type == 0x7CEC) { //type 2
    block_type = 2;

    _pst_getBlockOffset((char *)buf, ind_ptr, block_hdr.offset, &block_offset);
    fr_ptr = block_offset.from; //now got pointer to "7C block"
    memset(&seven_c_blk, 0, sizeof(seven_c_blk));
    memcpy(&seven_c_blk, &(buf[fr_ptr]), sizeof(seven_c_blk));
    LE16_CPU(seven_c_blk.u1);
    LE16_CPU(seven_c_blk.u2);
    LE16_CPU(seven_c_blk.u3);
    LE16_CPU(seven_c_blk.rec_size);
    LE16_CPU(seven_c_blk.b_five_offset);
    LE16_CPU(seven_c_blk.u5);
    LE16_CPU(seven_c_blk.ind2_offset);
    LE16_CPU(seven_c_blk.u6);
    LE16_CPU(seven_c_blk.u7);
    LE16_CPU(seven_c_blk.u8);

    list_start = fr_ptr + sizeof(seven_c_blk); // the list of item numbers start after this record

    if (seven_c_blk.seven_c != 0x7C) { // this would mean it isn't a 7C block!
      cli_warnmsg("Error. There isn't a 7C where I want to see 7C!\n");
      if (buf) free(buf);
      return NULL;
    }

    rec_size = seven_c_blk.rec_size;
    num_list = seven_c_blk.item_count;
    cli_dbgmsg("b5 offset = %#x\n", seven_c_blk.b_five_offset);

    _pst_getBlockOffset((char *)buf, ind_ptr, seven_c_blk.b_five_offset, &block_offset);
    fr_ptr = block_offset.from;
    memcpy(&table_rec, &(buf[fr_ptr]), sizeof(table_rec));
    cli_dbgmsg("before convert %#x\n", table_rec.type);
    LE16_CPU(table_rec.type);
    cli_dbgmsg("after convert %#x\n", table_rec.type);
    LE16_CPU(table_rec.ref_type);
    LE32_CPU(table_rec.value);

    if (table_rec.type != 0x04B5) { // different constant than a type 1 record
      cli_warnmsg("Unknown second block constant - %#X for id %#x\n", table_rec.type, block_id);
      if (buf) free(buf);
      return NULL;
    }

	if (table_rec.value == 0) { // this is for the 2nd index offset
		cli_errmsg("reference to second index block is zero\n");
		if (buf) free(buf);
		return NULL;
	}

    _pst_getBlockOffset((char *)buf, ind_ptr, table_rec.value, &block_offset);
    num_recs = (block_offset.to - block_offset.from) / 6; // this will give the number of records in this block

    _pst_getBlockOffset((char *)buf, ind_ptr, seven_c_blk.ind2_offset, &block_offset);
    ind2_ptr = block_offset.from;
  } else {
    cli_warnmsg("ERROR: Unknown block constant - %#X for id %#x\n", block_hdr.type, block_id);
    if (buf) free(buf);
    return NULL;
  }

  cli_dbgmsg("Mallocing number of items %i\n", num_recs);
  while (count_rec < num_recs) {
    na_ptr = (pst_num_array*) cli_calloc(1, sizeof(pst_num_array));
    if (na_head == NULL) {
      na_head = na_ptr;
      na_ptr->next = NULL;
    }
    else {
      na_ptr->next = na_head;
      na_head = na_ptr;
    }
    // allocate an array of count num_recs to contain sizeof(struct_pst_num_item)
    na_ptr->items = (struct _pst_num_item**) cli_calloc(num_list, sizeof(struct _pst_num_item));
    na_ptr->count_item = num_list;
    na_ptr->count_array = num_recs; // each record will have a record of the total number of records
    x = 0;

    fr_ptr = list_start; // init fr_ptr to the start of the list.
    cur_list = 0;
    stop = 0;
    while (!stop && cur_list < num_list) { //we will increase fr_ptr as we progress through index
      if (block_type == 1) {
	memcpy(&table_rec, &(buf[fr_ptr]), sizeof(table_rec));
	LE16_CPU(table_rec.type);
	LE16_CPU(table_rec.ref_type);
	fr_ptr += sizeof(table_rec);
      } else if (block_type == 2) {
	// we will copy the table2_rec values into a table_rec record so that we can keep the rest of the code
	memcpy(&table2_rec, &(buf[fr_ptr]), sizeof(table2_rec));
	LE16_CPU(table2_rec.ref_type);
	LE16_CPU(table2_rec.type);
	LE16_CPU(table2_rec.ind2_off);
	LE16_CPU(table2_rec.u1);

	// table_rec and table2_rec are arranged differently, so assign the values across
	table_rec.type = table2_rec.type;
	table_rec.ref_type = table2_rec.ref_type;
	if (ind2_ptr+table2_rec.ind2_off > 0 &&
	    ind2_ptr+table2_rec.ind2_off < read_size-sizeof(table_rec.value))
	  memcpy(&(table_rec.value), &(buf[ind2_ptr+table2_rec.ind2_off]), sizeof(table_rec.value));
	else {
	  cli_dbgmsg("trying to read more than blocks size. Size=%#x, Req.=%#x,"
		" Req Size=%#x\n", read_size, ind2_ptr+table2_rec.ind2_off,
			sizeof(table_rec.value));
	}

	fr_ptr += sizeof(table2_rec);
      } else {
	cli_warnmsg("Missing code for block_type %i\n", block_type);
	if (buf) free(buf);
	if(na_head)
		_pst_free_list(na_head);
	return NULL;
      }
      cur_list++; // get ready to read next bit from list

      na_ptr->items[x] = (struct _pst_num_item*) cli_calloc(1, sizeof(struct _pst_num_item));
      //      cli_dbgmsg("_pst_parse_block:   record address = %p\n", na_ptr->items[x]);

      // check here to see if the id of the attribute is a mapped one
      mapptr = pf->x_head;
      while (mapptr != NULL && mapptr->map < table_rec.type)
	mapptr = mapptr->next;
      if (mapptr != NULL && mapptr->map == table_rec.type) {
	if (mapptr->mytype == PST_MAP_ATTRIB) {
	  na_ptr->items[x]->id = *((int*)mapptr->data);
	  cli_dbgmsg("Mapped attrib %#x to %#x\n", table_rec.type, na_ptr->items[x]->id);
	} else if (mapptr->mytype == PST_MAP_HEADER) {
	  cli_dbgmsg("Internet Header mapping found %#x\n", table_rec.type);
	  na_ptr->items[x]->id = PST_ATTRIB_HEADER;
	  na_ptr->items[x]->extra = mapptr->data;
	}
      } else {
	na_ptr->items[x]->id = table_rec.type;
      }
      na_ptr->items[x]->type = 0; // checked later before it is set
	/* Reference Types

	 2 - 0x0002 - Signed 16bit value
	 3 - 0x0003 - Signed 32bit value
	 4 - 0x0004 - 4-byte floating point
	 5 - 0x0005 - Floating point double
	 6 - 0x0006 - Signed 64-bit int
	 7 - 0x0007 - Application Time
	10 - 0x000A - 32-bit error value
	11 - 0x000B - Boolean (non-zero = true)
	13 - 0x000D - Embedded Object
	20 - 0x0014 - 8-byte signed integer (64-bit)
	30 - 0x001E - Null terminated String
	31 - 0x001F - Unicode string
	64 - 0x0040 - Systime - Filetime structure
	72 - 0x0048 - OLE Guid
       258 - 0x0102 - Binary data

	   - 0x1003 - Array of 32bit values
	   - 0x1014 - Array of 64bit values
	   - 0x101E - Array of Strings
	   - 0x1102 - Array of Binary data
      */

      if (table_rec.ref_type == 0x0003 || table_rec.ref_type == 0x000b
	  || table_rec.ref_type == 0x0002) { //contains data
	na_ptr->items[x]->data = cli_malloc(sizeof(int32_t));
	memcpy(na_ptr->items[x]->data, &(table_rec.value), sizeof(int32_t));

	na_ptr->items[x]->size = sizeof(int32_t);
	na_ptr->items[x]->type = table_rec.ref_type;

      } else if (table_rec.ref_type == 0x0005 || table_rec.ref_type == 0x000D
		 || table_rec.ref_type == 0x1003 || table_rec.ref_type == 0x0014
		 || table_rec.ref_type == 0x001E || table_rec.ref_type == 0x0102
		 || table_rec.ref_type == 0x0040 || table_rec.ref_type == 0x101E
		 || table_rec.ref_type == 0x0048 || table_rec.ref_type == 0x1102
		 || table_rec.ref_type == 0x1014) {
	//contains index_ref to data
	LE32_CPU(table_rec.value);
	if ((table_rec.value & 0x0000000F) == 0xF) {
	  // if value ends in 'F' then this should be an id2 value
	  cli_dbgmsg("Found id2 [%#x] value. Will follow it\n",
		      table_rec.value);
	  if ((na_ptr->items[x]->size = _pst_ff_getID2block(pf, table_rec.value, i2_head,
							    &(na_ptr->items[x]->data)))==0) {
	    cli_dbgmsg("not able to read the ID2 data. Setting to be read later. %#x\n",
		  table_rec.value);
	    na_ptr->items[x]->size = 0;
	    na_ptr->items[x]->data = NULL;
	    na_ptr->items[x]->type = table_rec.value;
	  }
	  cli_dbgmsg("Read %i bytes to a buffer at %p\n",
		na_ptr->items[x]->size, na_ptr->items[x]->data);
	} else if (table_rec.value != 0) {
	  if ((table_rec.value >> 4)+ind_ptr > read_size) {
	    // check that we will not be outside the buffer we have read
	    cli_dbgmsg("table_rec.value [%#x] is outside of block [%#x]\n",
		  table_rec.value, read_size);
	    na_ptr->count_item --;
		free(na_ptr->items[x]);
		na_ptr->items[x] = NULL;
	    continue;
	  }
	  if (_pst_getBlockOffset((char *)buf, ind_ptr, table_rec.value, &block_offset)) {
	    cli_dbgmsg("failed to get block offset for table_rec.value of %#x\n",
		  table_rec.value);
	    na_ptr->count_item --; //we will be skipping a row
		free(na_ptr->items[x]);
		na_ptr->items[x] = NULL;
	    continue;
	  }
	  t_ptr = block_offset.from;
	  if (t_ptr <= (u_int32_t)block_offset.to) {
	    na_ptr->items[x]->size = size = block_offset.to - t_ptr;
	  } else {
	    cli_dbgmsg("I don't want to malloc less than zero sized block. from=%#x, to=%#x."
		  "Will change to 1 byte\n", block_offset.from, block_offset.to);
	    na_ptr->items[x]->size = size = 0; // the malloc statement will add one to this
	  }

	  // plus one for good luck (and strings) we will null terminate all reads
	  na_ptr->items[x]->data = (unsigned char *)cli_malloc(size+1);
	  memcpy(na_ptr->items[x]->data, &(buf[t_ptr]), size);
	  na_ptr->items[x]->data[size] = '\0'; // null terminate buffer

	  if (table_rec.ref_type == 0xd) {
	    // there is still more to do for the type of 0xD
	    type_d_rec = (struct _type_d_rec*) na_ptr->items[x]->data;
	    LE32_CPU(type_d_rec->id);
	    if ((na_ptr->items[x]->size =
		 _pst_ff_getID2block(pf, type_d_rec->id, i2_head,
				     &(na_ptr->items[x]->data)))==0){
	      cli_dbgmsg("not able to read the ID2 data. Setting to be read later. %#x\n",
		    type_d_rec->id);
	      na_ptr->items[x]->size = 0;
		na_ptr->items[x]->type = type_d_rec->id;
		if (na_ptr->items[x]->data) {
			free(na_ptr->items[x]->data);
			na_ptr->items[x]->data = NULL;
		}
	    }
	    cli_dbgmsg("Read %i bytes into a buffer at %p\n",
			 na_ptr->items[x]->size, na_ptr->items[x]->data);
	    //	  }
	  }
	} else {
	  cli_dbgmsg("Ignoring 0 value in offset\n");
	  if (na_ptr->items[x]->data)
	    free (na_ptr->items[x]->data);
	  na_ptr->items[x]->data = NULL;

	  free(na_ptr->items[x]);

	  na_ptr->count_item--; // remove this item from the destination list
	  continue;
	}
	if (na_ptr->items[x]->type == 0) //it can be used to convey information
	  // to later functions
	  na_ptr->items[x]->type = table_rec.ref_type;
      } else {
	cli_warnmsg("ERROR Unknown ref_type %#x\n", table_rec.ref_type);
	if(na_head)
	_pst_free_list(na_head);
	return NULL;
      }
      x++;
    }
    cli_dbgmsg("increasing ind2_ptr by %i [%#x] bytes. Was %#x, Now %#x\n",
		rec_size, rec_size, ind2_ptr,
		ind2_ptr+rec_size);
    ind2_ptr += rec_size;
    count_rec++;
  }
  if (buf != NULL)
    free(buf);
  return na_head;
}

// check if item->email is NULL, and init if so
#define MALLOC_EMAIL(x) { if (x->email == NULL) { x->email = (pst_item_email*) cli_malloc(sizeof(pst_item_email)); memset (x->email, 0, sizeof(pst_item_email));} }
#define MALLOC_FOLDER(x) { if (x->folder == NULL) { x->folder = (pst_item_folder*) cli_malloc(sizeof(pst_item_folder)); memset (x->folder, 0, sizeof(pst_item_folder));} }
#define MALLOC_CONTACT(x) { if (x->contact == NULL) { x->contact = (pst_item_contact*) cli_malloc(sizeof(pst_item_contact)); memset(x->contact, 0, sizeof(pst_item_contact));} }
#define MALLOC_MESSAGESTORE(x) { if (x->message_store == NULL) { x->message_store = (pst_item_message_store*) cli_malloc(sizeof(pst_item_message_store)); memset(x->message_store, 0, sizeof(pst_item_message_store)); } }
#define MALLOC_JOURNAL(x) { if (x->journal == NULL) { x->journal = (pst_item_journal*) cli_malloc(sizeof(pst_item_journal)); memset(x->journal, 0, sizeof(pst_item_journal));} }
#define MALLOC_APPOINTMENT(x) { if (x->appointment == NULL) { x->appointment = (pst_item_appointment*) cli_malloc(sizeof(pst_item_appointment)); memset(x->appointment, 0, sizeof(pst_item_appointment)); } }
// malloc space and copy the current item's data -- plus one on the size for good luck (and string termination)
#define LIST_COPY(targ, type) { \
  targ = type cli_realloc(targ, list->items[x]->size+1); \
  memset(targ, 0, list->items[x]->size+1); \
  memcpy(targ, list->items[x]->data, list->items[x]->size); \
}

/*  free(list->items[x]->data); \
    list->items[x]->data=NULL; \*/

//#define INC_CHECK_X() { if (++x >= list->count_item) break; }
#define NULL_CHECK(x) { if (x == NULL) { cli_dbgmsg("NULL_CHECK: Null Found\n"); break;} }

#define MOVE_NEXT(targ) { \
  if (next){\
    if ((char*)targ == NULL) {\
      cli_dbgmsg("MOVE_NEXT: Target is NULL. Will stop processing this option\n");\
      break;\
    }\
    targ = targ->next;\
    if ((char*)targ == NULL) {\
      cli_dbgmsg("MOVE_NEXT: Target is NULL after next. Will stop processing this option\n");\
      break;\
    }\
    next=0;\
  }\
}

int32_t _pst_process(pst_num_array *list , pst_item *item) {
  int32_t x, t;
  int32_t next = 0;
  pst_item_attach *attach;
  pst_item_extra_field *ef;

  if (item == NULL) {
    cli_dbgmsg("item cannot be NULL.\n");
    return -1;
  }

  attach = item->current_attach; // a working variable

  while (list != NULL) {
    x = 0;
    while (x < list->count_item) {
      // check here to see if the id is one that is mapped.
      cli_dbgmsg("#%d - id: %#x type: %#x length: %#x\n", x, list->items[x]->id, list->items[x]->type,
		   list->items[x]->size);

      switch (list->items[x]->id) {
      case PST_ATTRIB_HEADER: // CUSTOM attribute for saying the Extra Headers
	cli_dbgmsg("Extra Field - ");
	ef = (pst_item_extra_field*) cli_calloc(1, sizeof(pst_item_extra_field));
	ef->field_name = strdup(list->items[x]->extra);
	LIST_COPY(ef->value, (char*));
	ef->next = item->extra_fields;
	item->extra_fields = ef;
	cli_dbgmsg("\"%s\" = \"%s\"\n", ef->field_name, ef->value);
	break;
      case 0x0002: // PR_ALTERNATE_RECIPIENT_ALLOWED
	// If set to true, the sender allows this email to be autoforwarded
	cli_dbgmsg("AutoForward allowed - ");
	MALLOC_EMAIL(item);
	if (*((short int*)list->items[x]->data) != 0) {
	  cli_dbgmsg("True\n");
	  item->email->autoforward = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->email->autoforward = -1;
	}
	//	INC_CHECK_X();
	break;
      case 0x0003: // Extended Attributes table
	cli_dbgmsg("Extended Attributes Table - NOT PROCESSED\n");
	break;
      case 0x0017: // PR_IMPORTANCE
	// How important the sender deems it to be
	// 0 - Low
	// 1 - Normal
	// 2 - High

	cli_dbgmsg("Importance Level - ");
	MALLOC_EMAIL(item);
	memcpy(&(item->email->importance), list->items[x]->data, sizeof(item->email->importance));
	LE32_CPU(item->email->importance);
	t = item->email->importance;
	//	INC_CHECK_X();
	break;
      case 0x001A: // PR_MESSAGE_CLASS Ascii type of messages - NOT FOLDERS
	// must be case insensitive
	cli_dbgmsg("IPM.x - ");
	LIST_COPY(item->ascii_type, (char*));
	if (strncasecmp("IPM.Note", item->ascii_type, 8) == 0)
	  // the string begins with IPM.Note...
	  item->type = PST_TYPE_NOTE;
	else if (strcasecmp("IPM", item->ascii_type) == 0)
	  // the whole string is just IPM
	  item->type = PST_TYPE_NOTE;
	else if (strncasecmp("IPM.Contact", item->ascii_type, 11) == 0)
	  // the string begins with IPM.Contact...
	  item->type = PST_TYPE_CONTACT;
	else if (strncasecmp("REPORT.IPM.Note", item->ascii_type, 15) == 0)
	  // the string begins with the above
	  item->type = PST_TYPE_REPORT;
	else if (strncasecmp("IPM.Activity", item->ascii_type, 12) == 0)
	  item->type = PST_TYPE_JOURNAL;
	else if (strncasecmp("IPM.Appointment", item->ascii_type, 15) == 0)
	  item->type = PST_TYPE_APPOINTMENT;
	else
	  item->type = PST_TYPE_OTHER;

	cli_dbgmsg("%s\n", item->ascii_type);
	//	INC_CHECK_X(); //increment x here so that the next if statement has a chance of matching the next item
	break;
      case 0x0023: // PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED
	// set if the sender wants a delivery report from all recipients
	cli_dbgmsg("Global Delivery Report - ");
	MALLOC_EMAIL(item);
	if (*(int16_t*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->email->delivery_report = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->email->delivery_report = 0;
	}
	//	INC_CHECK_X();
	break;
      case 0x0026: // PR_PRIORITY
	// Priority of a message
	// -1 NonUrgent
	//  0 Normal
	//  1 Urgent
	cli_dbgmsg("Priority - ");
	MALLOC_EMAIL(item);
	memcpy(&(item->email->priority), list->items[x]->data, sizeof(item->email->priority));
	LE32_CPU(item->email->priority);
	t = item->email->priority;
	//	INC_CHECK_X();
	break;
      case 0x0029:// PR_READ_RECEIPT_REQUESTED
	cli_dbgmsg("Read Receipt - ");
	MALLOC_EMAIL(item);
	if (*(short int*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->email->read_receipt = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->email->read_receipt = 0;
	}
	//	INC_CHECK_X();
	break;
      case 0x002B: // PR_RECIPIENT_REASSIGNMENT_PROHIBITED
	cli_dbgmsg("Private) - ");
	if (*(short int*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->private = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->private = 0;
	}
	break;
      case 0x002E: // PR_ORIGINAL_SENSITIVITY
	// the sensitivity of the message before being replied to or forwarded
	// 0 - None
	// 1 - Personal
	// 2 - Private
	// 3 - Company Confidential
	cli_dbgmsg("Original Sensitivity - ");
	MALLOC_EMAIL(item);
	memcpy(&(item->email->orig_sensitivity), list->items[x]->data, sizeof(item->email->orig_sensitivity));
	LE32_CPU(item->email->orig_sensitivity);
	t = item->email->orig_sensitivity;
	//	INC_CHECK_X();
	break;
      case 0x0036: // PR_SENSITIVITY
	// sender's opinion of the sensitivity of an email
	// 0 - None
	// 1 - Personal
	// 2 - Private
	// 3 - Company Confidiential
	cli_dbgmsg("Sensitivity - ");
	MALLOC_EMAIL(item);
	memcpy(&(item->email->sensitivity), list->items[x]->data, sizeof(item->email->sensitivity));
	LE32_CPU(item->email->sensitivity);
	t = item->email->sensitivity;
	//	INC_CHECK_X();
	break;
      case 0x0037: // PR_SUBJECT raw subject
	//      if (list->items[x]->id == 0x0037) {
	cli_dbgmsg("Raw Subject - ");
	MALLOC_EMAIL(item);
	item->email->subject = (pst_item_email_subject*) cli_realloc(item->email->subject, sizeof(pst_item_email_subject));
	memset(item->email->subject, 0, sizeof(pst_item_email_subject));
	cli_dbgmsg(" [size = %i] ", list->items[x]->size);
	if (list->items[x]->size > 0) {
	  if (isprint(list->items[x]->data[0])) {
	    // then there are no control bytes at the front
	    item->email->subject->off1 = 0;
	    item->email->subject->off2 = 0;
	    item->email->subject->subj = cli_realloc(item->email->subject->subj, list->items[x]->size+1);
	    memset(item->email->subject->subj, 0, list->items[x]->size+1);
	    memcpy(item->email->subject->subj, list->items[x]->data, list->items[x]->size);
	  } else {
	    cli_dbgmsg("Raw Subject has control codes\n");
	    // there might be some control bytes in the first and second bytes
	    item->email->subject->off1 = list->items[x]->data[0];
	    item->email->subject->off2 = list->items[x]->data[1];
	    item->email->subject->subj = cli_realloc(item->email->subject->subj, (list->items[x]->size-2)+1);
	    memset(item->email->subject->subj, 0, list->items[x]->size-1);
	    memcpy(item->email->subject->subj, &(list->items[x]->data[2]), list->items[x]->size-2);
	  }
	  cli_dbgmsg("%s\n", item->email->subject->subj);
	} else {
	  // obviously outlook has decided not to be straight with this one.
	  item->email->subject->off1 = 0;
	  item->email->subject->off2 = 0;
	  item->email->subject = NULL;
	  cli_dbgmsg("NULL subject detected\n");
	}
	break;
	//	INC_CHECK_X();
      case 0x0039: // PR_CLIENT_SUBMIT_TIME Date Email Sent/Created
	cli_dbgmsg("Date sent - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->sent_date, (FILETIME*));
	LE32_CPU(item->email->sent_date->dwLowDateTime);
	LE32_CPU(item->email->sent_date->dwHighDateTime);
	//	INC_CHECK_X();
	break;
      case 0x003B: // PR_SENT_REPRESENTING_SEARCH_KEY Sender address 1
	cli_dbgmsg("Sent on behalf of address 1 - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->outlook_sender, (char*));
	cli_dbgmsg("%s\n", item->email->outlook_sender);
	//	INC_CHECK_X();
	break;
      case 0x003F: // PR_RECEIVED_BY_ENTRYID Structure containing Recipient
	cli_dbgmsg("Recipient Structure 1 -- NOT HANDLED\n");
	//	INC_CHECK_X();
	break;
      case 0x0040: // PR_RECEIVED_BY_NAME Name of Recipient Structure
	cli_dbgmsg("Received By Name 1 -- NOT HANDLED\n");
	//INC_CHECK_X();
	break;
      case 0x0041: // PR_SENT_REPRESENTING_ENTRYID Structure containing Sender
	cli_dbgmsg("Sent on behalf of Structure 1 -- NOT HANDLED\n");
	//INC_CHECK_X();
	break;
      case 0x0042: // PR_SENT_REPRESENTING_NAME Name of Sender Structure
	cli_dbgmsg("Sent on behalf of Structure Name - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->outlook_sender_name, (char*));
	cli_dbgmsg("%s\n", item->email->outlook_sender_name);
	//INC_CHECK_X();
	break;
      case 0x0043: // PR_RCVD_REPRESENTING_ENTRYID Recipient Structure 2
	cli_dbgmsg("Received on behalf of Structure -- NOT HANDLED\n");
	//INC_CHECK_X();
	break;
      case 0x0044: // PR_RCVD_REPRESENTING_NAME Name of Recipient Structure 2
	cli_dbgmsg("Received on behalf of Structure Name -- NOT HANDLED\n");
	//INC_CHECK_X();
	break;
      case 0x004F: // PR_REPLY_RECIPIENT_ENTRIES Reply-To Structure
	cli_dbgmsg("Reply-To Structure -- NOT HANDLED\n");
	//INC_CHECK_X();
	break;
      case 0x0050: // PR_REPLY_RECIPIENT_NAMES Name of Reply-To Structure
	cli_dbgmsg("Name of Reply-To Structure -");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->reply_to, (char*));
	cli_dbgmsg("%s\n", item->email->reply_to);
	//INC_CHECK_X();
	break;
      case 0x0051: // PR_RECEIVED_BY_SEARCH_KEY Recipient Address 1
	cli_dbgmsg("Search Key) - ");
	MALLOC_EMAIL(item);
	LIST_COPY (item->email->outlook_recipient, (char*));
	cli_dbgmsg("%s\n", item->email->outlook_recipient);
	//INC_CHECK_X();
	break;
      case 0x0052: // PR_RCVD_REPRESENTING_SEARCH_KEY Recipient Address 2
	cli_dbgmsg("Search Key) - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->outlook_recipient2, (char*));
	cli_dbgmsg("%s\n", item->email->outlook_recipient2);
	//INC_CHECK_X();
	break;
      case 0x0057: // PR_MESSAGE_TO_ME
	// this user is listed explicitly in the TO address
	cli_dbgmsg("My address in TO field - ");
	MALLOC_EMAIL(item);
	if (*(int16_t*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->email->message_to_me = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->email->message_to_me = 0;
	}
	//INC_CHECK_X();
	break;
      case 0x0058: // PR_MESSAGE_CC_ME
	// this user is listed explicitly in the CC address
	cli_dbgmsg("My address in CC field - ");
	MALLOC_EMAIL(item);
	if (*(int16_t*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->email->message_cc_me = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->email->message_cc_me = 0;
	}
	//INC_CHECK_X();
	break;
      case 0x0059: //PR_MESSAGE_RECIP_ME
	// this user appears in TO, CC or BCC address list
	cli_dbgmsg("Message addressed to me - ");
	MALLOC_EMAIL(item);
	if (*(int16_t*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->email->message_recip_me = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->email->message_recip_me = 0;
	}
	//INC_CHECK_X();
	break;
      case 0x0063: // PR_RESPONSE_REQUESTED
	cli_dbgmsg("Response requested - ");
	if (*(int16_t*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->response_requested = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->response_requested = 0;
	}
	break;
      case 0x0064: // PR_SENT_REPRESENTING_ADDRTYPE Access method for Sender Address
	cli_dbgmsg("Sent on behalf of address type - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->sender_access, (char*));
	cli_dbgmsg("%s\n", item->email->sender_access);
	//INC_CHECK_X();
	break;
      case 0x0065: // PR_SENT_REPRESENTING_EMAIL_ADDRESS Sender Address
	cli_dbgmsg("Sent on behalf of Address - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->sender_address, (char*));
	cli_dbgmsg("%s\n", item->email->sender_address);
	//INC_CHECK_X();
	break;
      case 0x0070: // PR_CONVERSATION_TOPIC Processed Subject
	cli_dbgmsg("Conversation Topic) - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->proc_subject, (char*));
	cli_dbgmsg("%s\n", item->email->proc_subject);
	//INC_CHECK_X();
	break;
      case 0x0071: // PR_CONVERSATION_INDEX Date 2
	cli_dbgmsg("Conversation Index - ");
	MALLOC_EMAIL(item);
	memcpy(&(item->email->conv_index), list->items[x]->data, sizeof(item->email->conv_index));
	cli_dbgmsg("%i\n", item->email->conv_index);
	//INC_CHECK_X();
	break;
      case 0x0075: // PR_RECEIVED_BY_ADDRTYPE Recipient Access Method
	cli_dbgmsg("Received by Address type - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->recip_access, (char*));
	cli_dbgmsg("%s\n", item->email->recip_access);
	//INC_CHECK_X();
	break;
      case 0x0076: // PR_RECEIVED_BY_EMAIL_ADDRESS Recipient Address
	cli_dbgmsg("Received by Address - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->recip_address, (char*));
	cli_dbgmsg("%s\n", item->email->recip_address);
	//INC_CHECK_X();
	break;
      case 0x0077: // PR_RCVD_REPRESENTING_ADDRTYPE Recipient Access Method 2
	cli_dbgmsg("Received on behalf of Address type - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->recip2_access, (char*));
	cli_dbgmsg("%s\n", item->email->recip2_access);
	//INC_CHECK_X();
	break;
      case 0x0078: // PR_RCVD_REPRESENTING_EMAIL_ADDRESS Recipient Address 2
	cli_dbgmsg("Received on behalf of Address -");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->recip2_address, (char*));
	cli_dbgmsg("%s\n", item->email->recip2_address);
	//INC_CHECK_X();
	break;
      case 0x007D: // PR_TRANSPORT_MESSAGE_HEADERS Internet Header
	cli_dbgmsg("Internet Header - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->header, (char*));
	//cli_dbgmsg("%s\n", item->email->header);
	cli_dbgmsg("NOT PRINTED\n");
	//INC_CHECK_X();
	break;
      case 0x0C17: // PR_REPLY_REQUESTED
	cli_dbgmsg("Reply Requested - ");
	MALLOC_EMAIL(item);
	if (*(int16_t*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->email->reply_requested = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->email->reply_requested = 0;
	}
	break;
      case 0x0C19: // PR_SENDER_ENTRYID Sender Structure 2
	cli_dbgmsg("Sender Structure 2 -- NOT HANDLED\n");
	//INC_CHECK_X();
	break;
      case 0x0C1A: // PR_SENDER_NAME Name of Sender Structure 2
	cli_dbgmsg("Name of Sender Structure 2 -- NOT HANDLED\n");
	//INC_CHECK_X();
	break;
      case 0x0C1D: // PR_SENDER_SEARCH_KEY Name of Sender Address 2
	cli_dbgmsg("Sender search key) - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->outlook_sender2, (char*));
	cli_dbgmsg("%s\n", item->email->outlook_sender2);
	//INC_CHECK_X();
	break;
      case 0x0C1E: // PR_SENDER_ADDRTYPE Sender Address 2 access method
	cli_dbgmsg("Sender Address type - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->sender2_access, (char*));
	cli_dbgmsg("%s\n", item->email->sender2_access);
	//INC_CHECK_X();
	break;
      case 0x0C1F: // PR_SENDER_EMAIL_ADDRESS Sender Address 2
	cli_dbgmsg("Sender Address - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->sender2_address, (char*));
	cli_dbgmsg("%s\n", item->email->sender2_address);
	//INC_CHECK_X();
	break;
      case 0x0E01: // PR_DELETE_AFTER_SUBMIT
	// I am not too sure how this works
	cli_dbgmsg("Delete after submit - ");
	MALLOC_EMAIL(item);
	if (*(int16_t*) list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->email->delete_after_submit = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->email->delete_after_submit = 0;
	}
	//INC_CHECK_X();
	break;
      case 0x0E03: // PR_DISPLAY_CC CC Addresses
	cli_dbgmsg("Display CC Addresses - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->cc_address, (char*));
	cli_dbgmsg("%s\n", item->email->cc_address);
	//INC_CHECK_X();
	break;
      case 0x0E04: // PR_DISPLAY_TO Address Sent-To
	cli_dbgmsg("Display Sent-To Address - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->sentto_address, (char*));
	cli_dbgmsg("%s\n", item->email->sentto_address);
	//INC_CHECK_X();
	break;
      case 0x0E06: // PR_MESSAGE_DELIVERY_TIME Date 3 - Email Arrival Date
	cli_dbgmsg("Delivery Time) - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->arrival_date, (FILETIME*));
	//INC_CHECK_X();
	break;
      case 0x0E07: // PR_MESSAGE_FLAGS Email Flag
	// 0x01 - Read
	// 0x02 - Unmodified
	// 0x04 - Submit
	// 0x08 - Unsent
	// 0x10 - Has Attachments
	// 0x20 - From Me
	// 0x40 - Associated
	// 0x80 - Resend
	// 0x100 - RN Pending
	// 0x200 - NRN Pending
	cli_dbgmsg("Message Flags - ");
	MALLOC_EMAIL(item);
	memcpy(&(item->email->flag), list->items[x]->data, sizeof(item->email->flag));
	LE32_CPU(item->email->flag);
	cli_dbgmsg("%i\n", item->email->flag);
	//INC_CHECK_X();
	break;
      case 0x0E08: // PR_MESSAGE_SIZE Total size of a message object
	cli_dbgmsg("Message Size - ");
	memcpy(&(item->message_size), list->items[x]->data, sizeof(item->message_size));
	LE32_CPU(item->message_size);
	cli_dbgmsg("%i [%#x]\n", item->message_size, item->message_size);
	//INC_CHECK_X();
	break;
      case 0x0E0A: // PR_SENTMAIL_ENTRYID
	// folder that this message is sent to after submission
	cli_dbgmsg("Sentmail EntryID - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->sentmail_folder, (pst_entryid*));
	LE32_CPU(item->email->sentmail_folder->id);
	cli_dbgmsg("[id = %#x]\n", item->email->sentmail_folder->id);
	//INC_CHECK_X();
	break;
      case 0x0E1F: // PR_RTF_IN_SYNC
	// True means that the rtf version is same as text body
	// False means rtf version is more up-to-date than text body
	// if this value doesn't exist, text body is more up-to-date than rtf and
	//   cannot update to the rtf
	cli_dbgmsg("Compressed RTF in Sync - ");
	MALLOC_EMAIL(item);
	if (*(int16_t*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->email->rtf_in_sync = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->email->rtf_in_sync = 0;
	}
	//INC_CHECK_X();
	break;
      case 0x0E20: // PR_ATTACH_SIZE binary Attachment data in record
	cli_dbgmsg("Attachment Size - ");
	NULL_CHECK(attach);
	MOVE_NEXT(attach);
	memcpy(&(attach->size), list->items[x]->data, sizeof(attach->size));
	cli_dbgmsg("%i\n", attach->size);
	//INC_CHECK_X();
	break;
      case 0x0FF9: // PR_RECORD_KEY Record Header 1
	cli_dbgmsg("Record Key 1 - ");
	LIST_COPY(item->record_key, (char*));
	item->record_key_size = list->items[x]->size;
	cli_dbgmsg(item->record_key, item->record_key_size);
	cli_dbgmsg("\n");
	//INC_CHECK_X();
	break;
      case 0x1000: // PR_BODY Plain Text body
	cli_dbgmsg("Plain Text body - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->body, (char*));
	//cli_dbgmsg("%s\n", item->email->body);
	cli_dbgmsg("NOT PRINTED\n");
	//INC_CHECK_X();
	break;
      case 0x1006: // PR_RTF_SYNC_BODY_CRC
	cli_dbgmsg("RTF Sync Body CRC - ");
	MALLOC_EMAIL(item);
	memcpy(&(item->email->rtf_body_crc), list->items[x]->data,
		sizeof(item->email->rtf_body_crc));
	LE32_CPU(item->email->rtf_body_crc);
	cli_dbgmsg("%#x\n", item->email->rtf_body_crc);
	//INC_CHECK_X();
	break;
      case 0x1007: // PR_RTF_SYNC_BODY_COUNT
	// a count of the *significant* charcters in the rtf body. Doesn't count
	// whitespace and other ignorable characters
	cli_dbgmsg("RTF Sync Body character count - ");
	MALLOC_EMAIL(item);
	memcpy(&(item->email->rtf_body_char_count), list->items[x]->data,
		sizeof(item->email->rtf_body_char_count));
	LE32_CPU(item->email->rtf_body_char_count);
	cli_dbgmsg("%i [%#x]\n", item->email->rtf_body_char_count,
		     item->email->rtf_body_char_count);
	//INC_CHECK_X();
	break;
      case 0x1008: // PR_RTF_SYNC_BODY_TAG
	// the first couple of lines of RTF body so that after modification, then beginning can
	// once again be found
	cli_dbgmsg("RTF Sync body tag - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->rtf_body_tag, (char*));
	cli_dbgmsg("%s\n", item->email->rtf_body_tag);
	//INC_CHECK_X();
	break;
      case 0x1009: // PR_RTF_COMPRESSED
	// some compression algorithm has been applied to this. At present
	// it is unknown
	cli_dbgmsg("RTF Compressed body - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->rtf_compressed, (char*));
	//	cli_dbgmsg("Pointer: %p\n", item->email->rtf_compressed);
	cli_dbgmsg("NOT PRINTED\n");
	//INC_CHECK_X();
	break;
      case 0x1010: // PR_RTF_SYNC_PREFIX_COUNT
	// a count of the ignored characters before the first significant character
	cli_dbgmsg("RTF whitespace prefix count - ");
	MALLOC_EMAIL(item);
	memcpy(&(item->email->rtf_ws_prefix_count), list->items[x]->data,
		sizeof(item->email->rtf_ws_prefix_count));
	cli_dbgmsg("%i\n", item->email->rtf_ws_prefix_count);
	//INC_CHECK_X();
	break;
      case 0x1011: // PR_RTF_SYNC_TRAILING_COUNT
	// a count of the ignored characters after the last significant character
	cli_dbgmsg("RTF whitespace tailing count - ");
	MALLOC_EMAIL(item);
	memcpy(&(item->email->rtf_ws_trailing_count), list->items[x]->data,
	       sizeof(item->email->rtf_ws_trailing_count));
	cli_dbgmsg("%i\n", item->email->rtf_ws_trailing_count);
	//INC_CHECK_X();
	break;
      case 0x1013: // HTML body
	cli_dbgmsg("HTML body - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->htmlbody, (char*));
	//	cli_dbgmsg("%s\n", item->email->htmlbody);
	cli_dbgmsg("NOT PRINTED\n");
	//INC_CHECK_X();
	break;
      case 0x1035: // Message ID
	cli_dbgmsg("Message ID - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->messageid, (char*));
	cli_dbgmsg("%s\n", item->email->messageid);
	//INC_CHECK_X();
	break;
      case 0x1042: // in-reply-to
	cli_dbgmsg("In-Reply-To - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->in_reply_to, (char*));
	cli_dbgmsg("%s\n", item->email->in_reply_to);
	//INC_CHECK_X();
	break;
      case 0x1046: // Return Path
	cli_dbgmsg("Return Path - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->return_path_address, (char*));
	cli_dbgmsg("%s\n", item->email->return_path_address);
	//INC_CHECK_X();
	break;
      case 0x3001: // PR_DISPLAY_NAME File As
	cli_dbgmsg("Display Name - ");
	LIST_COPY(item->file_as, (char*));
	cli_dbgmsg("%s\n", item->file_as);
	//INC_CHECK_X();
	break;
      case 0x3002: // PR_ADDRTYPE
	cli_dbgmsg("Address Type - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address1_transport, (char*));
	cli_dbgmsg("%s\n", item->contact->address1_transport);
	//INC_CHECK_X();
	break;
      case 0x3003: // PR_EMAIL_ADDRESS
	// Contact's email address
	cli_dbgmsg("Contact Address - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address1, (char*));
	cli_dbgmsg("%s\n", item->contact->address1);
	//INC_CHECK_X();
	break;
      case 0x3004: // PR_COMMENT Comment for item - usually folders
	cli_dbgmsg("Comment - ");
	LIST_COPY(item->comment, (char*));
	cli_dbgmsg("%s\n", item->comment);
	//INC_CHECK_X();
	break;
      case 0x3007: // PR_CREATION_TIME Date 4 - Creation Date?
	cli_dbgmsg("Item Creation Date) - ");
	LIST_COPY(item->create_date, (FILETIME*));
	//INC_CHECK_X();
	break;
      case 0x3008: // PR_LAST_MODIFICATION_TIME Date 5 - Modify Date
	cli_dbgmsg("Modify Date) - ");
	LIST_COPY(item->modify_date, (FILETIME*));
	//INC_CHECK_X();
	break;
      case 0x300B: // PR_SEARCH_KEY Record Header 2
	cli_dbgmsg("Record Search 2 -- NOT HANDLED\n");
	//INC_CHECK_X();
	break;
      case 0x35DF: // PR_VALID_FOLDER_MASK
	// States which folders are valid for this message store
	// FOLDER_IPM_SUBTREE_VALID 0x1
	// FOLDER_IPM_INBOX_VALID   0x2
	// FOLDER_IPM_OUTBOX_VALID  0x4
	// FOLDER_IPM_WASTEBOX_VALID 0x8
	// FOLDER_IPM_SENTMAIL_VALID 0x10
	// FOLDER_VIEWS_VALID        0x20
	// FOLDER_COMMON_VIEWS_VALID 0x40
	// FOLDER_FINDER_VALID       0x80
	cli_dbgmsg("Valid Folder Mask - ");
	MALLOC_MESSAGESTORE(item);
	memcpy(&(item->message_store->valid_mask), list->items[x]->data, sizeof(int));
	LE32_CPU(item->message_store->valid_mask);
	cli_dbgmsg("%i\n", item->message_store->valid_mask);
	//INC_CHECK_X();
	break;
      case 0x35E0: // PR_IPM_SUBTREE_ENTRYID Top of Personal Folder Record
	cli_dbgmsg("Top of Personal Folder Record - ");
	MALLOC_MESSAGESTORE(item);
	LIST_COPY(item->message_store->top_of_personal_folder, (pst_entryid*));
	LE32_CPU(item->message_store->top_of_personal_folder->id);
	cli_dbgmsg("[id = %#x]\n", item->message_store->top_of_personal_folder->id);
	//INC_CHECK_X();
	break;
      case 0x35E3: // PR_IPM_WASTEBASKET_ENTRYID Deleted Items Folder Record
	cli_dbgmsg("Deleted Items Folder record - ");
	MALLOC_MESSAGESTORE(item);
	LIST_COPY(item->message_store->deleted_items_folder, (pst_entryid*));
	LE32_CPU(item->message_store->deleted_items_folder->id);
	cli_dbgmsg("[id = %#x]\n", item->message_store->deleted_items_folder->id);
	//INC_CHECK_X();
	break;
      case 0x35E7: // PR_FINDER_ENTRYID Search Root Record
	cli_dbgmsg("Search Root record - ");
	MALLOC_MESSAGESTORE(item);
	LIST_COPY(item->message_store->search_root_folder, (pst_entryid*));
	LE32_CPU(item->message_store->search_root_folder->id);
	cli_dbgmsg("[id = %#x]\n", item->message_store->search_root_folder->id);
	//INC_CHECK_X();
	break;
      case 0x3602: // PR_CONTENT_COUNT Number of emails stored in a folder
	cli_dbgmsg("Folder Email Count - ");
	MALLOC_FOLDER(item);
	memcpy(&(item->folder->email_count), list->items[x]->data, sizeof(item->folder->email_count));
	LE32_CPU(item->folder->email_count);
	cli_dbgmsg("%i\n", item->folder->email_count);
	//INC_CHECK_X();
	break;
      case 0x3603: // PR_CONTENT_UNREAD Number of unread emails
	cli_dbgmsg("Unread Email Count - ");
	MALLOC_FOLDER(item);
	memcpy(&(item->folder->unseen_email_count), list->items[x]->data, sizeof(item->folder->unseen_email_count));
	LE32_CPU(item->folder->unseen_email_count);
	cli_dbgmsg("%i\n", item->folder->unseen_email_count);
	//INC_CHECK_X();
	break;
      case 0x360A: // PR_SUBFOLDERS Has children
	cli_dbgmsg("Has Subfolders - ");
	MALLOC_FOLDER(item);
	if (*((int32_t*)list->items[x]->data) != 0) {
	  cli_dbgmsg("True\n");
	  item->folder->subfolder = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->folder->subfolder = 0;
	}
	//INC_CHECK_X();
	break;
      case 0x3613: // PR_CONTAINER_CLASS IPF.x
	cli_dbgmsg("IPF.x - ");
	LIST_COPY(item->ascii_type, (char*));
	if (strncmp("IPF.Note", item->ascii_type, 8) == 0)
	  item->type = PST_TYPE_NOTE;
	else if (strncmp("IPF.Contact", item->ascii_type, 11) == 0)
	  item->type = PST_TYPE_CONTACT;
	else if (strncmp("IPF.Journal", item->ascii_type, 11) == 0)
	  item->type = PST_TYPE_JOURNAL;
	else if (strncmp("IPF.Appointment", item->ascii_type, 15) == 0)
	  item->type = PST_TYPE_APPOINTMENT;
	else if (strncmp("IPF.StickyNote", item->ascii_type, 14) == 0)
	  item->type = PST_TYPE_STICKYNOTE;
	else if (strncmp("IPF.Task", item->ascii_type, 8) == 0)
	  item->type = PST_TYPE_TASK;
	else
	  item->type = PST_TYPE_OTHER;

	cli_dbgmsg("%s [%i]\n", item->ascii_type, item->type);
	//INC_CHECK_X();
	break;
      case 0x3617: // PR_ASSOC_CONTENT_COUNT
	// associated content are items that are attached to this folder
	// but are hidden from users
	cli_dbgmsg("Associate Content count - ");
	MALLOC_FOLDER(item);
	memcpy(&(item->folder->assoc_count), list->items[x]->data, sizeof(item->folder->assoc_count));
	LE32_CPU(item->folder->assoc_count);
	cli_dbgmsg("%i [%#x]\n", item->folder->assoc_count, item->folder->assoc_count);
	//INC_CHECK_X();
	break;
      case 0x3701: // PR_ATTACH_DATA_OBJ binary data of attachment
	cli_dbgmsg("Binary Data [Size %i] - ",
		    list->items[x]->size);
	NULL_CHECK(attach);
	MOVE_NEXT(attach);
	if (list->items[x]->data == NULL) { //special case
	  attach->id2_val = list->items[x]->type;
	  cli_dbgmsg("Seen a Reference. The data hasn't been loaded yet. [%#x][%#x]\n",
		       attach->id2_val, list->items[x]->type);
	} else {
	  LIST_COPY(attach->data, (char*));
	  attach->size = list->items[x]->size;
	  cli_dbgmsg("NOT PRINTED\n");
	}
	//INC_CHECK_X();
	break;
      case 0x3704: // PR_ATTACH_FILENAME Attachment filename (8.3)
	cli_dbgmsg("Attachment Filename - ");
	NULL_CHECK(attach);
	MOVE_NEXT(attach);
	LIST_COPY(attach->filename1, (char*));
	cli_dbgmsg("%s\n", attach->filename1);
	//INC_CHECK_X();
	break;
      case 0x3705: // PR_ATTACH_METHOD
	// 0 - No Attachment
	// 1 - Attach by Value
	// 2 - Attach by reference
	// 3 - Attach by ref resolve
	// 4 - Attach by ref only
	// 5 - Embedded Message
	// 6 - OLE
	cli_dbgmsg("Attachement method - ");
	NULL_CHECK(attach);
	MOVE_NEXT(attach);
	memcpy(&(attach->method), list->items[x]->data, sizeof(attach->method));
	LE32_CPU(attach->method);
	t = attach->method;
	//INC_CHECK_X();
	break;
      case 0x370B: // PR_RENDERING_POSITION
	// position in characters that the attachment appears in the plain text body
	cli_dbgmsg("Attachment Position - ");
	NULL_CHECK(attach);
	MOVE_NEXT(attach);
	memcpy(&(attach->position), list->items[x]->data, sizeof(attach->position));
	LE32_CPU(attach->position);
	cli_dbgmsg("%i [%#x]\n", attach->position);
	//INC_CHECK_X();
	break;
      case 0x3707: // PR_ATTACH_LONG_FILENAME Attachment filename (long?)
	cli_dbgmsg("Attachment Filename long - ");
	NULL_CHECK(attach);
	MOVE_NEXT(attach);
	LIST_COPY(attach->filename2, (char*));
	cli_dbgmsg("%s\n", attach->filename2);
	//INC_CHECK_X();
	break;
      case 0x370E: // PR_ATTACH_MIME_TAG Mime type of encoding
	cli_dbgmsg("Attachment mime encoding - ");
	NULL_CHECK(attach);
	MOVE_NEXT(attach);
	LIST_COPY(attach->mimetype, (char*));
	cli_dbgmsg("%s\n", attach->mimetype);
	//INC_CHECK_X();
	break;
      case 0x3710: // PR_ATTACH_MIME_SEQUENCE
	// sequence number for mime parts. Includes body
	cli_dbgmsg("Attachment Mime Sequence - ");
	NULL_CHECK(attach);
	MOVE_NEXT(attach);
	memcpy(&(attach->sequence), list->items[x]->data, sizeof(attach->sequence));
	LE32_CPU(attach->sequence);
	cli_dbgmsg("%i\n", attach->sequence);
	//INC_CHECK_X();
	break;
      case 0x3A00: // PR_ACCOUNT
	cli_dbgmsg("Contact's Account name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->account_name, (char*));
	cli_dbgmsg("%s\n", item->contact->account_name);
	break;
      case 0x3A01: // PR_ALTERNATE_RECIPIENT
	cli_dbgmsg("Contact Alternate Recipient - NOT PROCESSED\n");
	break;
      case 0x3A02: // PR_CALLBACK_TELEPHONE_NUMBER
	cli_dbgmsg("Callback telephone number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->callback_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->callback_phone);
	break;
      case 0x3A03: // PR_CONVERSION_PROHIBITED
	cli_dbgmsg("Message Conversion Prohibited - ");
	MALLOC_EMAIL(item);
	if (*(int16_t*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->email->conversion_prohib = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->email->conversion_prohib = 0;
	}
	break;
      case 0x3A05: // PR_GENERATION suffix
	cli_dbgmsg("Contacts Suffix - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->suffix, (char*));
	cli_dbgmsg("%s\n", item->contact->suffix);
	break;
      case 0x3A06: // PR_GIVEN_NAME Contact's first name
	cli_dbgmsg("Contacts First Name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->first_name, (char*));
	cli_dbgmsg("%s\n", item->contact->first_name);
	//INC_CHECK_X();
	break;
      case 0x3A07: // PR_GOVERNMENT_ID_NUMBER
	cli_dbgmsg("Contacts Government ID Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->gov_id, (char*));
	cli_dbgmsg("%s\n", item->contact->gov_id);
	break;
      case 0x3A08: // PR_BUSINESS_TELEPHONE_NUMBER
	cli_dbgmsg("Business Telephone Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->business_phone);
	break;
      case 0x3A09: // PR_HOME_TELEPHONE_NUMBER
	cli_dbgmsg("Home Telephone Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->home_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->home_phone);
	break;
      case 0x3A0A: // PR_INITIALS Contact's Initials
	cli_dbgmsg("Contacts Initials - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->initials, (char*));
	cli_dbgmsg("%s\n", item->contact->initials);
	//INC_CHECK_X();
	break;
      case 0x3A0B: // PR_KEYWORD
	cli_dbgmsg("Keyword - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->keyword, (char*));
	cli_dbgmsg("%s\n", item->contact->keyword);
	break;
      case 0x3A0C: // PR_LANGUAGE
	cli_dbgmsg("Contact's Language - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->language, (char*));
	cli_dbgmsg("%s\n", item->contact->language);
	break;
      case 0x3A0D: // PR_LOCATION
	cli_dbgmsg("Contact's Location - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->location, (char*));
	cli_dbgmsg("%s\n", item->contact->location);
	break;
      case 0x3A0E: // PR_MAIL_PERMISSION - Can the recipient receive and send email
	cli_dbgmsg("Mail Permission - ");
	MALLOC_CONTACT(item);
	if (*(int16_t*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->contact->mail_permission = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->contact->mail_permission = 0;
	}
	break;
      case 0x3A0F: // PR_MHS_COMMON_NAME
	cli_dbgmsg("MHS Common Name - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->common_name, (char*));
	cli_dbgmsg("%s\n", item->email->common_name);
	break;
      case 0x3A10: // PR_ORGANIZATIONAL_ID_NUMBER
	cli_dbgmsg("Organizational ID # - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->org_id, (char*));
	cli_dbgmsg("%s\n", item->contact->org_id);
	break;
      case 0x3A11: // PR_SURNAME Contact's Surname
	cli_dbgmsg("Contacts Surname - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->surname, (char*));
	cli_dbgmsg("%s\n", item->contact->surname);
	//INC_CHECK_X();
	break;
      case 0x3A12: // PR_ORIGINAL_ENTRY_ID
	cli_dbgmsg("Original Entry ID - NOT PROCESSED\n");
	break;
      case 0x3A13: // PR_ORIGINAL_DISPLAY_NAME
	cli_dbgmsg("Original Display Name - NOT PROCESSED\n");
	break;
      case 0x3A14: // PR_ORIGINAL_SEARCH_KEY
	cli_dbgmsg("Original Search Key - NOT PROCESSED\n");
	break;
      case 0x3A15: // PR_POSTAL_ADDRESS
	cli_dbgmsg("Default Postal Address - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->def_postal_address, (char*));
	cli_dbgmsg("%s\n", item->contact->def_postal_address);
	break;
      case 0x3A16: // PR_COMPANY_NAME
	cli_dbgmsg("Company Name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->company_name, (char*));
	cli_dbgmsg("%s\n", item->contact->company_name);
	break;
      case 0x3A17: // PR_TITLE - Job Title
	cli_dbgmsg("Job Title - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->job_title, (char*));
	cli_dbgmsg("%s\n", item->contact->job_title);
	break;
      case 0x3A18: // PR_DEPARTMENT_NAME
	cli_dbgmsg("Department Name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->department, (char*));
	cli_dbgmsg("%s\n", item->contact->department);
	break;
      case 0x3A19: // PR_OFFICE_LOCATION
	cli_dbgmsg("Office Location - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->office_loc, (char*));
	cli_dbgmsg("%s\n", item->contact->office_loc);
	break;
      case 0x3A1A: // PR_PRIMARY_TELEPHONE_NUMBER
	cli_dbgmsg("Primary Telephone - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->primary_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->primary_phone);
	break;
      case 0x3A1B: // PR_BUSINESS2_TELEPHONE_NUMBER
	cli_dbgmsg("Business Phone Number 2 - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_phone2, (char*));
	cli_dbgmsg("%s\n", item->contact->business_phone2);
	break;
      case 0x3A1C: // PR_MOBILE_TELEPHONE_NUMBER
	cli_dbgmsg("Mobile Phone Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->mobile_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->mobile_phone);
	break;
      case 0x3A1D: // PR_RADIO_TELEPHONE_NUMBER
	cli_dbgmsg("Radio Phone Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->radio_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->radio_phone);
	break;
      case 0x3A1E: // PR_CAR_TELEPHONE_NUMBER
	cli_dbgmsg("Car Phone Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->car_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->car_phone);
	break;
      case 0x3A1F: // PR_OTHER_TELEPHONE_NUMBER
	cli_dbgmsg("Other Phone Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->other_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->other_phone);
	break;
      case 0x3A20: // PR_TRANSMITTABLE_DISPLAY_NAME
	cli_dbgmsg("Transmittable Display Name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->transmittable_display_name, (char*));
	cli_dbgmsg("%s\n", item->contact->transmittable_display_name);
	break;
      case 0x3A21: // PR_PAGER_TELEPHONE_NUMBER
	cli_dbgmsg("Pager Phone Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->pager_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->pager_phone);
	break;
      case 0x3A22: // PR_USER_CERTIFICATE
	cli_dbgmsg("User Certificate - NOT PROCESSED");
	break;
      case 0x3A23: // PR_PRIMARY_FAX_NUMBER
	cli_dbgmsg("Primary Fax Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->primary_fax, (char*));
	cli_dbgmsg("%s\n", item->contact->primary_fax);
	break;
      case 0x3A24: // PR_BUSINESS_FAX_NUMBER
	cli_dbgmsg("Business Fax Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_fax, (char*));
	cli_dbgmsg("%s\n", item->contact->business_fax);
	break;
      case 0x3A25: // PR_HOME_FAX_NUMBER
	cli_dbgmsg("Home Fax Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->home_fax, (char*));
	cli_dbgmsg("%s\n", item->contact->home_fax);
	break;
      case 0x3A26: // PR_BUSINESS_ADDRESS_COUNTRY
	cli_dbgmsg("Business Address Country - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_country, (char*));
	cli_dbgmsg("%s\n", item->contact->business_country);
	break;
      case 0x3A27: // PR_BUSINESS_ADDRESS_CITY
	cli_dbgmsg("Business Address City - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_city, (char*));
	cli_dbgmsg("%s\n", item->contact->business_city);
	break;
      case 0x3A28: // PR_BUSINESS_ADDRESS_STATE_OR_PROVINCE
	cli_dbgmsg("Business Address State - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_state, (char*));
	cli_dbgmsg("%s\n", item->contact->business_state);
	break;
      case 0x3A29: // PR_BUSINESS_ADDRESS_STREET
	cli_dbgmsg("Business Address Street - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_street, (char*));
	cli_dbgmsg("%s\n", item->contact->business_street);
	break;
      case 0x3A2A: // PR_BUSINESS_POSTAL_CODE
	cli_dbgmsg("Business Postal Code - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_postal_code, (char*));
	cli_dbgmsg("%s\n", item->contact->business_postal_code);
	break;
      case 0x3A2B: // PR_BUSINESS_PO_BOX
	cli_dbgmsg("Business PO Box - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_po_box, (char*));
	cli_dbgmsg("%s\n", item->contact->business_po_box);
	break;
      case 0x3A2C: // PR_TELEX_NUMBER
	cli_dbgmsg("Telex Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->telex, (char*));
	cli_dbgmsg("%s\n", item->contact->telex);
	break;
      case 0x3A2D: // PR_ISDN_NUMBER
	cli_dbgmsg("ISDN Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->isdn_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->isdn_phone);
	break;
      case 0x3A2E: // PR_ASSISTANT_TELEPHONE_NUMBER
	cli_dbgmsg("Assistant Phone Number - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->assistant_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->assistant_phone);
	break;
      case 0x3A2F: // PR_HOME2_TELEPHONE_NUMBER
	cli_dbgmsg("Home Phone 2 - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->home_phone2, (char*));
	cli_dbgmsg("%s\n", item->contact->home_phone2);
	break;
      case 0x3A30: // PR_ASSISTANT
	cli_dbgmsg("Assistant's Name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->assistant_name, (char*));
	cli_dbgmsg("%s\n", item->contact->assistant_name);
	break;
      case 0x3A40: // PR_SEND_RICH_INFO
	cli_dbgmsg("Can receive Rich Text - ");
	MALLOC_CONTACT(item);
	if(*(int16_t*)list->items[x]->data != 0) {
	  cli_dbgmsg("True\n");
	  item->contact->rich_text = 1;
	} else {
	  cli_dbgmsg("False\n");
	  item->contact->rich_text = 0;
	}
	break;
      case 0x3A41: // PR_WEDDING_ANNIVERSARY
	cli_dbgmsg("Wedding Anniversary - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->wedding_anniversary, (FILETIME*));
	break;
      case 0x3A42: // PR_BIRTHDAY
	cli_dbgmsg("Birthday - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->birthday, (FILETIME*));
	break;
      case 0x3A43: // PR_HOBBIES
	cli_dbgmsg("Hobbies - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->hobbies, (char*));
	cli_dbgmsg("%s\n", item->contact->hobbies);
	break;
      case 0x3A44: // PR_MIDDLE_NAME
	cli_dbgmsg("Middle Name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->middle_name, (char*));
	cli_dbgmsg("%s\n", item->contact->middle_name);
	break;
      case 0x3A45: // PR_DISPLAY_NAME_PREFIX
	cli_dbgmsg("Title) - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->display_name_prefix, (char*));
	cli_dbgmsg("%s\n", item->contact->display_name_prefix);
	break;
      case 0x3A46: // PR_PROFESSION
	cli_dbgmsg("Profession - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->profession, (char*));
	cli_dbgmsg("%s\n", item->contact->profession);
	break;
      case 0x3A47: // PR_PREFERRED_BY_NAME
	cli_dbgmsg("Preferred By Name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->pref_name, (char*));
	cli_dbgmsg("%s\n", item->contact->pref_name);
	break;
      case 0x3A48: // PR_SPOUSE_NAME
	cli_dbgmsg("Spouse's Name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->spouse_name, (char*));
	cli_dbgmsg("%s\n", item->contact->spouse_name);
	break;
      case 0x3A49: // PR_COMPUTER_NETWORK_NAME
	cli_dbgmsg("Computer Network Name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->computer_name, (char*));
	cli_dbgmsg("%s\n", item->contact->computer_name);
	break;
      case 0x3A4A: // PR_CUSTOMER_ID
	cli_dbgmsg("Customer ID - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->customer_id, (char*));
	cli_dbgmsg("%s\n", item->contact->customer_id);
	break;
      case 0x3A4B: // PR_TTYTDD_PHONE_NUMBER
	cli_dbgmsg("TTY/TDD Phone - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->ttytdd_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->ttytdd_phone);
	break;
      case 0x3A4C: // PR_FTP_SITE
	cli_dbgmsg("Ftp Site - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->ftp_site, (char*));
	cli_dbgmsg("%s\n", item->contact->ftp_site);
	break;
      case 0x3A4D: // PR_GENDER
	cli_dbgmsg("Gender - ");
	MALLOC_CONTACT(item);
	memcpy(&item->contact->gender, list->items[x]->data, sizeof(int16_t));
	LE16_CPU(item->contact->gender);
	switch(item->contact->gender) {
	case 0:
	  cli_dbgmsg("Unspecified\n");
	  break;
	case 1:
	  cli_dbgmsg("Female\n");
	  break;
	case 2:
	  cli_dbgmsg("Male\n");
	  break;
	default:
	  cli_dbgmsg("Error processing\n");
	}
	break;
      case 0x3A4E: // PR_MANAGER_NAME
	cli_dbgmsg("Manager's Name - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->manager_name, (char*));
	cli_dbgmsg("%s\n", item->contact->manager_name);
	break;
      case 0x3A4F: // PR_NICKNAME
	cli_dbgmsg("Nickname - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->nickname, (char*));
	cli_dbgmsg("%s\n", item->contact->nickname);
	break;
      case 0x3A50: // PR_PERSONAL_HOME_PAGE
	cli_dbgmsg("Personal Home Page - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->personal_homepage, (char*));
	cli_dbgmsg("%s\n", item->contact->personal_homepage);
	break;
      case 0x3A51: // PR_BUSINESS_HOME_PAGE
	cli_dbgmsg("Business Home Page - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_homepage, (char*));
	cli_dbgmsg("%s\n", item->contact->business_homepage);
	break;
      case 0x3A57: // PR_COMPANY_MAIN_PHONE_NUMBER
	cli_dbgmsg("Company Main Phone - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->company_main_phone, (char*));
	cli_dbgmsg("%s\n", item->contact->company_main_phone);
	break;
      case 0x3A58: // PR_CHILDRENS_NAMES
	cli_dbgmsg("Children's Names - NOT PROCESSED\n");
	break;
      case 0x3A59: // PR_HOME_ADDRESS_CITY
	cli_dbgmsg("Home Address City - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->home_city, (char*));
	cli_dbgmsg("%s\n", item->contact->home_city);
	break;
      case 0x3A5A: // PR_HOME_ADDRESS_COUNTRY
	cli_dbgmsg("Home Address Country - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->home_country, (char*));
	cli_dbgmsg("%s\n", item->contact->home_country);
	break;
      case 0x3A5B: // PR_HOME_ADDRESS_POSTAL_CODE
	cli_dbgmsg("Home Address Postal Code - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->home_postal_code, (char*));
	cli_dbgmsg("%s\n", item->contact->home_postal_code);
	break;
      case 0x3A5C: // PR_HOME_ADDRESS_STATE_OR_PROVINCE
	cli_dbgmsg("Home Address State or Province - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->home_state, (char*));
	cli_dbgmsg("%s\n", item->contact->home_state);
	break;
      case 0x3A5D: // PR_HOME_ADDRESS_STREET
	cli_dbgmsg("Home Address Street - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->home_street, (char*));
	cli_dbgmsg("%s\n", item->contact->home_street);
	break;
      case 0x3A5E: // PR_HOME_ADDRESS_POST_OFFICE_BOX
	cli_dbgmsg("Home Address Post Office Box - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->home_po_box, (char*));
	cli_dbgmsg("%s\n", item->contact->home_po_box);
	break;
      case 0x3A5F: // PR_OTHER_ADDRESS_CITY
	cli_dbgmsg("Other Address City - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->other_city, (char*));
	cli_dbgmsg("%s\n", item->contact->other_city);
	break;
      case 0x3A60: // PR_OTHER_ADDRESS_COUNTRY
	cli_dbgmsg("Other Address Country - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->other_country, (char*));
	cli_dbgmsg("%s\n", item->contact->other_country);
	break;
      case 0x3A61: // PR_OTHER_ADDRESS_POSTAL_CODE
	cli_dbgmsg("Other Address Postal Code - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->other_postal_code, (char*));
	cli_dbgmsg("%s\n", item->contact->other_postal_code);
	break;
      case 0x3A62: // PR_OTHER_ADDRESS_STATE_OR_PROVINCE
	cli_dbgmsg("Other Address State - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->other_state, (char*));
	cli_dbgmsg("%s\n", item->contact->other_state);
	break;
      case 0x3A63: // PR_OTHER_ADDRESS_STREET
	cli_dbgmsg("Other Address Street - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->other_street, (char*));
	cli_dbgmsg("%s\n", item->contact->other_street);
	break;
      case 0x3A64: // PR_OTHER_ADDRESS_POST_OFFICE_BOX
	cli_dbgmsg("Other Address Post Office box - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->other_po_box, (char*));
	cli_dbgmsg("%s\n", item->contact->other_po_box);
	break;
      case 0x65E3: // Entry ID?
	cli_dbgmsg("Entry ID - ");
	item->record_key = (char*) cli_malloc(16+1);
	memcpy(item->record_key, &(list->items[x]->data[1]), 16); //skip first byte
	item->record_key[16]='\0';
	item->record_key_size=16;
	//INC_CHECK_X();
	break;
      case 0x67F2: // ID2 value of the attachments proper record
	cli_dbgmsg("Attachment ID2 value - ");
	if (attach != NULL){
	  MOVE_NEXT(attach);
	  memcpy(&(attach->id2_val), list->items[x]->data, sizeof(attach->id2_val));
	  LE32_CPU(attach->id2_val);
	  cli_dbgmsg("%#x\n", attach->id2_val);
	} else {
	  cli_dbgmsg("NOT AN ATTACHMENT: %#x\n", list->items[x]->id);
	}
	//INC_CHECK_X();
	break;
      case 0x67FF: // Extra Property Identifier (Password CheckSum)
	cli_dbgmsg("Password checksum [0x67FF] - ");
	MALLOC_MESSAGESTORE(item);
	memcpy(&(item->message_store->pwd_chksum), list->items[x]->data,
	       sizeof(item->message_store->pwd_chksum));
	cli_dbgmsg("%#x\n", item->message_store->pwd_chksum);
	//INC_CHECK_X();
	break;
      case 0x6F02: // Secure HTML Body
	cli_dbgmsg("Secure HTML Body - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->encrypted_htmlbody, (char*));
	item->email->encrypted_htmlbody_size = list->items[x]->size;
	cli_dbgmsg("Not Printed\n");
	//INC_CHECK_X();
	break;
      case 0x6F04: // Secure Text Body
	cli_dbgmsg("Secure Text Body - ");
	MALLOC_EMAIL(item);
	LIST_COPY(item->email->encrypted_body, (char*));
	item->email->encrypted_body_size = list->items[x]->size;
	cli_dbgmsg("Not Printed\n");
	//INC_CHECK_X();
	break;
      case 0x7C07: // top of folders ENTRYID
	cli_dbgmsg("Top of folders RecID [0x7c07] - ");
	MALLOC_MESSAGESTORE(item);
	item->message_store->top_of_folder = (pst_entryid*) cli_malloc(sizeof(pst_entryid));
	memcpy(item->message_store->top_of_folder, list->items[x]->data, sizeof(pst_entryid));
	LE32_CPU(item->message_store->top_of_folder->u1);
	LE32_CPU(item->message_store->top_of_folder->id);
	//INC_CHECK_X();
	break;
      case 0x8005: // Contact's Fullname
	cli_dbgmsg("Contact Fullname - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->fullname, (char*));
	cli_dbgmsg("%s\n", item->contact->fullname);
	break;
      case 0x801A: // Full Home Address
	cli_dbgmsg("Home Address - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->home_address, (char*));
	cli_dbgmsg("%s\n", item->contact->home_address);
	break;
      case 0x801B: // Full Business Address
	cli_dbgmsg("Business Address - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->business_address, (char*));
	cli_dbgmsg("%s\n", item->contact->business_address);
	break;
      case 0x801C: // Full Other Address
	cli_dbgmsg("Other Address - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->other_address, (char*));
	cli_dbgmsg("%s\n", item->contact->other_address);
	break;
      case 0x8082: // Email Address 1 Transport
	cli_dbgmsg("Email Address 1 Transport - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address1_transport, (char*));
	cli_dbgmsg("%s\n", item->contact->address1_transport);
	break;
      case 0x8083: // Email Address 1 Address
	cli_dbgmsg("Email Address 1 Address - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address1, (char*));
	cli_dbgmsg("%s\n", item->contact->address1);
	break;
      case 0x8084: // Email Address 1 Description
	cli_dbgmsg("Email Address 1 Description - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address1_desc, (char*));
	cli_dbgmsg("%s\n", item->contact->address1_desc);
	break;
      case 0x8085: // Email Address 1 Record
	cli_dbgmsg("Email Address 1 Record - NOT PROCESSED\n");
	break;
      case 0x8092: // Email Address 2 Transport
	cli_dbgmsg("Email Address 2 Transport - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address2_transport, (char*));
	cli_dbgmsg("%s\n", item->contact->address2_transport);
	break;
      case 0x8093: // Email Address 2 Address
	cli_dbgmsg("Email Address 2 Address - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address2, (char*));
	cli_dbgmsg("%s\n", item->contact->address2);
	break;
      case 0x8094: // Email Address 2 Description
	cli_dbgmsg("Email Address 2 Description - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address2_desc, (char*));
	cli_dbgmsg("%s\n", item->contact->address2_desc);
	break;
      case 0x8095: // Email Address 2 Record
	cli_dbgmsg("Email Address 2 Record - NOT PROCESSED\n");
	break;
      case 0x80A2: // Email Address 3 Transport
	cli_dbgmsg("Email Address 3 Transport - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address3_transport, (char*));
	cli_dbgmsg("%s\n", item->contact->address3_transport);
	break;
      case 0x80A3: // Email Address 3 Address
	cli_dbgmsg("Email Address 3 Address - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address3, (char*));
	cli_dbgmsg("%s\n", item->contact->address3);
	break;
      case 0x80A4: // Email Address 3 Description
	cli_dbgmsg("Email Address 3 Description - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->address3_desc, (char*));
	cli_dbgmsg("%s\n", item->contact->address3_desc);
	break;
      case 0x80A5: // Email Address 3 Record
	cli_dbgmsg("Email Address 3 Record - NOT PROCESSED\n");
	break;
      case 0x80D8: // Internet Free/Busy
	cli_dbgmsg("Internet Free/Busy - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->free_busy_address, (char*));
	cli_dbgmsg("%s\n", item->contact->free_busy_address);
	break;
      case 0x8205: // Show on Free/Busy as
	// 0: Free
	// 1: Tentative
	// 2: Busy
	// 3: Out Of Office
	cli_dbgmsg("Appointment shows as - ");
	MALLOC_APPOINTMENT(item);
	memcpy(&(item->appointment->showas), list->items[x]->data, sizeof(item->appointment->showas));
	LE32_CPU(item->appointment->showas);
	switch (item->appointment->showas) {
	case PST_FREEBUSY_FREE:
	  cli_dbgmsg("Free\n"); break;
	case PST_FREEBUSY_TENTATIVE:
	  cli_dbgmsg("Tentative\n"); break;
	case PST_FREEBUSY_BUSY:
	  cli_dbgmsg("Busy\n"); break;
	case PST_FREEBUSY_OUT_OF_OFFICE:
	  cli_dbgmsg("Out Of Office\n"); break;
	default:
	  cli_dbgmsg("Unknown Value: %d\n", item->appointment->showas); break;
	}
	break;
      case 0x8208: // Location of an appointment
	cli_dbgmsg("Appointment Location - ");
	MALLOC_APPOINTMENT(item);
	LIST_COPY(item->appointment->location, (char*));
	cli_dbgmsg("%s\n", item->appointment->location);
	break;
      case 0x8214: // Label for an appointment
	cli_dbgmsg("Label for appointment - ");
	MALLOC_APPOINTMENT(item);
	memcpy(&(item->appointment->label), list->items[x]->data, sizeof(item->appointment->label));
	LE32_CPU(item->appointment->label);
	switch (item->appointment->label) {
	case PST_APP_LABEL_NONE:
	  cli_dbgmsg("None\n"); break;
	case PST_APP_LABEL_IMPORTANT:
	  cli_dbgmsg("Important\n"); break;
	case PST_APP_LABEL_BUSINESS:
	  cli_dbgmsg("Business\n"); break;
	case PST_APP_LABEL_PERSONAL:
	  cli_dbgmsg("Personal\n"); break;
	case PST_APP_LABEL_VACATION:
	  cli_dbgmsg("Vacation\n"); break;
	case PST_APP_LABEL_MUST_ATTEND:
	  cli_dbgmsg("Must Attend\n"); break;
	case PST_APP_LABEL_TRAVEL_REQ:
	  cli_dbgmsg("Travel Required\n"); break;
	case PST_APP_LABEL_NEEDS_PREP:
	  cli_dbgmsg("Needs Preparation\n"); break;
	case PST_APP_LABEL_BIRTHDAY:
	  cli_dbgmsg("Birthday\n"); break;
	case PST_APP_LABEL_ANNIVERSARY:
	  cli_dbgmsg("Anniversary\n"); break;
	case PST_APP_LABEL_PHONE_CALL:
	  cli_dbgmsg("Phone Call\n"); break;
	}
	break;
      case 0x8234: // TimeZone as String
	cli_dbgmsg("TimeZone of times - ");
	MALLOC_APPOINTMENT(item);
	LIST_COPY(item->appointment->timezonestring, (char*));
	cli_dbgmsg("%s\n", item->appointment->timezonestring);
	break;
      case 0x8235: // Appointment start time
	cli_dbgmsg("Appointment Start Time - ");
	MALLOC_APPOINTMENT(item);
	LIST_COPY(item->appointment->start, (FILETIME*));
	break;
      case 0x8236: // Appointment end time
	cli_dbgmsg("Appointment End Time - ");
	MALLOC_APPOINTMENT(item);
	LIST_COPY(item->appointment->end, (FILETIME*));
	break;
      case 0x8516: // Journal time start
	cli_dbgmsg("Duplicate Time Start - ");
	break;
      case 0x8517: // Journal time end
	cli_dbgmsg("Duplicate Time End - ");
	break;
      case 0x8530: // Followup
	cli_dbgmsg("Followup String - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->followup, (char*));
	cli_dbgmsg("%s\n", item->contact->followup);
	break;
      case 0x8534: // Mileage
	cli_dbgmsg("Mileage - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->mileage, (char*));
	cli_dbgmsg("%s\n", item->contact->mileage);
	break;
      case 0x8535: // Billing Information
	cli_dbgmsg("Billing Information - ");
	MALLOC_CONTACT(item);
	LIST_COPY(item->contact->billing_information, (char*));
	cli_dbgmsg("%s\n", item->contact->billing_information);
	break;
      case 0x8554: // Outlook Version
	cli_dbgmsg("Outlook Version - ");
	LIST_COPY(item->outlook_version, (char*));
	cli_dbgmsg("%s\n", item->outlook_version);
	break;
      case 0x8560: // Appointment Reminder Time
	cli_dbgmsg("Appointment Reminder Time - ");
	MALLOC_APPOINTMENT(item);
	LIST_COPY(item->appointment->reminder, (FILETIME*));
	break;
      case 0x8700: // Journal Type
	cli_dbgmsg("Journal Entry Type - ");
	MALLOC_JOURNAL(item);
	LIST_COPY(item->journal->type, (char*));
	cli_dbgmsg("%s\n", item->journal->type);
	break;
      case 0x8706: // Journal Start date/time
	cli_dbgmsg("Start Timestamp - ");
	MALLOC_JOURNAL(item);
	LIST_COPY(item->journal->start, (FILETIME*));
	break;
      case 0x8708: // Journal End date/time
	cli_dbgmsg("End Timestamp - ");
	MALLOC_JOURNAL(item);
	LIST_COPY(item->journal->end, (FILETIME*));
	break;
      case 0x8712: // Title?
	cli_dbgmsg("Journal Entry Type - ");
	MALLOC_JOURNAL(item);
	LIST_COPY(item->journal->type, (char*));
	cli_dbgmsg("%s\n", item->journal->type);
	break;
      default:
      /* Reference Types

	 2 - 0x0002 - Signed 16bit value
	 3 - 0x0003 - Signed 32bit value
	11 - 0x000B - Boolean (non-zero = true)
	13 - 0x000D - Embedded Object
	30 - 0x001E - Null terminated String
	31 - 0x001F - Unicode string
	64 - 0x0040 - Systime - Filetime structure
	72 - 0x0048 - OLE Guid
       258 - 0x0102 - Binary data

	   - 0x1003 - Array of 32bit values
	   - 0x101E - Array of Strings
	   - 0x1102 - Array of Binary data
      */
	//	cli_dbgmsg("Unknown id [%#x, size=%#x]\n", list->items[x]->id, list->items[x]->size);
	if (list->items[x]->type == 0x02) {
	  /*cli_dbgmsg(int16_t*)list->items[x]->data)*/;
	} else if (list->items[x]->type == 0x03) {
		/*cli_dbgmsg(int32_t*)list->items[x]->data)*/;
	} else if (list->items[x]->type == 0x0b) {
	  cli_dbgmsg("Unknown 16bit boolean = %s [%hi]\n",
		       (*((int16_t*)list->items[x]->data)!=0?"True":"False"),
		       *((int16_t*)list->items[x]->data));
	} else if (list->items[x]->type == 0x1e) {
	  cli_dbgmsg("Unknown String Data = \"%s\" [%#x]\n",
		      list->items[x]->data, list->items[x]->type);
	} else if (list->items[x]->type == 0x40) {
	  cli_dbgmsg("Unknown Date = \"%s\" [%#x]\n",
		      fileTimeToAscii((FILETIME*)list->items[x]->data),
		      list->items[x]->type);
	} else if (list->items[x]->type == 0x102) {
	  cli_dbgmsg("Unknown Binary Data [size = %#x]\n",
		       list->items[x]->size);
	} else if (list->items[x]->type == 0x101E) {
	  cli_dbgmsg("Unknown Array of Strings [%#x]\n",
		      list->items[x]->type);
	} else {
	  cli_dbgmsg("Unknown Not Printable [%#x]\n",
		      list->items[x]->type);
	}
	if (list->items[x]->data != NULL) {
	  free(list->items[x]->data);
	  list->items[x]->data = NULL;
	}
	//INC_CHECK_X();
      }
      x++;
    }
    x = 0;
    list = list->next;
    next = 1;
  }
  return 0;
}

int32_t _pst_free_list(pst_num_array *list) {
  int32_t x = 0;
  pst_num_array *l;
  while (list != NULL) {
    while (x < list->count_item) {
      if (list->items[x]->data != NULL) {
	free (list->items[x]->data);
      }
      if (list->items[x] != NULL) {
	free (list->items[x]);
      }
      x++;
    }
    if (list->items != NULL) {
      free(list->items);
    }
    l = list;
    list = list->next;
    free (l);
    x = 0;
  }
  return 1;
}

int32_t _pst_free_id2(pst_index2_ll * head) {
  pst_index2_ll *t;
  while (head != NULL) {
    t = head->next;
    free (head);
    head = t;
  }
  return 1;
}

int32_t _pst_free_id (pst_index_ll *head) {
  pst_index_ll *t;
  while (head != NULL) {
    t = head->next;
    free(head);
    head = t;
  }
  return 1;
}

int32_t _pst_free_desc (pst_desc_ll *head) {
  pst_desc_ll *t;
  while (head != NULL) {
    while (head->child != NULL) {
      head = head->child;
    }

    // point t to the next item
    t = head->next;
    if (t == NULL && head->parent != NULL) {
      t = head->parent;
      t->child = NULL; // set the child to NULL so we don't come back here again!
    }

    if (head != NULL)
      free(head);
    else {
      cli_errmsg("head is NULL\n");
    }

    head = t;
  }
  return 1;
}

int32_t _pst_free_xattrib(pst_x_attrib_ll *x) {
  pst_x_attrib_ll *t;
  while (x != NULL) {
    if (x->data)
      free(x->data);
    t = x->next;
    free(x);
    x = t;
  }
  return 1;
}

pst_index2_ll *
_pst_build_id2(pst_file *pf, pst_index_ll* list, pst_index2_ll* head_ptr) {
  pst_block_header block_head;
  pst_index2_ll *head = NULL, *tail = NULL;
  int32_t x = 0, b_ptr = 0;
  char *buf = NULL;
  pst_id2_assoc id2_rec;
  pst_index_ll *i_ptr = NULL;
  pst_index2_ll *i2_ptr = NULL;
  if (head_ptr != NULL) {
    head = head_ptr;
    while (head_ptr != NULL)
      head_ptr = (tail = head_ptr)->next;
  }
  if (_pst_read_block_size(pf, list->offset, list->size, &buf, PST_NO_ENC,0) < list->size) {
    //an error occured in block read
    cli_warnmsg("block read error occured. offset = %#x, size = %#x\n", list->offset, list->size);
    if(buf)
    	free(buf);
    return NULL;
  }

  memcpy(&block_head, &(buf[0]), sizeof(block_head));
  LE16_CPU(block_head.type);
  LE16_CPU(block_head.count);

  if (block_head.type != 0x0002) { // some sort of constant?
    cli_warnmsg("Unknown constant [%#x] at start of id2 values [offset %#x].\n", block_head.type, list->offset);
    if(buf)
    	free(buf);
    return NULL;
  }

  x = 0;
  b_ptr = 0x04;
  while (x < block_head.count) {
    memcpy(&id2_rec, &(buf[b_ptr]), sizeof(id2_rec));
    LE32_CPU(id2_rec.id2);
    LE32_CPU(id2_rec.id);
    LE32_CPU(id2_rec.table2);

    b_ptr += sizeof(id2_rec);
    cli_dbgmsg("\tid2 = %#x, id = %#x, table2 = %#x\n", id2_rec.id2, id2_rec.id, id2_rec.table2);
    if ((i_ptr = _pst_getID(pf, id2_rec.id)) == NULL) {
      cli_dbgmsg("\t\t%#x - Not Found\n", id2_rec.id);
    } else {
      // add it to the linked list
      //check it doesn't exist already first
      /*      i2_ptr = head;
      while(i2_ptr != NULL) {
	if (i2_ptr->id2 == id2_rec.id2)
	  break;
	i2_ptr = i2_ptr->next;
	}*/

      //      if (i2_ptr == NULL) {
      i2_ptr = (pst_index2_ll*) cli_malloc(sizeof(pst_index2_ll));
      i2_ptr->id2 = id2_rec.id2;
      i2_ptr->id = i_ptr;
      i2_ptr->next = NULL;
      if (head == NULL)
	head = i2_ptr;
      if (tail != NULL)
	tail->next = i2_ptr;
      tail = i2_ptr;
      /*    } else {
	// if it does already exist
	cli_dbgmsg(): \t\t%#x already exists. Updating ID to %#x\n",
		     id2_rec.id2, i_ptr->id));
	i2_ptr->id = i_ptr;
	}*/
      if (id2_rec.table2 != 0) {
	if ((i_ptr = _pst_getID(pf, id2_rec.table2)) == NULL) {
	  cli_dbgmsg("\tTable2 [%#x] not found\n", id2_rec.table2);
	} else {
	  cli_dbgmsg("\tGoing deeper for table2 [%#x]\n", id2_rec.table2);
	  if ((i2_ptr = _pst_build_id2(pf, i_ptr, head)) != NULL) {
	    /*cli_dbgmsg(): \t\tAdding new list onto end of current\n");
	    if (head == NULL)
	      head = i2_ptr;
	    if (tail != NULL)
	      tail->next = i2_ptr;
	    while (i2_ptr->next != NULL)
	      i2_ptr = i2_ptr->next;
	      tail = i2_ptr;*/
	  }
	  // need to re-establish tail
	  cli_dbgmsg("Returned from depth\n");
	  if (tail != NULL) {
	    while (tail->next != NULL)
	      tail = tail->next;
	  }
	}
      }
    }
    x++;
  }
  if (buf != NULL) {
    free (buf);
  }
  return head;
}

// This version of free does NULL check first
#define SAFE_FREE(x) {if (x != NULL) free(x);}

void _pst_freeItem(pst_item *item) {
  pst_item_attach *t;
  pst_item_extra_field *et;

  if (item != NULL) {
    if (item->email) {
      SAFE_FREE(item->email->arrival_date);
      SAFE_FREE(item->email->body);
      SAFE_FREE(item->email->cc_address);
      SAFE_FREE(item->email->common_name);
      SAFE_FREE(item->email->encrypted_body);
      SAFE_FREE(item->email->encrypted_htmlbody);
      SAFE_FREE(item->email->header);
      SAFE_FREE(item->email->htmlbody);
      SAFE_FREE(item->email->in_reply_to);
      SAFE_FREE(item->email->messageid);
      SAFE_FREE(item->email->outlook_recipient);
      SAFE_FREE(item->email->outlook_recipient2);
      SAFE_FREE(item->email->outlook_sender);
      SAFE_FREE(item->email->outlook_sender_name);
      SAFE_FREE(item->email->outlook_sender2);
      SAFE_FREE(item->email->proc_subject);
      SAFE_FREE(item->email->recip_access);
      SAFE_FREE(item->email->recip_address);
      SAFE_FREE(item->email->recip2_access);
      SAFE_FREE(item->email->recip2_address);
      SAFE_FREE(item->email->reply_to);
      SAFE_FREE(item->email->rtf_body_tag);
      SAFE_FREE(item->email->rtf_compressed);
      SAFE_FREE(item->email->return_path_address);
      SAFE_FREE(item->email->sender_access);
      SAFE_FREE(item->email->sender_address);
      SAFE_FREE(item->email->sender2_access);
      SAFE_FREE(item->email->sender2_address);
      SAFE_FREE(item->email->sent_date);
      SAFE_FREE(item->email->sentmail_folder);
      SAFE_FREE(item->email->sentto_address);
      if (item->email->subject != NULL)
	SAFE_FREE(item->email->subject->subj);
      SAFE_FREE(item->email->subject);
      free(item->email);
    }
    if (item->folder) {
      free(item->folder);
    }
    if (item->message_store) {
      SAFE_FREE(item->message_store->deleted_items_folder);
      SAFE_FREE(item->message_store->search_root_folder);
      SAFE_FREE(item->message_store->top_of_personal_folder);
      SAFE_FREE(item->message_store->top_of_folder);
      free(item->message_store);
    }
    if (item->contact) {
      SAFE_FREE(item->contact->access_method);
      SAFE_FREE(item->contact->account_name);
      SAFE_FREE(item->contact->address1);
      SAFE_FREE(item->contact->address1_desc);
      SAFE_FREE(item->contact->address1_transport);
      SAFE_FREE(item->contact->address2);
      SAFE_FREE(item->contact->address2_desc);
      SAFE_FREE(item->contact->address2_transport);
      SAFE_FREE(item->contact->address3);
      SAFE_FREE(item->contact->address3_desc);
      SAFE_FREE(item->contact->address3_transport);
      SAFE_FREE(item->contact->assistant_name);
      SAFE_FREE(item->contact->assistant_phone);
      SAFE_FREE(item->contact->billing_information);
      SAFE_FREE(item->contact->birthday);
      SAFE_FREE(item->contact->business_address);
      SAFE_FREE(item->contact->business_city);
      SAFE_FREE(item->contact->business_country);
      SAFE_FREE(item->contact->business_fax);
      SAFE_FREE(item->contact->business_homepage);
      SAFE_FREE(item->contact->business_phone);
      SAFE_FREE(item->contact->business_phone2);
      SAFE_FREE(item->contact->business_po_box);
      SAFE_FREE(item->contact->business_postal_code);
      SAFE_FREE(item->contact->business_state);
      SAFE_FREE(item->contact->business_street);
      SAFE_FREE(item->contact->callback_phone);
      SAFE_FREE(item->contact->car_phone);
      SAFE_FREE(item->contact->company_main_phone);
      SAFE_FREE(item->contact->company_name);
      SAFE_FREE(item->contact->computer_name);
      SAFE_FREE(item->contact->customer_id);
      SAFE_FREE(item->contact->def_postal_address);
      SAFE_FREE(item->contact->department);
      SAFE_FREE(item->contact->display_name_prefix);
      SAFE_FREE(item->contact->first_name);
      SAFE_FREE(item->contact->followup);
      SAFE_FREE(item->contact->free_busy_address);
      SAFE_FREE(item->contact->ftp_site);
      SAFE_FREE(item->contact->fullname);
      SAFE_FREE(item->contact->gov_id);
      SAFE_FREE(item->contact->hobbies);
      SAFE_FREE(item->contact->home_address);
      SAFE_FREE(item->contact->home_city);
      SAFE_FREE(item->contact->home_country);
      SAFE_FREE(item->contact->home_fax);
      SAFE_FREE(item->contact->home_po_box);
      SAFE_FREE(item->contact->home_phone);
      SAFE_FREE(item->contact->home_phone2);
      SAFE_FREE(item->contact->home_postal_code);
      SAFE_FREE(item->contact->home_state);
      SAFE_FREE(item->contact->home_street);
      SAFE_FREE(item->contact->initials);
      SAFE_FREE(item->contact->isdn_phone);
      SAFE_FREE(item->contact->job_title);
      SAFE_FREE(item->contact->keyword);
      SAFE_FREE(item->contact->language);
      SAFE_FREE(item->contact->location);
      SAFE_FREE(item->contact->manager_name);
      SAFE_FREE(item->contact->middle_name);
      SAFE_FREE(item->contact->mileage);
      SAFE_FREE(item->contact->mobile_phone);
      SAFE_FREE(item->contact->nickname);
      SAFE_FREE(item->contact->office_loc);
      SAFE_FREE(item->contact->org_id);
      SAFE_FREE(item->contact->other_address);
      SAFE_FREE(item->contact->other_city);
      SAFE_FREE(item->contact->other_country);
      SAFE_FREE(item->contact->other_phone);
      SAFE_FREE(item->contact->other_po_box);
      SAFE_FREE(item->contact->other_postal_code);
      SAFE_FREE(item->contact->other_state);
      SAFE_FREE(item->contact->other_street);
      SAFE_FREE(item->contact->pager_phone);
      SAFE_FREE(item->contact->personal_homepage);
      SAFE_FREE(item->contact->pref_name);
      SAFE_FREE(item->contact->primary_fax);
      SAFE_FREE(item->contact->primary_phone);
      SAFE_FREE(item->contact->profession);
      SAFE_FREE(item->contact->radio_phone);
      SAFE_FREE(item->contact->spouse_name);
      SAFE_FREE(item->contact->suffix);
      SAFE_FREE(item->contact->surname);
      SAFE_FREE(item->contact->telex);
      SAFE_FREE(item->contact->transmittable_display_name);
      SAFE_FREE(item->contact->ttytdd_phone);
      SAFE_FREE(item->contact->wedding_anniversary);
      free(item->contact);
    }
    while (item->attach != NULL) {
      SAFE_FREE(item->attach->filename1);
      SAFE_FREE(item->attach->filename2);
      SAFE_FREE(item->attach->mimetype);
      SAFE_FREE(item->attach->data);
      t = item->attach->next;
      free(item->attach);
      item->attach = t;
    }
    while (item->extra_fields != NULL) {
      SAFE_FREE(item->extra_fields->field_name);
      SAFE_FREE(item->extra_fields->value);
      et = item->extra_fields->next;
      free(item->extra_fields);
      item->extra_fields = et;
    }
    if (item->journal) {
      SAFE_FREE(item->journal->end);
      SAFE_FREE(item->journal->start);
      SAFE_FREE(item->journal->type);
      free(item->journal);
    }
    if (item->appointment) {
      SAFE_FREE(item->appointment->location);
      SAFE_FREE(item->appointment->reminder);
      SAFE_FREE(item->appointment->start);
      SAFE_FREE(item->appointment->end);
      SAFE_FREE(item->appointment->timezonestring);
      free(item->appointment);
    }
    SAFE_FREE(item->ascii_type);
    SAFE_FREE(item->comment);
    SAFE_FREE(item->create_date);
    SAFE_FREE(item->file_as);
    SAFE_FREE(item->modify_date);
    SAFE_FREE(item->outlook_version);
    SAFE_FREE(item->record_key);
    free(item);
  }
}

int32_t _pst_getBlockOffset(char *buf, int32_t i_offset, int32_t offset, pst_block_offset *p) {
  int32_t of1;
  if (p == NULL || buf == NULL || offset == 0) {
    cli_dbgmsg("p is NULL or buf is NULL or offset is 0 (%p, %p, %#x)\n", p, buf, offset);
    return -1;
  }
  of1 = offset>>4;
  memcpy(&(p->from), &(buf[(i_offset+2)+of1]), sizeof(p->from));
  memcpy(&(p->to), &(buf[(i_offset+2)+of1+sizeof(p->from)]), sizeof(p->to));
  LE16_CPU(p->from);
  LE16_CPU(p->to);
  return 0;
}

pst_index_ll *
_pst_getID(pst_file* pf, u_int32_t id)
{
  pst_index_ll *ptr = NULL;

  if (id == 0) {
    return NULL;
  }

  id &= 0xFFFFFFFE; /* remove least sig. bit. seems that it might work if I do this */

  cli_dbgmsg("Trying to find %#x\n", id);

	if (ptr == NULL)
		ptr = pf->i_head;

	while (ptr->id != id) {
		ptr = ptr->next;
		if (ptr == NULL)
			break;
	}

	if (ptr == NULL)
		cli_dbgmsg("ERROR: Value not found\n");
	else
		cli_dbgmsg("Found Value %#x\n", ptr->id);

	return ptr;
}

static pst_index_ll *
_pst_getID2(pst_index2_ll *ptr, u_int32_t id)
{
	cli_dbgmsg("Head = %p\n", ptr);
	cli_dbgmsg("Trying to find %#x\n", id);

	while (ptr != NULL && ptr->id2 != (int32_t)id)
		ptr = ptr->next;

	if (ptr != NULL) {
		if (ptr->id != NULL)
			cli_dbgmsg("Found value %#x\n", ptr->id->id);
		else
			cli_dbgmsg("Found value, though it is NULL!\n");
		return ptr->id;
	}
	cli_dbgmsg("ERROR Not Found\n");
	return NULL;
}

pst_desc_ll * _pst_getDptr(pst_file *pf, u_int32_t id) {
  pst_desc_ll *ptr = pf->d_head;
  while(ptr != NULL && ptr->id != id) {
    if (ptr->child != NULL) {
      ptr = ptr->child;
      continue;
    }
    while (ptr->next == NULL && ptr->parent != NULL) {
      ptr = ptr->parent;
    }
    ptr = ptr->next;
  }
  return ptr; // will be NULL or record we are looking for
}

// when the first byte of the block being read is 01, then we can assume
// that it is a list of further ids to read and we will follow those ids
// recursively calling this function until we have all the data
// we could do decryption of the encrypted PST files here
static size_t
_pst_read_block_size(pst_file *pf, int32_t offset, size_t size, char ** buf, int32_t do_enc, unsigned char is_index)
{
  u_int32_t fpos, x;
  int16_t count, y;
  char *buf2 = NULL, *buf3 = NULL;
  unsigned char fdepth;
  pst_index_ll *ptr = NULL;
  size_t rsize, z;

  cli_dbgmsg("Reading block from %#x, %i bytes\n", offset, size);

  if(size == 0)
	return 0;

  fpos = ftell(pf->fp);
  fseek(pf->fp, offset, SEEK_SET);

  if (*buf != NULL) {
    cli_dbgmsg("Freeing old memory\n");
    free(*buf);
    *buf = (void *)cli_realloc(*buf, size + 1);
  } else
	  *buf = (void*) cli_malloc(size+1); //plus one so that we can NULL terminate it later

  rsize = fread(*buf, 1, size, pf->fp);
  if (rsize != size) {
    cli_warnmsg("Didn't read all that I could. fread returned less [%i instead of %i]\n", rsize, size);
    if (feof(pf->fp)) {
      cli_warnmsg("We tried to read past the end of the file at [offset %#x, size %#x]\n", offset, size);
    } else if (ferror(pf->fp)) {
      cli_warnmsg("Error is set on file stream.\n");
    } else {
      cli_warnmsg("I can't tell why it failed\n");
    }
	if(rsize <= 2) {
		fseek(pf->fp, fpos, SEEK_SET);
		**buf = '\0';
		return 0;
	}
    size = rsize;
  }

  //  cli_dbgmsg(*buf, size);

  /*  if (is_index) {
    cli_dbgmsg("_pst_read_block_size: ODD_BLOCK should be here\n");
    cli_dbgmsg(*buf)[1]);
    }*/

  if ((*buf)[0] == 0x01 && (*buf)[1] != 0x00 && is_index) {
    //don't do this recursion if we should be at a leaf node
    memcpy(&count, &((*buf)[2]), sizeof(int16_t));
    LE16_CPU(count);
    memcpy(&fdepth, &((*buf)[1]), sizeof(fdepth));
    cli_dbgmsg("Seen indexes to blocks. Depth is %i\n", fdepth);
    // do fancy stuff! :)
    cli_dbgmsg("There are %i ids\n", count);
    // if first 2 blocks are 01 01 then index to blocks
    size = 0;
    y = 0;
    while (y < count) {
      memcpy(&x, &(*buf)[0x08+(y*4)], sizeof(int32_t));
      LE32_CPU(x);
      if ((ptr = _pst_getID(pf, x)) == NULL) {
	cli_errmsg("Error. Cannot find ID [%#x] during multi-block read\n", x);
	buf3 = (char*) cli_realloc(buf3, size+1);
	buf3[size] = '\0';
	*buf = buf3;
	fseek(pf->fp, fpos, SEEK_SET);
	return size;
      }
      if ((z = _pst_read_block_size(pf, ptr->offset, ptr->size, &buf2, do_enc, fdepth-1)) < ptr->size) {
	buf3 = (char*) cli_realloc(buf3, size+1);
	buf3[size] = '\0';
	*buf = buf3;
	fseek(pf->fp, fpos, SEEK_SET);
	return size;
      }
      cli_dbgmsg("Melding newley retrieved block with bigger one. New size is %i\n", size+z);
      buf3 = (char*) cli_realloc(buf3, size+z+1); //plus one so that we can null terminate it later
      cli_dbgmsg("Doing copy. Start pos is %i, length is %i\n", size, z);
      memcpy(&(buf3[size]), buf2, z);
      size += z;
      y++;
    }
    free(*buf);
    if (buf2 != NULL)
      free(buf2);
    if (buf3 == NULL) {
      // this can happen if count == 0. We should create an empty buffer so we don't
      // confuse any clients
      buf3 = (char*) cli_malloc(1);
    }
    *buf = buf3;
  } else if (do_enc && pf->encryption)
    _pst_decrypt((unsigned char *)*buf, size, pf->encryption);

  (*buf)[size] = '\0'; //should be byte after last one read
  fseek(pf->fp, fpos, SEEK_SET);
  return size;
}

int32_t _pst_decrypt(unsigned char *buf, size_t size, int32_t type) {
  size_t x = 0;
  unsigned char y;
  if (buf == NULL) {
    return -1;
  }

  if (type == PST_COMP_ENCRYPT) {
    x = 0;
    while (x < size) {
      y = buf[x];
      /*cli_dbgmsg("Transposing %#hhx to %#hhx [%#x]\n", buf[x], comp_enc[y], y);*/
      buf[x] = comp_enc[y]; // transpose from encrypt array
      x++;
    }
  } else {
    cli_warnmsg("Unknown encryption: %i. Cannot decrypt\n", type);
    return -1;
  }
  return 0;
}

static int32_t
_pst_getAtPos(FILE *fp, int32_t pos, void* buf, u_int32_t size)
{
	if(fseek(fp, pos, SEEK_SET) == -1)
		return 1;

	if(fread(buf, size, 1, fp) != 1)
		return 2;

	return 0;
}

int32_t _pst_get (FILE *fp, void *buf, u_int32_t size) {
  if (fread(buf, 1,  size, fp) < size) {
    return 1;
  }
  return 0;
}

size_t _pst_ff_getIDblock_dec(pst_file *pf, u_int32_t id, unsigned char **b) {
  size_t r;
  r = _pst_ff_getIDblock(pf, id, b);
  if (pf->encryption)
    _pst_decrypt(*b, r, pf->encryption);
  return r;
}

/** the get ID function for the default file format that I am working with
    ie the one in the PST files */
static size_t
_pst_ff_getIDblock(pst_file *pf, u_int32_t id, unsigned char** b)
{
  pst_index_ll *rec;
  size_t rsize = 0;//, re_size=0;
  if ((rec = _pst_getID(pf, id)) == NULL) {
    cli_dbgmsg("Cannot find ID %#x\n", id);
    return 0;
  }
  fseek(pf->fp, rec->offset, SEEK_SET);
  if (*b != NULL) {
    cli_dbgmsg("freeing old memory in b\n");
	*b = (unsigned char*) cli_realloc(*b, rec->size+1);
  } else
	*b = (unsigned char*) cli_malloc(rec->size+1);

  cli_dbgmsg("record size = %#x, estimated size = %#x\n", rec->size, rec->size);
  rsize = fread(*b, 1, rec->size, pf->fp);
  if (rsize != rec->size) {
    cli_dbgmsg("Didn't read all the size. fread returned less [%i instead of %i]\n", rsize, rec->size);
    if (feof(pf->fp)) {
      cli_dbgmsg("We tried to read past the end of the file [offset %#x, size %#x]\n", rec->offset, rec->size);
    } else if (ferror(pf->fp)) {
      cli_dbgmsg("Some error occured on the file stream\n");
    } else {
      cli_dbgmsg("No error has been set on the file stream\n");
    }
  }
  return rsize;
}

#define PST_PTR_BLOCK_SIZE 0x120
size_t _pst_ff_getID2block(pst_file *pf, u_int32_t id2, pst_index2_ll *id2_head, unsigned char** buf) {
  pst_index_ll* ptr;
  struct holder h = {buf, NULL, 0, {'\0', '\0', '\0'}, 0};
  ptr = _pst_getID2(id2_head, id2);

  if (ptr == NULL) {
    cli_dbgmsg("Cannot find id2 value %#x\n", id2);
    return 0;
  }
  return _pst_ff_getID2data(pf, ptr, &h);
}

static size_t
_pst_ff_getID2data(pst_file *pf, pst_index_ll *ptr, struct holder *h)
{
  // if the attachment begins with 01 01, <= 256 bytes, it is stored in the record
  int32_t ret;
  unsigned char *b = NULL;
  char *t;
  if (!(ptr->id & 0x02)) {
    ret = _pst_ff_getIDblock_dec(pf, ptr->id, &b);
    if (h->buf != NULL) {
      *(h->buf) = b;
    } else if (h->base64 == 1 && h->fp != NULL) {
      t = base64_encode(b, ret);
      if(t) {
	      fputs(t, h->fp);
	      free(t);
	}
      free(b);
    } else if (h->fp != NULL) {
      pst_fwrite(b, 1, ret, h->fp);
      free(b);
    }
    //    if ((*buf)[0] == 0x1) {
//      cli_dbgmsg("WARNING: buffer starts with 0x1, but I didn't expect it to!\n");
//      }
  } else {
    // here we will assume it is a block that points to others
    cli_dbgmsg("Assuming it is a multi-block record because of it's id\n");
    ret = _pst_ff_compile_ID(pf, ptr->id, h, 0);
  }
  if (h->buf != NULL && *h->buf != NULL)
    (*(h->buf))[ret]='\0';
  return ret;
}

static size_t
_pst_ff_compile_ID(pst_file *pf, u_int32_t id, struct holder *h, int32_t size)
{
	size_t z, a;
	u_int16_t count, y;
	u_int32_t x, b;
	unsigned char * buf3 = NULL, *buf2 = NULL;
	char *t;
	unsigned char fdepth;

	if ((a = _pst_ff_getIDblock(pf, id, &buf3))==0) {
		if(buf3)
			free(buf3);
		return 0;
	}

  if ((buf3[0] != 0x1)) { // if bit 8 is set) {
    //  if ((buf3)[0] != 0x1 && (buf3)[1] > 4) {
    cli_dbgmsg("WARNING: buffer doesn't start with 0x1, but I expected it to or doesn't have it's two-bit set!\n");
    cli_dbgmsg("Treating as normal buffer\n");
    if (pf->encryption)
      _pst_decrypt(buf3, a, pf->encryption);
    if (h->buf != NULL)
      *(h->buf) = buf3;
    else if (h->base64 == 1 && h->fp != NULL) {
      t = base64_encode(buf3, a);
      if(t) {
	      fputs(t, h->fp);
	      free(t);
	}
      free(buf3);
    } else if (h->fp != NULL) {
      pst_fwrite(buf3, 1, a, h->fp);
      free(buf3);
    }
    return a;
  }
  memcpy (&count, &(buf3[2]), sizeof(int16_t));
  LE16_CPU(count);
  memcpy (&fdepth, &(buf3[1]), sizeof(char));
  cli_dbgmsg("Seen index to blocks. Depth is %i\n", fdepth);
  cli_dbgmsg("There are %i ids here\n", count);

  y = 0;
  while (y < count) {
    memcpy(&x, &buf3[0x08+(y*4)], sizeof(int32_t));
    LE32_CPU(x);
    if (fdepth == 0x1) {
      if ((z = _pst_ff_getIDblock(pf, x, &buf2)) == 0) {
	cli_dbgmsg("call to getIDblock returned zero %i\n", z);
	if (buf2 != NULL)
	  free(buf2);
	free(buf3);
	return z;
      }
      if (pf->encryption)
	_pst_decrypt(buf2, z, pf->encryption);
      if (h->buf != NULL) {
	*(h->buf) = cli_realloc(*(h->buf), size+z+1);
	cli_dbgmsg("appending read data of size %i onto main buffer from pos %i\n", z, size);
	memcpy(&((*(h->buf))[size]), buf2, z);
      } else if (h->base64 == 1 && h->fp != NULL) {
	// include any byte left over from the last one encoding
	buf2 = (unsigned char*)cli_realloc(buf2, z+h->base64_extra);
	memmove(buf2+h->base64_extra, buf2, z);
	memcpy(buf2, h->base64_extra_chars, h->base64_extra);
	z+= h->base64_extra;

	b = z % 3; // find out how many bytes will be left over after the encoding.
	// and save them
	memcpy(h->base64_extra_chars, &(buf2[z-b]), b);
	h->base64_extra = b;
	t = base64_encode(buf2, z-b);
	cli_dbgmsg("writing %i bytes to file as base64 [%i]. Currently %i\n",
		    z, strlen(t), size);
	if(t) {
		fputs(t, h->fp);
		free(t);
	}
      } else if (h->fp != NULL) {
	cli_dbgmsg("writing %i bytes to file. Currently %i\n", z, size);
	pst_fwrite(buf2, 1, z, h->fp);
      }
      size += z;
      y++;
    } else {
      if ((z = _pst_ff_compile_ID(pf, x, h, size)) == 0) {
	cli_dbgmsg("recursive called returned zero %i\n", z);
	free(buf3);
	return z;
      }
      size = z;
      y++;
    }
  }
  free(buf3);
  if (buf2 != NULL)
    free(buf2);
  return size;
}

size_t pst_fwrite(const void*ptr, size_t size, size_t nmemb, FILE*stream) {
  size_t r;
  if (ptr != NULL)
    r = fwrite(ptr, size, nmemb, stream);
  else {
    r = 0;
    cli_warnmsg("An attempt to write a NULL Pointer was made\n");
  }
  return r;
}

char * _pst_wide_to_single(char *wt, int32_t size) {
  // returns the first byte of each wide char. the size is the number of bytes in source
  char *x, *y;
  x = cli_malloc((size/2)+1);
  y = x;
  while (size != 0 && *wt != '\0') {
    *y = *wt;
    wt+=2;
    size -= 2;
    y++;
  }
  *y = '\0';
  return x;
}

/* Taken from LibStrfunc v7.3 */

static const unsigned char _sf_uc_ib[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==";

static char *
base64_encode(const unsigned char *data, size_t size)
{
	char *output;
	char *ou;
	const unsigned char *p = data;
	const unsigned char *dte = &data[size];
	int nc=0;

  if(data == NULL)
    return NULL;

    if(size == 0)
	return NULL;

  ou=output=(char *)cli_malloc(size / 3 * 4 + (size / 50) + 5);
  if(!output)
    return NULL;

  while((dte - p) >= 3) {
    *ou = _sf_uc_ib[ *p >> 2 ];
    ou[1] = _sf_uc_ib[ ((*p & 0x03) << 4) | (p[1] >> 4) ];
    ou[2] = _sf_uc_ib[ ((p[1] & 0x0F) << 2) | (p[2] >> 6) ];
    ou[3] = _sf_uc_ib[ p[2] & 0x3F ];

    p+=3;
    ou+=4;

    nc+=4;
    if(!(nc % 76)) *ou++='\n';
  };
  if((dte - p) == 2) {
    *ou++ = _sf_uc_ib[ *p >> 2 ];
    *ou++ = _sf_uc_ib[ ((*p & 0x03) << 4) | (p[1] >> 4) ];
    *ou++ = _sf_uc_ib[ ((p[1] & 0x0F) << 2) ];
    *ou++ = '=';
  } else if((dte - p) == 1) {
    *ou++ = _sf_uc_ib[ *p >> 2 ];
    *ou++ = _sf_uc_ib[ ((*p & 0x03) << 4) ];
    *ou++ = '=';
    *ou++ = '=';
  };

  *ou=0;
	return output;
}


/* NJH, hacked from readpst.c */
#define RTF_ATTACH_NAME "rtf-body.rtf"
// mime type for the attachment
#define RTF_ATTACH_TYPE "application/rtf"
// output mode for contacts
#define CMODE_VCARD 0
#define CMODE_LIST  1

#define MIME_TYPE_DEFAULT "application/octet-stream"
#define OUTPUT_TEMPLATE "%s"

struct file_ll {
  char *name;
  char *dname;
  FILE * output;
  int32_t stored_count;
  int32_t email_count;
  int32_t skip_count;
  int32_t type;
  struct file_ll *next;
};
#define C_TIME_SIZE 500

// char *check_filename(char *fname) {{{1
char *check_filename(char *fname) {
  char *t = fname;
  if (t == NULL) {
    return fname;
  }
  while ((t = strpbrk(t, "/\\:")) != NULL) {
    // while there are characters in the second string that we don't want
    *t = '_'; //replace them with an underscore
  }
  return fname;
}

static int
chr_count(const char *str, char x)
{
	int r = 0;

	while (*str != '\0') {
		if (*str == x)
			r++;
		str++;
	}
	return r;
}

static const char *
rfc2426_escape(const char *str)
{
	static char* buf = NULL;
	const char *ret, *a;
	char *b;
	int x = 0, y, z;

  if (str == NULL)
    ret = str;
  else {

    // calculate space required to escape all the following characters
    x = strlen(str) +(y=(chr_count(str, ',')*2) + (chr_count(str, '\\')*2) + (chr_count(str, ';')*2) + (chr_count(str, '\n')*2));
    z = chr_count(str, '\r');
    if (y == 0 && z == 0)
      // there isn't any extra space required
      ret = str;
    else {
      buf = (char*) cli_realloc(buf, x+1);
      a = str;
      b = buf;
      while (*a != '\0') {
	switch(*a) {
	case ',' :
	case '\\':
	case ';' :
	case '\n':
	  *(b++)='\\';
	  *b=*a;
	break;
	case '\r':
	  break;
	default:
	  *b=*a;
	}
	b++;
      a++;
      }
      *b = '\0';
      ret = buf;
    }
  }
  return ret;
}

/* my_stristr varies from strstr in that its searches are case-insensitive */
static char *
my_stristr(const char *haystack, const char *needle)
{
	const char *x=haystack, *y=needle, *z = NULL;
	if (haystack == NULL || needle == NULL)
		return NULL;

	while (*y != '\0' && *x != '\0') {
		if (tolower(*y) == tolower(*x)) {
			// move y on one
			y++;
			if (z == NULL) {
				z = x; // store first position in haystack where a match is made
			}
		} else {
			y = needle; // reset y to the beginning of the needle
			z = NULL; // reset the haystack storage point
		}
		x++; // advance the search in the haystack
	}
	return (char *)z;
}

static const char *
rfc2445_datetime_format(FILETIME *ft)
{
	static char *buffer = NULL;
	const struct tm *stm = NULL;
	if (buffer == NULL)
		buffer = cli_malloc(30); // should be enough
	stm = fileTimeToStructTM(ft);
	if (strftime(buffer, 30, "%Y%m%dT%H%M%SZ", stm)==0) {
		cli_dbgmsg("Problem occured formatting date\n");
		return NULL;
	}
	return buffer;
}

char *removeCR (char *c) {
  // converts /r/n to /n
  char *a, *b;
  a = b = c;
  while (*a != '\0') {
    *b = *a;
    if (*a != '\r')
      b++;
    a++;
  }
  *b = '\0';
  return c;
}

static size_t
write_email_body(FILE *f, const char *body)
{
	const char *n = body;

	while (n != NULL) {
		if (strncmp(body, "From ", 5) == 0)
			putc('>', f);

		if((n = strchr(body, '\n')) != NULL) {
			n++;
			(void)fwrite(body, n-body, 1, f);	/* write just a line */

			body = n;
		}
	}
	return fputs(body, f);
}

// The sole purpose of this function is to bypass the pseudo-header prologue
// that Microsoft Outlook inserts at the beginning of the internet email
// headers for emails stored in their "Personal Folders" files.
char *skip_header_prologue(char *headers) {
	const char *bad = "Microsoft Mail Internet Headers";

	if ( strncmp(headers, bad, strlen(bad)) == 0 ) {
		// Found the offensive header prologue
		char *pc;

		pc = strchr(headers, '\n');
		return pc + 1;
	}

	return headers;
}

static const char *
rfc2425_datetime_format(const FILETIME *ft)
{
	static char *buffer = NULL;
	const struct tm *stm = NULL;
	if (buffer == NULL)
		buffer = cli_malloc(30); // should be enough for the date as defined below

	stm = fileTimeToStructTM(ft);
	//Year[4]-Month[2]-Day[2] Hour[2]:Min[2]:Sec[2]
	if(strftime(buffer, 30, "%Y-%m-%dT%H:%M:%SZ", stm) == 0) {
		cli_errmsg("Problem occured formatting date\n");
		return NULL;
	}
	return buffer;
}

#define LZFU_COMPRESSED         0x75465a4c
#define LZFU_UNCOMPRESSED       0x414c454d

// initital dictionary
#define LZFU_INITDICT   "{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}" \
						 "{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscrip" \
						 "t \\fdecor MS Sans SerifSymbolArialTimes Ne" \
						 "w RomanCourier{\\colortbl\\red0\\green0\\blue0" \
						 "\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab" \
						 "\\tx"
// initial length of dictionary
#define LZFU_INITLENGTH 207

// header for compressed rtf
typedef struct _lzfuheader {
  uint32_t cbSize;
  uint32_t cbRawSize;
  uint32_t dwMagic;
  uint32_t dwCRC;
} lzfuheader;


/**
    We always need to add 0x10 to the buffer offset because we need to skip past the header info
*/

static unsigned char *
lzfu_decompress(const unsigned char* rtfcomp, size_t *nbytes)
{
  // the dictionary buffer
  unsigned char dict[4096];
  // the dictionary pointer
  unsigned int dict_length=0;
  // the header of the lzfu block
  lzfuheader lzfuhdr;
  // container for the data blocks
  unsigned char flags;
  // temp value for determining the bits in the flag
  unsigned char flag_mask;
  unsigned int i, in_size;
  unsigned char *out_buf;
  unsigned int out_ptr = 0;

	*nbytes = 0;
  memcpy(dict, LZFU_INITDICT, LZFU_INITLENGTH);
  dict_length = LZFU_INITLENGTH;
  memcpy(&lzfuhdr, rtfcomp, sizeof(lzfuhdr));
  LE32_CPU(lzfuhdr.cbSize);   LE32_CPU(lzfuhdr.cbRawSize);
  LE32_CPU(lzfuhdr.dwMagic);  LE32_CPU(lzfuhdr.dwCRC);
  /*printf("total size: %d\n", lzfuhdr.cbSize+4);
  printf("raw size  : %d\n", lzfuhdr.cbRawSize);
  printf("compressed: %s\n", (lzfuhdr.dwMagic == LZFU_COMPRESSED ? "yes" : "no"));
  printf("CRC       : %#x\n", lzfuhdr.dwCRC);
  printf("\n");*/
  out_buf = (unsigned char*)cli_malloc(lzfuhdr.cbRawSize+20); //plus 4 cause we have 2x'}' and a \0
  in_size = 0;
  // we add plus one here cause when referencing an array, the index is always one less
  // (ie, when accessing 2 element array, highest index is [1])
  while (in_size+0x11 < lzfuhdr.cbSize) {
    memcpy(&flags, &(rtfcomp[in_size+0x10]), 1);
    in_size += 1;

    flag_mask = 1;
    while (flag_mask != 0 && in_size+0x11 < lzfuhdr.cbSize) {
      if (flag_mask & flags) {
	// read 2 bytes from input
	unsigned short int blkhdr, offset, length;
	memcpy(&blkhdr, &(rtfcomp[in_size+0x10]), 2);
	LE16_CPU(blkhdr);
	in_size += 2;
	/* swap the upper and lower bytes of blkhdr */
	blkhdr = (((blkhdr&0xFF00)>>8)+
		  ((blkhdr&0x00FF)<<8));
	/* the offset is the first 24 bits of the 32 bit value */
	offset = (blkhdr&0xFFF0)>>4;
	/* the length of the dict entry are the last 8 bits */
	length = (blkhdr&0x000F)+2;
	// add the value we are about to print to the dictionary
	for (i=0; i < length; i++) {
	  unsigned char c1;
	  c1 = dict[(offset+i)%4096];
	  dict[dict_length]=c1;
	  dict_length = (dict_length+1) % 4096;
	  out_buf[out_ptr++] = c1;
	}
      } else {
	// uncompressed chunk (single byte)
	char c1 = rtfcomp[in_size+0x10];
	in_size ++;
	dict[dict_length] = c1;
	dict_length = (dict_length+1)%4096;
	out_buf[out_ptr++] = c1;
      }
      flag_mask <<= 1;
    }
  }
  // the compressed version doesn't appear to drop the closing braces onto the doc.
  // we should do that
  out_buf[out_ptr++] = '}';
  out_buf[out_ptr++] = '}';
  out_buf[out_ptr++] = '\0';
	if(nbytes)
		*nbytes = (size_t)out_ptr;
  return out_buf;
}

static int
pst_decode(const char *dir, int desc)
{
	int base64_body = 0;
	char *boundary = NULL, *b1, *b2;	/* the boundary marker between multipart sections */
	char *c_time, *filename;
	time_t em_time;
	int contact_mode = CMODE_VCARD;
	int skip_child = 0;
	int attach_num = 0;
	int x;
	char *temp = NULL;	/* temporary char pointer */
	pst_item *item = NULL;
	pst_file pstfile;
	pst_desc_ll *d_ptr;
	struct file_ll  *f, *head;
	char *enc = NULL;	/* base64 encoded attachment */

	x = pst_open(&pstfile, desc);
	if(x != CL_SUCCESS)
		return x;

	if(pst_load_index(&pstfile) != 0) {
		pst_close(&pstfile);
		return CL_EFORMAT;
	}

	if(pst_load_extended_attributes(&pstfile) == 0) {
		pst_close(&pstfile);
		return CL_EFORMAT;
	}

	d_ptr = pstfile.d_head;	/* first record is main record */

	if ((item = _pst_parse_item(&pstfile, d_ptr)) == NULL || item->message_store == NULL) {
		pst_close(&pstfile);
		return CL_EFORMAT;
	}

	/*
	 * default the file_as to the same as the main filename if it doesn't
	 * exist
	 */
	if (item->file_as == NULL) {
		item->file_as = strdup("clamav-pst");
		if(item->file_as == NULL) {
			pst_close(&pstfile);
			return CL_EMEM;
		}
	}
	head = f = (struct file_ll*)cli_calloc(1, sizeof(struct file_ll));

	if(f == NULL) {
		free(item->file_as);
		pst_close(&pstfile);
		return CL_EMEM;
	}

	f->name = (char*) cli_malloc(strlen(item->file_as)+strlen(OUTPUT_TEMPLATE)+1);
	if(f->name == NULL) {
		free(f);
		free(item->file_as);
		pst_close(&pstfile);
		return CL_EMEM;
	}
	sprintf(f->name, OUTPUT_TEMPLATE, item->file_as);

	f->dname = strdup(item->file_as);

    // if overwrite is set to 1 we keep the existing name and don't modify anything
    // we don't want to go changing the file name of the SEPERATE items
    temp = (char*) cli_malloc (strlen(f->name)+10); //enough room for 10 digits
    strcpy(temp, f->name);
    temp = check_filename(temp);
    x = 0;
    while ((f->output = fopen(temp, "r")) != NULL) {
      x++;
      sprintf(temp, "%s%08d", f->name, x);
      if (x == 99999999) {
	cli_errmsg("main: Why can I not create a folder %s? I have tried %i extensions...\n", f->name, x);
      }
      fclose(f->output);
    }
    if (x > 0) { //then the f->name should change
      free (f->name);
      f->name = temp;
    } else {
      free (temp);
    }
    f->name = check_filename(f->name);
    filename = cli_malloc(strlen(f->name) + strlen(dir) + 2);
    sprintf(filename, "%s/%s", dir, f->name);
	cli_dbgmsg("PST: create %s\n", filename);
    if ((f->output = fopen(filename, "w")) == NULL) {
      cli_errmsg("main: Could not open file \"%s\" for write\n", filename);
    free(filename);
	return CL_ETMPFILE;
    }
    free(filename);
  f->type = item->type;

  if ((d_ptr = pst_getTopOfFolders(&pstfile, item)) == NULL) {
	return CL_EFORMAT;
  }

  if (item){
    _pst_freeItem(item);
    item = NULL;
  }

  /*  if ((item = _pst_parse_item(&pstfile, d_ptr)) == NULL || item->folder == NULL) {
    printf("main: Could not get \"Top Of Personal Folder\" record\n");
    return -2;
    }*/
  d_ptr = d_ptr->child; // do the children of TOPF

  while (d_ptr != NULL) {
    if (d_ptr->desc == NULL) {
      cli_warnmsg("pst_decode: item's desc record is NULL\n");
      f->skip_count++;
      goto check_parent;
    }

    item = _pst_parse_item(&pstfile, d_ptr);
    if (item != NULL && item->email != NULL && item->email->subject != NULL &&
	item->email->subject->subj != NULL) {
      //      cli_dbgmsg("item->email->subject = %p\n", item->email->subject);
      //      cli_dbgmsg("item->email->subject->subj = %p\n", item->email->subject->subj);
    }
    if (item != NULL) {
      if (item->message_store != NULL) {
	// there should only be one message_store, and we have already done it
	cli_errmsg("main: A second message_store has been found. Sorry, this must be an error.\n");
      }


      if (item->folder != NULL) {
	// Process Folder item {{{2
	// if this is a folder, we want to recurse into it
	//	f->email_count++;
	f = (struct file_ll*) cli_calloc(1, sizeof(struct file_ll));

	f->next = head;
	f->type = item->type;
	f->stored_count = item->folder->email_count;
	head = f;

	temp = item->file_as;
	temp = check_filename(temp);

	  f->name = (char*) cli_malloc(strlen(item->file_as)+strlen(OUTPUT_TEMPLATE+1));
	  sprintf(f->name, OUTPUT_TEMPLATE, item->file_as);

	f->dname = strdup(item->file_as);

	  temp = (char*) cli_malloc (strlen(f->name)+10); //enough room for 10 digits
	  strcpy(temp, f->name);
	  x = 0;
	  temp = check_filename(temp);
	  while ((f->output = fopen(temp, "r")) != NULL) {
	    x++;
	    sprintf(temp, "%s%08d", f->name, x);
	    if (x == 99999999) {
	      cli_errmsg("main: Why can I not create a folder %s? I have tried %i extensions...\n", f->name, x);
	      return(5);
	    }
	    fclose(f->output);
	  }
	  if (x > 0) { //then the f->name should change
	    free (f->name);
	    f->name = temp;
	  } else {
	    free(temp);
	  }

	  filename = cli_malloc(strlen(dir) + strlen(f->name) + 2);
	  sprintf(filename, "%s/%s", dir, f->name);
	cli_dbgmsg("PST: create %s\n", filename);
	  if ((f->output = fopen(filename, "w")) == NULL) {
	    cli_errmsg("main: Could not open file \"%s\" for write\n", f->name);
	    free(filename);
	    return CL_ETMPFILE;
	  }
	    free(filename);
	if (d_ptr->child != NULL) {
	  d_ptr = d_ptr->child;
	  skip_child = 1;
	} else {
	  head = f->next;
	  if (f->output != NULL)
	    fclose(f->output);
	  free(f->dname);
	  free(f->name);
	  free(f);

	  f = head;
	}
	_pst_freeItem(item);
	item = NULL; // just for the odd situations!
	goto check_parent;
	// }}}2
      } else if (item->contact != NULL) {
	// Process Contact item {{{2
	// deal with a contact
	// write them to the file, one per line in this format
	// Desc Name <email@address>\n
	f->email_count++;

	if (item->contact == NULL) { // this is an incorrect situation. Inform user
	  cli_errmsg("main: ERROR. This contact has not been fully parsed. one of the pre-requisties is NULL\n");
	} else {
	  if (contact_mode == CMODE_VCARD) {
	    // the specification I am following is (hopefully) RFC2426 vCard Mime Directory Profile
	    fprintf(f->output, "BEGIN:VCARD\n");
	    fprintf(f->output, "FN:%s\n", rfc2426_escape(item->contact->fullname));
	    fprintf(f->output, "N:%s;%s;%s;%s;%s\n",
		    rfc2426_escape((item->contact->surname==NULL?"":item->contact->surname)),
		    rfc2426_escape((item->contact->first_name==NULL?"":item->contact->first_name)),
		    rfc2426_escape((item->contact->middle_name==NULL?"":item->contact->middle_name)),
		    rfc2426_escape((item->contact->display_name_prefix==NULL?"":item->contact->display_name_prefix)),
		    rfc2426_escape((item->contact->suffix==NULL?"":item->contact->suffix)));
	    if (item->contact->nickname != NULL)
	      fprintf(f->output, "NICKNAME:%s\n", rfc2426_escape(item->contact->nickname));
	    if (item->contact->address1 != NULL)
	      fprintf(f->output, "EMAIL:%s\n", rfc2426_escape(item->contact->address1));
	    if (item->contact->address2 != NULL)
	      fprintf(f->output, "EMAIL:%s\n", rfc2426_escape(item->contact->address2));
	    if (item->contact->address3 != NULL)
	      fprintf(f->output, "EMAIL:%s\n", rfc2426_escape(item->contact->address3));
	    if (item->contact->birthday != NULL)
	      fprintf(f->output, "BDAY:%s\n", rfc2425_datetime_format(item->contact->birthday));
	    if (item->contact->home_address != NULL) {
	      fprintf(f->output, "ADR;TYPE=home:%s;%s;%s;%s;%s;%s;%s\n",
		      rfc2426_escape((item->contact->home_po_box!=NULL?item->contact->home_po_box:"")),
		      "", // extended Address
		      rfc2426_escape((item->contact->home_street!=NULL?item->contact->home_street:"")),
		      rfc2426_escape((item->contact->home_city!=NULL?item->contact->home_city:"")),
		      rfc2426_escape((item->contact->home_state!=NULL?item->contact->home_state:"")),
		      rfc2426_escape((item->contact->home_postal_code!=NULL?item->contact->home_postal_code:"")),
		      rfc2426_escape((item->contact->home_country!=NULL?item->contact->home_country:"")));
	      fprintf(f->output, "LABEL;TYPE=home:%s\n", rfc2426_escape(item->contact->home_address));
	    }
	    if (item->contact->business_address != NULL) {
	      fprintf(f->output, "ADR;TYPE=work:%s;%s;%s;%s;%s;%s;%s\n",
		      rfc2426_escape((item->contact->business_po_box!=NULL?item->contact->business_po_box:"")),
		      "", // extended Address
		      rfc2426_escape((item->contact->business_street!=NULL?item->contact->business_street:"")),
		      rfc2426_escape((item->contact->business_city!=NULL?item->contact->business_city:"")),
		      rfc2426_escape((item->contact->business_state!=NULL?item->contact->business_state:"")),
		      rfc2426_escape((item->contact->business_postal_code!=NULL?item->contact->business_postal_code:"")),
		      rfc2426_escape((item->contact->business_country!=NULL?item->contact->business_country:"")));
	      fprintf(f->output, "LABEL;TYPE=work:%s\n", rfc2426_escape(item->contact->business_address));
	    }
	    if (item->contact->other_address != NULL) {
	      fprintf(f->output, "ADR;TYPE=postal:%s;%s;%s;%s;%s;%s;%s\n",
		      rfc2426_escape((item->contact->other_po_box!=NULL?item->contact->business_po_box:"")),
		      "", // extended Address
		      rfc2426_escape((item->contact->other_street!=NULL?item->contact->other_street:"")),
		      rfc2426_escape((item->contact->other_city!=NULL?item->contact->other_city:"")),
		      rfc2426_escape((item->contact->other_state!=NULL?item->contact->other_state:"")),
		      rfc2426_escape((item->contact->other_postal_code!=NULL?item->contact->other_postal_code:"")),
		      rfc2426_escape((item->contact->other_country!=NULL?item->contact->other_country:"")));
	      fprintf(f->output, "ADR;TYPE=postal:%s\n", rfc2426_escape(item->contact->other_address));
	    }
	    if (item->contact->business_fax != NULL)
	      fprintf(f->output, "TEL;TYPE=work,fax:%s\n", rfc2426_escape(item->contact->business_fax));
	    if (item->contact->business_phone != NULL)
	      fprintf(f->output, "TEL;TYPE=work,voice:%s\n", rfc2426_escape(item->contact->business_phone));
	    if (item->contact->business_phone2 != NULL)
	      fprintf(f->output, "TEL;TYPE=work,voice:%s\n", rfc2426_escape(item->contact->business_phone2));
	    if (item->contact->car_phone != NULL)
	      fprintf(f->output, "TEL;TYPE=car,voice:%s\n", rfc2426_escape(item->contact->car_phone));
	    if (item->contact->home_fax != NULL)
	      fprintf(f->output, "TEL;TYPE=home,fax:%s\n", rfc2426_escape(item->contact->home_fax));
	    if (item->contact->home_phone != NULL)
	      fprintf(f->output, "TEL;TYPE=home,voice:%s\n", rfc2426_escape(item->contact->home_phone));
	    if (item->contact->home_phone2 != NULL)
	      fprintf(f->output, "TEL;TYPE=home,voice:%s\n", rfc2426_escape(item->contact->home_phone2));
	    if (item->contact->isdn_phone != NULL)
	      fprintf(f->output, "TEL;TYPE=isdn:%s\n", rfc2426_escape(item->contact->isdn_phone));
	    if (item->contact->mobile_phone != NULL)
	      fprintf(f->output, "TEL;TYPE=cell,voice:%s\n", rfc2426_escape(item->contact->mobile_phone));
	    if (item->contact->other_phone != NULL)
	      fprintf(f->output, "TEL;TYPE=msg:%s\n", rfc2426_escape(item->contact->other_phone));
	    if (item->contact->pager_phone != NULL)
	      fprintf(f->output, "TEL;TYPE=pager:%s\n", rfc2426_escape(item->contact->pager_phone));
	    if (item->contact->primary_fax != NULL)
	      fprintf(f->output, "TEL;TYPE=fax,pref:%s\n", rfc2426_escape(item->contact->primary_fax));
	    if (item->contact->primary_phone != NULL)
	      fprintf(f->output, "TEL;TYPE=phone,pref:%s\n", rfc2426_escape(item->contact->primary_phone));
	    if (item->contact->radio_phone != NULL)
	      fprintf(f->output, "TEL;TYPE=pcs:%s\n", rfc2426_escape(item->contact->radio_phone));
	    if (item->contact->telex != NULL)
	      fprintf(f->output, "TEL;TYPE=bbs:%s\n", rfc2426_escape(item->contact->telex));
	    if (item->contact->job_title != NULL)
	      fprintf(f->output, "TITLE:%s\n", rfc2426_escape(item->contact->job_title));
	    if (item->contact->profession != NULL)
	      fprintf(f->output, "ROLE:%s\n", rfc2426_escape(item->contact->profession));
	    if (item->contact->assistant_name != NULL || item->contact->assistant_phone != NULL) {
	      fprintf(f->output, "AGENT:BEGIN:VCARD\\n");
	      if (item->contact->assistant_name != NULL)
		fprintf(f->output, "FN:%s\\n", rfc2426_escape(item->contact->assistant_name));
	      if (item->contact->assistant_phone != NULL)
		fprintf(f->output, "TEL:%s\\n", rfc2426_escape(item->contact->assistant_phone));
	      fprintf(f->output, "END:VCARD\\n\n");
	    }
	    if (item->contact->company_name != NULL)
	      fprintf(f->output, "ORG:%s\n", rfc2426_escape(item->contact->company_name));
	    if (item->comment != NULL)
	      fprintf(f->output, "NOTE:%s\n", rfc2426_escape(item->comment));

	    fprintf(f->output, "VERSION: 3.0\n");
	    fprintf(f->output, "END:VCARD\n\n");
	  } else {
	    fprintf(f->output, "%s <%s>\n", item->contact->fullname, item->contact->address1);
	  }
	}
	// }}}2
      } else if (item->email != NULL &&
		 (item->type == PST_TYPE_NOTE || item->type == PST_TYPE_REPORT)) {
	// Process Email item {{{2

	f->email_count++;

	// convert the sent date if it exists, or set it to a fixed date
	if (item->email->sent_date != NULL) {
	  em_time = fileTimeToUnixTime(item->email->sent_date, 0);
	  c_time = ctime(&em_time);
	  if (c_time != NULL)
	    c_time[strlen(c_time)-1] = '\0'; //remove end \n
	  else
	    c_time = (char *)"Fri Dec 28 12:06:21 2001";
	} else
	  c_time= (char *)"Fri Dec 28 12:06:21 2001";

	// if the boundary is still set from the previous run, then free it
	if (boundary != NULL) {
	  free (boundary);
	  boundary = NULL;
	}

	// we will always look at the header to discover some stuff
	if (item->email->header != NULL ) {
	  // see if there is a boundary variable there
	  // this search MUST be made case insensitive (DONE).
	  // Also, some check to find out if we
	  // are looking at the boundary associated with content-type, and that the content
	  // type really is "multipart"
	  if ((b2 = my_stristr(item->email->header, "boundary=")) != NULL) {
	    b2 += strlen("boundary="); // move boundary to first char of marker

	    if (*b2 == '"') {
	      b2++;
	      b1 = strchr(b2, '"'); // find terminating quote
	    } else {
	      b1 = b2;
	      while (isgraph(*b1)) // find first char that isn't part of boundary
		b1++;
	    }

	    boundary = cli_calloc (1, (b1-b2)+1); //malloc that length
	    strncpy(boundary, b2, b1-b2); // copy boundary to another variable
	    b1 = b2 = boundary;
	    while (*b2 != '\0') { // remove any CRs and Tabs
	      if (*b2 != '\n' && *b2 != '\r' && *b2 != '\t') {
		*b1 = *b2;
		b1++;
	      }
	      b2++;
	    }
	    *b1 = '\0';

	  } else {
	    cli_errmsg("main: boundary not found in header\n");
	  }

	  // also possible to set 7bit encoding detection here.
	  if ((b2 = my_stristr(item->email->header, "Content-Transfer-Encoding:")) != NULL) {
	    if ((b2 = strchr(b2, ':')) != NULL) {
	      b2++; // skip to the : at the end of the string

	      while (*b2 == ' ' || *b2 == '\t')
		b2++;
	      if (strncasecmp(b2, "base64", 6)==0) {
		cli_dbgmsg("body is base64 encoded\n");
		base64_body = 1;
	      }
	    } else {
	      cli_errmsg("found a ':' during the my_stristr, but not after that..\n");
	    }
	  }

	}
	if (boundary == NULL && (item->attach ||(item->email->body && item->email->htmlbody)
				 || item->email->rtf_compressed || item->email->encrypted_body
				 || item->email->encrypted_htmlbody)) {
	  // we need to create a boundary here.
	  boundary = cli_malloc(50 * sizeof(char)); // allow 50 chars for boundary
	  sprintf(boundary, "--boundary-LibPST-iamunique-%i_-_-", rand());
	}

	if (item->email->header != NULL) {
	    char *soh = NULL;  // real start of headers.
	  // some of the headers we get from the file are not properly defined.
	  // they can contain some email stuff too. We will cut off the header
	  // when we see a \n\n or \r\n\r\n

	  removeCR(item->email->header);

	  temp = strstr(item->email->header, "\n\n");

	  if (temp != NULL) {
	    temp += 2; // get past the \n\n
	    *temp = '\0';
	  }

	    // don't put rubbish in if we are doing seperate
	    fprintf(f->output, "From \"%s\" %s\n", item->email->outlook_sender_name, c_time);
	    soh = skip_header_prologue(item->email->header);
	    fprintf(f->output, "%s\n\n", soh);
	} else {
	  //make up our own header!
	    // don't want this first line for this mode
	    if (item->email->outlook_sender_name != NULL) {
	      temp = item->email->outlook_sender_name;
	    } else {
	      temp = (char *)"(readpst_null)";
	    }
	    fprintf(f->output, "From \"%s\" %s\n", temp, c_time);
	  if ((temp = item->email->outlook_sender) == NULL)
	    temp = (char *)"";
	  fprintf(f->output, "From: \"%s\" <%s>\n", item->email->outlook_sender_name, temp);
	  if (item->email->subject != NULL) {
	    fprintf(f->output, "Subject: %s\n", item->email->subject->subj);
	  } else {
	    fprintf(f->output, "Subject: \n");
	  }
	  fprintf(f->output, "To: %s\n", item->email->sentto_address);
	  if (item->email->cc_address != NULL) {
	    fprintf(f->output, "CC: %s\n", item->email->cc_address);
	  }
	  if (item->email->sent_date != NULL) {
	    c_time = (char*) cli_malloc(C_TIME_SIZE);
	    strftime(c_time, C_TIME_SIZE, "%a, %d %b %Y %H:%M:%S %z", gmtime(&em_time));
	    fprintf(f->output, "Date: %s\n", c_time);
	    free(c_time);
	  }

	  fprintf(f->output, "MIME-Version: 1.0\n");
	  if (item->attach != NULL) {
	    // write the boundary stuff if we have attachments
	    fprintf(f->output, "Content-type: multipart/mixed;\n\tboundary=\"%s\"\n",
		    boundary);
	  } else if (item->email->htmlbody && item->email->body) {
	    // else if we have an html and text body then tell it so
	    fprintf(f->output, "Content-type: multipart/alternate;\n\tboundary=\"%s\"\n",
		    boundary);
	  } else if (item->email->htmlbody) {
	    fprintf(f->output, "Content-type: text/html\n");
	  }
	  fprintf(f->output, "\n");
	}


	if (item->email->body != NULL) {
	  if (boundary) {
	    fprintf(f->output, "\n--%s\n", boundary);
	    fprintf(f->output, "Content-type: text/plain\n\n");
	    if (base64_body)
	      fprintf(f->output, "Content-Transfer-Encoding: base64\n");
	  }
	  removeCR(item->email->body);
	  if (base64_body)
	    write_email_body(f->output, base64_encode((const unsigned char *)item->email->body,
						      strlen(item->email->body)));
	  else
	    write_email_body(f->output, item->email->body);
	}

	if (item->email->htmlbody != NULL) {
	  if (boundary) {
	    fprintf(f->output, "\n--%s\n", boundary);
	    fprintf(f->output, "Content-type: text/html\n\n");
	    if (base64_body)
	      fprintf(f->output, "Content-Transfer-Encoding: base64\n");
	  }
	  removeCR(item->email->htmlbody);
	  if (base64_body)
	    write_email_body(f->output, base64_encode((const unsigned char *)item->email->htmlbody,
						      strlen(item->email->htmlbody)));
	  else
	    write_email_body(f->output, item->email->htmlbody);
	}

	attach_num = 0;

	if (item->email->rtf_compressed != NULL) {
		size_t nbytes;
	  item->current_attach = (pst_item_attach*)cli_calloc(1, sizeof(pst_item_attach));
	  item->current_attach->next = item->attach;
	  item->attach = item->current_attach;
	  item->current_attach->data = (char *)lzfu_decompress((const unsigned char *)item->email->rtf_compressed, &nbytes);
	  item->current_attach->filename2 = strdup(RTF_ATTACH_NAME);
	  item->current_attach->mimetype = strdup(RTF_ATTACH_TYPE);
	  /*memcpy(&(item->current_attach->size), item->email->rtf_compressed+sizeof(int32_t), sizeof(int32_t));
	  LE32_CPU(item->current_attach->size);*/
	  item->current_attach->size = nbytes;
	  //	  item->email->rtf_compressed = ;
	  //	  attach_num++;
	}
	if (item->email->encrypted_body || item->email->encrypted_htmlbody) {
	  // if either the body or htmlbody is encrypted, add them as attachments
	  if (item->email->encrypted_body) {
	    item->current_attach = (pst_item_attach*) cli_calloc(1, sizeof(pst_item_attach));
	    item->current_attach->next = item->attach;
	    item->attach = item->current_attach;

	    item->current_attach->data = item->email->encrypted_body;
	    item->current_attach->size = item->email->encrypted_body_size;
	    item->email->encrypted_body = NULL;
	  }
	  if (item->email->encrypted_htmlbody) {
	    item->current_attach = (pst_item_attach*) cli_calloc(1, sizeof(pst_item_attach));
	    item->current_attach->next = item->attach;
	    item->attach = item->current_attach;

	    item->current_attach->data = item->email->encrypted_htmlbody;
	    item->current_attach->size = item->email->encrypted_htmlbody_size;
	    item->email->encrypted_htmlbody = NULL;
	  }
	  write_email_body(f->output, "The body of this email is encrypted. This isn't supported yet, but the body is now an attachment\n");
	}
	base64_body = 0;
	// attachments
	item->current_attach = item->attach;
	while (item->current_attach != NULL) {
	  if (item->current_attach->data == NULL) {
	    cli_dbgmsg("main: Data of attachment is NULL!. Size is supposed to be %i\n", item->current_attach->size);
	  }
	    if (item->current_attach->data != NULL) {
	      if ((enc = base64_encode ((const unsigned char *)item->current_attach->data, item->current_attach->size)) == NULL) {
		cli_errmsg("main: ERROR base64_encode returned NULL. Must have failed\n");
		item->current_attach = item->current_attach->next;
		continue;
	      }
	    }
	    if (boundary) {
	      fprintf(f->output, "\n--%s\n", boundary);
	      if (item->current_attach->mimetype == NULL) {
		fprintf(f->output, "Content-type: %s\n", MIME_TYPE_DEFAULT);
	      } else {
		fprintf(f->output, "Content-type: %s\n", item->current_attach->mimetype);
	      }
	      fprintf(f->output, "Content-transfer-encoding: base64\n");
	      if (item->current_attach->filename2 == NULL) {
		fprintf(f->output, "Content-Disposition: inline\n\n");
	      } else {
		fprintf(f->output, "Content-Disposition: attachment; filename=\"%s\"\n\n",
			item->current_attach->filename2);
	      }
	    }
	    if (item->current_attach->data != NULL) {
		fputs(enc, f->output);
		free(enc);
	    } else
	      pst_attach_to_file_base64(&pstfile, item->current_attach, f->output);
	    fprintf(f->output, "\n\n");
	  item->current_attach = item->current_attach->next;
	  attach_num++;
	}
	  if (boundary)
	    fprintf(f->output, "\n--%s--\n", boundary);
	  fprintf(f->output, "\n\n");
	// }}}2
      } else if (item->type == PST_TYPE_JOURNAL) {
	// Process Journal item {{{2
	// deal with journal items
	f->email_count++;

	cli_dbgmsg("main: Processing Journal Entry\n");
	if (f->type != PST_TYPE_JOURNAL) {
	  cli_dbgmsg("main: I have a journal entry, but folder isn't specified as a journal type. Processing...\n");
	}

	/*	if (item->type != PST_TYPE_JOURNAL) {
	  printf("main: I have an item with journal info, but it's type is \"%s\" \n. Processing...\n",
		      item->ascii_type));
	}*/
	fprintf(f->output, "BEGIN:VJOURNAL\n");
	if (item->email->subject != NULL)
	  fprintf(f->output, "SUMMARY:%s\n", rfc2426_escape(item->email->subject->subj));
	if (item->email->body != NULL)
	  fprintf(f->output, "DESCRIPTION:%s\n", rfc2426_escape(item->email->body));
	if (item->journal->start != NULL)
	  fprintf(f->output, "DTSTART;VALUE=DATE-TIME:%s\n", rfc2445_datetime_format(item->journal->start));
	fprintf(f->output, "END:VJOURNAL\n\n");
	// }}}2
      } else if (item->type == PST_TYPE_APPOINTMENT) {
	// Process Calendar Appointment item {{{2
	// deal with Calendar appointments
	f->email_count++;

	fprintf(f->output, "BEGIN:VEVENT\n");
	if (item->create_date != NULL)
	  fprintf(f->output, "CREATED:%s\n", rfc2445_datetime_format(item->create_date));
	if (item->modify_date != NULL)
	  fprintf(f->output, "LAST-MOD:%s\n", rfc2445_datetime_format(item->modify_date));
	if (item->email != NULL && item->email->subject != NULL)
	  fprintf(f->output, "SUMMARY:%s\n", rfc2426_escape(item->email->subject->subj));
	if (item->email != NULL && item->email->body != NULL)
	  fprintf(f->output, "DESCRIPTION:%s\n", rfc2426_escape(item->email->body));
	if (item->appointment != NULL && item->appointment->start != NULL)
	  fprintf(f->output, "DTSTART;VALUE=DATE-TIME:%s\n", rfc2445_datetime_format(item->appointment->start));
	if (item->appointment != NULL && item->appointment->end != NULL)
	  fprintf(f->output, "DTEND;VALUE=DATE-TIME:%s\n", rfc2445_datetime_format(item->appointment->end));
	if (item->appointment != NULL && item->appointment->location != NULL)
	  fprintf(f->output, "LOCATION:%s\n", rfc2426_escape(item->appointment->location));
	if (item->appointment != NULL) {
	  switch (item->appointment->showas) {
	  case PST_FREEBUSY_TENTATIVE:
	    fprintf(f->output, "STATUS:TENTATIVE\n");
	    break;
	  case PST_FREEBUSY_FREE:
	    // mark as transparent and as confirmed
	    fprintf(f->output, "TRANSP:TRANSPARENT\n");
	  case PST_FREEBUSY_BUSY:
	  case PST_FREEBUSY_OUT_OF_OFFICE:
	    fprintf(f->output, "STATUS:CONFIRMED\n");
	    break;
	  }
	  switch (item->appointment->label) {
	  case PST_APP_LABEL_NONE:
	    fprintf(f->output, "CATEGORIES:NONE\n"); break;
	  case PST_APP_LABEL_IMPORTANT:
	    fprintf(f->output, "CATEGORIES:IMPORTANT\n"); break;
	  case PST_APP_LABEL_BUSINESS:
	    fprintf(f->output, "CATEGORIES:BUSINESS\n"); break;
	  case PST_APP_LABEL_PERSONAL:
	    fprintf(f->output, "CATEGORIES:PERSONAL\n"); break;
	  case PST_APP_LABEL_VACATION:
	    fprintf(f->output, "CATEGORIES:VACATION\n"); break;
	  case PST_APP_LABEL_MUST_ATTEND:
	    fprintf(f->output, "CATEGORIES:MUST-ATTEND\n"); break;
	  case PST_APP_LABEL_TRAVEL_REQ:
	    fprintf(f->output, "CATEGORIES:TRAVEL-REQUIRED\n"); break;
	  case PST_APP_LABEL_NEEDS_PREP:
	    fprintf(f->output, "CATEGORIES:NEEDS-PREPARATION\n"); break;
	  case PST_APP_LABEL_BIRTHDAY:
	    fprintf(f->output, "CATEGORIES:BIRTHDAY\n"); break;
	  case PST_APP_LABEL_ANNIVERSARY:
	    fprintf(f->output, "CATEGORIES:ANNIVERSARY\n"); break;
	  case PST_APP_LABEL_PHONE_CALL:
	    fprintf(f->output, "CATEGORIES:PHONE-CALL\n"); break;
	  }
	}
	fprintf(f->output, "END:VEVENT\n\n");
	// }}}2
      } else {
	f->skip_count++;
	cli_errmsg("main: Unknown item type. %i. Ascii1=\"%s\"\n",
		   item->type, item->ascii_type);
      }
    } else {
      f->skip_count++;
      cli_errmsg("main: A NULL item was seen\n");
    }

    if (boundary) {
      free(boundary);
      boundary = NULL;
    }

  check_parent:
    //    _pst_freeItem(item);
    while (!skip_child && d_ptr->next == NULL && d_ptr->parent != NULL) {
      head = f->next;
      if (f->output != NULL)
	fclose(f->output);
      free(f->name);
      free(f->dname);
      free(f);
      f = head;
      if (head == NULL) { //we can't go higher. Must be at start?
	break; //from main while loop
      }
      d_ptr = d_ptr->parent;
      skip_child = 0;
    }

    if (item != NULL) {
      _pst_freeItem(item);
      item = NULL;
    }

    if (!skip_child)
      d_ptr = d_ptr->next;
    else
      skip_child = 0;

  }

	//  fclose(pstfile.fp);
	while (f != NULL) {
		if (f->output != NULL)
			fclose(f->output);
		free(f->name);
		free(f->dname);

		head = f->next;
		free (f);
		f = head;
	}

	return pst_close(&pstfile);
}
