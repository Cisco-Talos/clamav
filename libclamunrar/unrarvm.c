/*
 *  Extract RAR archives
 *
 *  Copyright (C) 2005-2006 trog@uncon.org
 *
 *  This code is based on the work of Alexander L. Roshal (C)
 *
 *  The unRAR sources may be used in any software to handle RAR
 *  archives without limitations free of charge, but cannot be used
 *  to re-create the RAR compression algorithm, which is proprietary.
 *  Distribution of modified unRAR sources in separate form or as a
 *  part of other software is permitted, provided that it is clearly
 *  stated in the documentation and source comments that the code may
 *  not be used to develop a RAR (WinRAR) compatible archiver.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <string.h>

#include "unrar.h"
#include "unrarvm.h"
#include "unrarcmd.h"
#include "others.h"

#ifdef RAR_HIGH_DEBUG
#define rar_dbgmsg printf
#else
static void rar_dbgmsg(){};
#endif

#define VMCF_OP0             0
#define VMCF_OP1             1
#define VMCF_OP2             2
#define VMCF_OPMASK          3
#define VMCF_BYTEMODE        4
#define VMCF_JUMP            8
#define VMCF_PROC           16
#define VMCF_USEFLAGS       32
#define VMCF_CHFLAGS        64

static uint8_t vm_cmdflags[]=
{
  /* VM_MOV   */ VMCF_OP2 | VMCF_BYTEMODE                                ,
  /* VM_CMP   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_ADD   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_SUB   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_JZ    */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JNZ   */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_INC   */ VMCF_OP1 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_DEC   */ VMCF_OP1 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_JMP   */ VMCF_OP1 | VMCF_JUMP                                    ,
  /* VM_XOR   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_AND   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_OR    */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_TEST  */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_JS    */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JNS   */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JB    */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JBE   */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JA    */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JAE   */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_PUSH  */ VMCF_OP1                                                ,
  /* VM_POP   */ VMCF_OP1                                                ,
  /* VM_CALL  */ VMCF_OP1 | VMCF_PROC                                    ,
  /* VM_RET   */ VMCF_OP0 | VMCF_PROC                                    ,
  /* VM_NOT   */ VMCF_OP1 | VMCF_BYTEMODE                                ,
  /* VM_SHL   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_SHR   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_SAR   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_NEG   */ VMCF_OP1 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_PUSHA */ VMCF_OP0                                                ,
  /* VM_POPA  */ VMCF_OP0                                                ,
  /* VM_PUSHF */ VMCF_OP0 | VMCF_USEFLAGS                                ,
  /* VM_POPF  */ VMCF_OP0 | VMCF_CHFLAGS                                 ,
  /* VM_MOVZX */ VMCF_OP2                                                ,
  /* VM_MOVSX */ VMCF_OP2                                                ,
  /* VM_XCHG  */ VMCF_OP2 | VMCF_BYTEMODE                                ,
  /* VM_MUL   */ VMCF_OP2 | VMCF_BYTEMODE                                ,
  /* VM_DIV   */ VMCF_OP2 | VMCF_BYTEMODE                                ,
  /* VM_ADC   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_USEFLAGS | VMCF_CHFLAGS ,
  /* VM_SBB   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_USEFLAGS | VMCF_CHFLAGS ,
  /* VM_PRINT */ VMCF_OP0
};

#define UINT32(x)  (sizeof(uint32_t)==4 ? (uint32_t)(x):((x)&0xffffffff))

static unsigned int rarvm_get_value(int byte_mode, unsigned int *addr)
{
	if (byte_mode) {
		return *addr;
	} else {
#if WORDS_BIGENDIAN == 0
		return UINT32(*addr);
#else
                unsigned char *B = (unsigned char *)addr;
                return UINT32((uint8_t)B[0]|((uint8_t)B[1]<<8)|((uint8_t)B[2]<<16)|((uint8_t)B[3]<<24));
#endif
	}
}

#if WORDS_BIGENDIAN == 0
#define GET_VALUE(byte_mode,addr) ((byte_mode) ? (*(unsigned char *)(addr)) : UINT32((*(unsigned int *)(addr))))
#else
#define GET_VALUE(byte_mode,addr) rarvm_get_value(byte_mode, (unsigned int *)addr)
#endif

void rarvm_set_value(int byte_mode, unsigned int *addr, unsigned int value)
{
	if (byte_mode) {
		*(unsigned char *)addr=value;
	} else {
#if WORDS_BIGENDIAN == 0
		*(uint32_t *)addr = value;
#else
		((unsigned char *)addr)[0]=(unsigned char)value;
		((unsigned char *)addr)[1]=(unsigned char)(value>>8);
		((unsigned char *)addr)[2]=(unsigned char)(value>>16);
		((unsigned char *)addr)[3]=(unsigned char)(value>>24);
#endif
	}
}

		
#if WORDS_BIGENDIAN == 0
#define SET_VALUE(byte_mode,addr,value) ((byte_mode) ? (*(unsigned char *)(addr)=(value)):(*(uint32_t *)(addr)=((uint32_t)(value))))
#else
#define SET_VALUE(byte_mode,addr,value) rarvm_set_value(byte_mode, (unsigned int *)addr, value);
#endif

uint32_t crc_tab[256];

static void rar_crc_init()
{
	int i, j;
	unsigned int c;
	
	for (i=0 ; i < 256 ; i++) {
		c = i;
		for (j = 0 ; j < 8 ; j++) {
			c = (c & 1) ? (c >> 1) ^ 0xedb88320L : (c>>1);
		}
		crc_tab[i] = c;
	}
}

uint32_t rar_crc(uint32_t start_crc, void *addr, uint32_t size)
{
	unsigned char *data;
	int i;

	data = addr;
#if WORDS_BIGENDIAN == 0
	while (size > 0 && ((int)data & 7))
	{
		start_crc = crc_tab[(unsigned char)(start_crc^data[0])]^(start_crc>>8);
		size--;
		data++;
	}
	while (size >= 8)
	{
		start_crc ^= *(uint32_t *) data;
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc ^= *(uint32_t *)(data+4);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		data += 8;
		size -= 8;
	}
#endif
	for (i=0 ; i < size ; i++) {
		start_crc = crc_tab[(unsigned char)(start_crc^data[i])]^(start_crc >> 8);
	}
	return start_crc;
}

int rarvm_init(rarvm_data_t *rarvm_data)
{
	rarvm_data->mem = (uint8_t *) cli_malloc(RARVM_MEMSIZE+4);
	rar_crc_init();
	if (!rarvm_data->mem) {
		return FALSE;
	}
	return TRUE;
}

void rarvm_free(rarvm_data_t *rarvm_data)
{
	if (rarvm_data && rarvm_data->mem) {
		free(rarvm_data->mem);
		rarvm_data->mem = NULL;
	}
}

void rarvm_addbits(rarvm_input_t *rarvm_input, int bits)
{
	bits += rarvm_input->in_bit;
	rarvm_input->in_addr += bits >> 3;
	rarvm_input->in_bit = bits & 7;
}

unsigned int rarvm_getbits(rarvm_input_t *rarvm_input)
{
	unsigned int bit_field;

	bit_field = (unsigned int) rarvm_input->in_buf[rarvm_input->in_addr] << 16;
	bit_field |= (unsigned int) rarvm_input->in_buf[rarvm_input->in_addr+1] << 8;
	bit_field |= (unsigned int) rarvm_input->in_buf[rarvm_input->in_addr+2];
	bit_field >>= (8-rarvm_input->in_bit);

	return (bit_field & 0xffff);
}

unsigned int rarvm_read_data(rarvm_input_t *rarvm_input)
{
	unsigned int data;
	
	data = rarvm_getbits(rarvm_input);
	rar_dbgmsg("rarvm_read_data getbits=%u\n", data);
	switch (data & 0xc000) {
	case 0:
		rarvm_addbits(rarvm_input,6);
		rar_dbgmsg("rarvm_read_data=%u\n", ((data>>10)&0x0f));
		return ((data>>10)&0x0f);
	case 0x4000:
		if ((data & 0x3c00) == 0) {
			data = 0xffffff00 | ((data>>2) & 0xff);
			rarvm_addbits(rarvm_input,14);
		} else {
			data = (data >> 6) &0xff;
			rarvm_addbits(rarvm_input,10);
		}
		rar_dbgmsg("rarvm_read_data=%u\n", data);
		return data;
	case 0x8000:
		rarvm_addbits(rarvm_input,2);
		data = rarvm_getbits(rarvm_input);
		rarvm_addbits(rarvm_input,16);
		rar_dbgmsg("rarvm_read_data=%u\n", data);
		return data;
	default:
		rarvm_addbits(rarvm_input,2);
		data = (rarvm_getbits(rarvm_input) << 16);
		rarvm_addbits(rarvm_input,16);
		data |= rarvm_getbits(rarvm_input);
		rarvm_addbits(rarvm_input,16);
		rar_dbgmsg("rarvm_read_data=%u\n", data);
		return data;
	}
}

static rarvm_standard_filters_t is_standard_filter(unsigned char *code, int code_size)
{
	uint32_t code_crc;
	int i;

	struct standard_filter_signature
	{
		int length;
		uint32_t crc;
		rarvm_standard_filters_t type;
	} std_filt_list[] = {
		{53,  0xad576887, VMSF_E8},
		{57,  0x3cd7e57e, VMSF_E8E9},
		{120, 0x3769893f, VMSF_ITANIUM},
		{29,  0x0e06077d, VMSF_DELTA},
		{149, 0x1c2c5dc8, VMSF_RGB},
 		{216, 0xbc85e701, VMSF_AUDIO},
		{40,  0x46b9c560, VMSF_UPCASE}
	};
	
	code_crc = rar_crc(0xffffffff, code, code_size)^0xffffffff;
	rar_dbgmsg("code_crc=%u\n", code_crc);
	for (i=0 ; i<sizeof(std_filt_list)/sizeof(std_filt_list[0]) ; i++) {
		if (std_filt_list[i].crc == code_crc && std_filt_list[i].length == code_size) {
			return std_filt_list[i].type;
		}
	}
	return VMSF_NONE;
}

void rarvm_set_memory(rarvm_data_t *rarvm_data, unsigned int pos, uint8_t *data, unsigned int data_size)
{
	if (pos<RARVM_MEMSIZE && data!=rarvm_data->mem+pos) {
		memmove(rarvm_data->mem+pos, data, MIN(data_size, RARVM_MEMSIZE-pos));
	}
}

static unsigned int *rarvm_get_operand(rarvm_data_t *rarvm_data,
				struct rarvm_prepared_operand *cmd_op)
{
	if (cmd_op->type == VM_OPREGMEM) {
		return ((unsigned int *)&rarvm_data->mem[(*cmd_op->addr+cmd_op->base) & RARVM_MEMMASK]);
	} else {
		return cmd_op->addr;
	}
}

static unsigned int filter_itanium_getbits(unsigned char *data, int bit_pos, int bit_count)
{
	int in_addr=bit_pos/8;
	int in_bit=bit_pos&7;
	unsigned int bit_field=(unsigned int)data[in_addr++];
	bit_field|=(unsigned int)data[in_addr++] << 8;
	bit_field|=(unsigned int)data[in_addr++] << 16;
	bit_field|=(unsigned int)data[in_addr] << 24;
	bit_field >>= in_bit;
	return(bit_field & (0xffffffff>>(32-bit_count)));
}

static void filter_itanium_setbits(unsigned char *data, unsigned int bit_field, int bit_pos, int bit_count)
{
	int i, in_addr=bit_pos/8;
	int in_bit=bit_pos&7;
	unsigned int and_mask=0xffffffff>>(32-bit_count);
	and_mask=~(and_mask<<in_bit);

	bit_field<<=in_bit;

	for (i=0 ; i<4 ; i++) {
		data[in_addr+i]&=and_mask;
		data[in_addr+i]|=bit_field;
		and_mask=(and_mask>>8)|0xff000000;
		bit_field>>=8;
	}
}

static void execute_standard_filter(rarvm_data_t *rarvm_data, rarvm_standard_filters_t filter_type)
{
	unsigned char *data, cmp_byte2, cur_byte, *src_data, *dest_data;
	int i, j, data_size, channels, src_pos, dest_pos, border, width, PosR;
	int op_type, cur_channel, byte_count, start_pos, pa, pb, pc;
	unsigned int file_offset, cur_pos, predicted;
	int32_t offset, addr;
	const int file_size=0x1000000;

	switch(filter_type) {
	case VMSF_E8:
	case VMSF_E8E9:
		data=rarvm_data->mem;
		data_size = rarvm_data->R[4];
		file_offset = rarvm_data->R[6];

		if ((data_size >= VM_GLOBALMEMADDR) || (data_size < 4)) {
			break;
		}

		cmp_byte2 = filter_type==VMSF_E8E9 ? 0xe9:0xe8;
		for (cur_pos = 0 ; cur_pos < data_size-4 ; ) {
			cur_byte = *(data++);
			cur_pos++;
			if (cur_byte==0xe8 || cur_byte==cmp_byte2) {
				offset = cur_pos+file_offset;
				addr = GET_VALUE(FALSE, data);
				if (addr < 0) {
					if (addr+offset >=0 ) {
						SET_VALUE(FALSE, data, addr+file_size);
					}
				} else {
					if (addr<file_size) {
						SET_VALUE(FALSE, data, addr-offset);
					}
				}
				data += 4;
				cur_pos += 4;
			}
		}
		break;
	case VMSF_ITANIUM:
		data=rarvm_data->mem;
		data_size = rarvm_data->R[4];
		file_offset = rarvm_data->R[6];
		
		if ((data_size >= VM_GLOBALMEMADDR) || (data_size < 21)) {
			break;
		}
		
		cur_pos = 0;
		
		file_offset>>=4;
		
		while (cur_pos < data_size-21) {
			int Byte = (data[0] & 0x1f) - 0x10;
			if (Byte >= 0) {
				static unsigned char masks[16]={4,4,6,6,0,0,7,7,4,4,0,0,4,4,0,0};
				unsigned char cmd_mask = masks[Byte];
				
				if (cmd_mask != 0) {
					for (i=0 ; i <= 2 ; i++) {
						if (cmd_mask & (1<<i)) {
							start_pos = i*41+5;
							op_type = filter_itanium_getbits(data,
									start_pos+37, 4);
							if (op_type == 5) {
								offset = filter_itanium_getbits(data,
										start_pos+13, 20);
								filter_itanium_setbits(data,
									(offset-file_offset)
									&0xfffff,start_pos+13,20);
							}
						}
					}
				}
			}
			data += 16;
			cur_pos += 16;
			file_offset++;
		}
		break;
	case VMSF_DELTA:
		data_size = rarvm_data->R[4];
		channels = rarvm_data->R[0];
		src_pos = 0;
		border = data_size*2;
		
		SET_VALUE(FALSE, &rarvm_data->mem[VM_GLOBALMEMADDR+0x20], data_size);
		if (data_size >= VM_GLOBALMEMADDR/2) {
			break;
		}
		for (cur_channel=0 ; cur_channel < channels ; cur_channel++) {
			unsigned char prev_byte = 0;
			for (dest_pos=data_size+cur_channel ; dest_pos<border ; dest_pos+=channels) {
				rarvm_data->mem[dest_pos] = (prev_byte -= rarvm_data->mem[src_pos++]);
			}
		}
		break;
	case VMSF_RGB: {
		const int channels=3;
		data_size = rarvm_data->R[4];
		width = rarvm_data->R[0] - 3;
		PosR = rarvm_data->R[1];
		src_data = rarvm_data->mem;
		dest_data = src_data + data_size;
		
		SET_VALUE(FALSE, &rarvm_data->mem[VM_GLOBALMEMADDR+0x20], data_size);
		if (data_size >= VM_GLOBALMEMADDR/2) {
			break;
		}
		for (cur_channel=0 ; cur_channel < channels; cur_channel++) {
			unsigned int prev_byte = 0;
			for (i=cur_channel ; i<data_size ; i+=channels) {
				int upper_pos=i-width;
				if (upper_pos >= 3) {
					unsigned char *upper_data = dest_data+upper_pos;
					unsigned int upper_byte = *upper_data;
					unsigned int upper_left_byte = *(upper_data-3);
					predicted = prev_byte+upper_byte-upper_left_byte;
					pa = abs((int)(predicted-prev_byte));
					pb = abs((int)(predicted-upper_byte));
					pc = abs((int)(predicted-upper_left_byte));
					if (pa <= pb && pa <= pc) {
						predicted = prev_byte;
					} else {
						if (pb <= pc) {
							predicted = upper_byte;
						} else {
							predicted = upper_left_byte;
						}
					}
				} else {
					predicted = prev_byte;
				}
				dest_data[i] = prev_byte = (unsigned char)(predicted-*(src_data++));
			}
		}
		for (i=PosR,border=data_size-2 ; i < border ; i+=3) {
			unsigned char g=dest_data[i+1];
			dest_data[i] += g;
			dest_data[i+2] += g;
		}
		break;
	}
	case VMSF_AUDIO: {
		int channels=rarvm_data->R[0];
		data_size = rarvm_data->R[4];
		src_data = rarvm_data->mem;
		dest_data = src_data + data_size;
		
		SET_VALUE(FALSE, &rarvm_data->mem[VM_GLOBALMEMADDR+0x20], data_size);
		if (data_size >= VM_GLOBALMEMADDR/2) {
			break;
		}
		for (cur_channel=0 ; cur_channel < channels ; cur_channel++) {
			unsigned int prev_byte = 0, prev_delta=0, Dif[7];
			int D, D1=0, D2=0, D3=0, K1=0, K2=0, K3=0;
			
			memset(Dif, 0, sizeof(Dif));
			
			for (i=cur_channel, byte_count=0 ; i<data_size ; i+=channels, byte_count++) {
				D3=D2;
				D2 = prev_delta-D1;
				D1 = prev_delta;
				
				predicted = 8*prev_byte+K1*D1+K2*D2+K3*D3;
				predicted = (predicted>>3) & 0xff;
				
				cur_byte = *(src_data++);
				
				predicted -= cur_byte;
				dest_data[i] = predicted;
				prev_delta = (signed char)(predicted-prev_byte);
				prev_byte = predicted;
				
				D=((signed char)cur_byte) << 3;
				
				Dif[0] += abs(D);
				Dif[1] += abs(D-D1);
				Dif[2] += abs(D+D1);
				Dif[3] += abs(D-D2);
				Dif[4] += abs(D+D2);
				Dif[5] += abs(D-D3);
				Dif[6] += abs(D+D3);
				
				if ((byte_count & 0x1f) == 0) {
					unsigned int min_dif=Dif[0], num_min_dif=0;
					Dif[0]=0;
					for (j=1 ; j<sizeof(Dif)/sizeof(Dif[0]) ; j++) {
						if (Dif[j] < min_dif) {
							min_dif = Dif[j];
							num_min_dif = j;
						}
						Dif[j]=0;
					}
					switch(num_min_dif) {
					case 1: if (K1>=-16) K1--; break;
					case 2: if (K1 < 16) K1++; break;
					case 3: if (K2>=-16) K2--; break;
					case 4: if (K2 < 16) K2++; break;
					case 5: if (K3>=-16) K3--; break;
					case 6: if (K3 < 16) K3++; break;
					}
				}
			}
		}
		break;
	}
	case VMSF_UPCASE:
		data_size = rarvm_data->R[4];
		src_pos = 0;
		dest_pos = data_size;
		if (data_size >= VM_GLOBALMEMADDR/2) {
			break;
		}
		while (src_pos < data_size) {
			cur_byte = rarvm_data->mem[src_pos++];
			if (cur_byte==2 && (cur_byte=rarvm_data->mem[src_pos++]) != 2) {
				cur_byte -= 32;
			}
			rarvm_data->mem[dest_pos++]=cur_byte;
		}
		SET_VALUE(FALSE, &rarvm_data->mem[VM_GLOBALMEMADDR+0x1c], dest_pos-data_size);
		SET_VALUE(FALSE, &rarvm_data->mem[VM_GLOBALMEMADDR+0x20], data_size);
		break;
	}
}
				
#define SET_IP(IP)                      \
  if ((IP)>=code_size)                   \
    return TRUE;                       \
  if (--max_ops<=0)                  \
    return FALSE;                      \
  cmd=prepared_code+(IP);

static int rarvm_execute_code(rarvm_data_t *rarvm_data,
		struct rarvm_prepared_command *prepared_code, int code_size)
{
	int max_ops=25000000, i, SP;
	struct rarvm_prepared_command *cmd;
	unsigned int value1, value2, result, divider, FC, *op1, *op2;
	const int reg_count=sizeof(rarvm_data->R)/sizeof(rarvm_data->R[0]);
	
	rar_dbgmsg("in rarvm_execute_code\n");
	cmd = prepared_code;
	while (1) {
		if (cmd > (prepared_code + code_size)) {
			cli_dbgmsg("RAR: code overrun detected\n");
			return FALSE;
		}
		if (cmd < prepared_code) {
			cli_dbgmsg("RAR: code underrun detected\n");
                        return FALSE;
                }
		op1 = rarvm_get_operand(rarvm_data, &cmd->op1);
		op2 = rarvm_get_operand(rarvm_data, &cmd->op2);
		rar_dbgmsg("op(%d) op_code: %d, op1=%u, op2=%u\n", 25000000-max_ops,
					cmd->op_code, op1, op2);
		switch(cmd->op_code) {
		case VM_MOV:
			SET_VALUE(cmd->byte_mode, op1, GET_VALUE(cmd->byte_mode, op2));
			break;
		case VM_MOVB:
			SET_VALUE(TRUE, op1, GET_VALUE(TRUE, op2));
			break;
		case VM_MOVD:
			SET_VALUE(FALSE, op1, GET_VALUE(FALSE, op2));
			break;
		case VM_CMP:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(value1 - GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : (result>value1)|(result&VM_FS);
			break;
		case VM_CMPB:
			value1 = GET_VALUE(TRUE, op1);
			result = UINT32(value1 - GET_VALUE(TRUE, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : (result>value1)|(result&VM_FS);
			break;
		case VM_CMPD:
			value1 = GET_VALUE(FALSE, op1);
			result = UINT32(value1 - GET_VALUE(FALSE, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : (result>value1)|(result&VM_FS);
			break;
		case VM_ADD:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(value1 + GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : (result<value1)|(result&VM_FS);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_ADDB:
			SET_VALUE(TRUE, op1, GET_VALUE(TRUE, op1)+GET_VALUE(TRUE, op2));
			break;
		case VM_ADDD:
			SET_VALUE(FALSE, op1, GET_VALUE(FALSE, op1)+GET_VALUE(FALSE, op2));
			break;
		case VM_SUB:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(value1 - GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : (result>value1)|(result&VM_FS);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_SUBB:
			SET_VALUE(TRUE, op1, GET_VALUE(TRUE, op1)-GET_VALUE(TRUE, op2));
			break;
		case VM_SUBD:
			SET_VALUE(FALSE, op1, GET_VALUE(FALSE, op1)-GET_VALUE(FALSE, op2));
			break;
		case VM_JZ:
			if ((rarvm_data->Flags & VM_FZ) != 0) {
				SET_IP(GET_VALUE(FALSE, op1));
				continue;
			}
			break;
		case VM_JNZ:
			if ((rarvm_data->Flags & VM_FZ) == 0) {
				SET_IP(GET_VALUE(FALSE, op1));
				continue;
			}
			break;
		case VM_INC:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)+1);
			SET_VALUE(cmd->byte_mode, op1, result);
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			break;
		case VM_INCB:
			SET_VALUE(TRUE, op1, GET_VALUE(TRUE, op1)+1);
			break;
		case VM_INCD:
			SET_VALUE(FALSE, op1, GET_VALUE(FALSE, op1)+1);
			break;
		case VM_DEC:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)-1);
			SET_VALUE(cmd->byte_mode, op1, result);
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			break;
		case VM_DECB:
			SET_VALUE(TRUE, op1, GET_VALUE(TRUE, op1)-1);
			break;
		case VM_DECD:
			SET_VALUE(FALSE, op1, GET_VALUE(FALSE, op1)-1);
			break;
		case VM_JMP:
			SET_IP(GET_VALUE(FALSE, op1));
			continue;
		case VM_XOR:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)^GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_AND:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)&GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_OR:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)|GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_TEST:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)&GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			break;
		case VM_JS:
			if ((rarvm_data->Flags & VM_FS) != 0) {
				SET_IP(GET_VALUE(FALSE, op1));
				continue;
			}
			break;
		case VM_JNS:
			if ((rarvm_data->Flags & VM_FS) == 0) {
				SET_IP(GET_VALUE(FALSE, op1));
				continue;
			}
			break;
		case VM_JB:
			if ((rarvm_data->Flags & VM_FC) != 0) {
				SET_IP(GET_VALUE(FALSE, op1));
				continue;
			}
			break;
		case VM_JBE:
			if ((rarvm_data->Flags & (VM_FC|VM_FZ)) != 0) {
				SET_IP(GET_VALUE(FALSE, op1));
				continue;
			}
			break;
		case VM_JA:
			if ((rarvm_data->Flags & (VM_FC|VM_FZ)) == 0) {
				SET_IP(GET_VALUE(FALSE, op1));
				continue;
			}
			break;
		case VM_JAE:
			if ((rarvm_data->Flags & VM_FC) == 0) {
				SET_IP(GET_VALUE(FALSE, op1));
				continue;
			}
			break;
		case VM_PUSH:
			rarvm_data->R[7] -= 4;
			SET_VALUE(FALSE, (unsigned int *)&rarvm_data->mem[rarvm_data->R[7] &
				RARVM_MEMMASK],	GET_VALUE(FALSE, op1));
			break;
		case VM_POP:
			SET_VALUE(FALSE, op1, GET_VALUE(FALSE,
				(unsigned int *)&rarvm_data->mem[rarvm_data->R[7] & RARVM_MEMMASK]));
			rarvm_data->R[7] += 4;
			break;
		case VM_CALL:
			rarvm_data->R[7] -= 4;
			SET_VALUE(FALSE, (unsigned int *)&rarvm_data->mem[rarvm_data->R[7] &
					RARVM_MEMMASK], cmd-prepared_code+1);
			SET_IP(GET_VALUE(FALSE, op1));
			continue;
		case VM_NOT:
			SET_VALUE(cmd->byte_mode, op1, ~GET_VALUE(cmd->byte_mode, op1));
			break;
		case VM_SHL:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			value2 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(value1 << value2);
			rarvm_data->Flags = (result==0 ? VM_FZ : (result&VM_FS))|
				((value1 << (value2-1))&0x80000000 ? VM_FC:0);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_SHR:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			value2 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(value1 >> value2);
			rarvm_data->Flags = (result==0 ? VM_FZ : (result&VM_FS))|
				((value1 >> (value2-1)) & VM_FC);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_SAR:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			value2 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(((int)value1) >> value2);
			rarvm_data->Flags = (result==0 ? VM_FZ : (result&VM_FS))|
				((value1 >> (value2-1)) & VM_FC);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_NEG:
			result = UINT32(-GET_VALUE(cmd->byte_mode, op1));
			rarvm_data->Flags = result==0 ? VM_FZ:VM_FC|(result&VM_FS);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_NEGB:
			SET_VALUE(TRUE, op1, -GET_VALUE(TRUE, op1));
			break;
		case VM_NEGD:
			SET_VALUE(FALSE, op1, -GET_VALUE(FALSE, op1));
			break;
		case VM_PUSHA:
			for (i=0, SP=rarvm_data->R[7]-4 ; i<reg_count ; i++, SP-=4) {
				SET_VALUE(FALSE,
					(unsigned int *)&rarvm_data->mem[SP & RARVM_MEMMASK],
					rarvm_data->R[i]);
			}
			rarvm_data->R[7] -= reg_count*4;
			break;
		case VM_POPA:
			for (i=0,SP=rarvm_data->R[7] ; i<reg_count ; i++, SP+=4) {
				rarvm_data->R[7-i] = GET_VALUE(FALSE,
					(unsigned int *)&rarvm_data->mem[SP & RARVM_MEMMASK]);
			}
			break;
		case VM_PUSHF:
			rarvm_data->R[7] -= 4;
			SET_VALUE(FALSE,
				(unsigned int *)&rarvm_data->mem[rarvm_data->R[7] & RARVM_MEMMASK],
				rarvm_data->Flags);
			break;
		case VM_POPF:
			rarvm_data->Flags = GET_VALUE(FALSE,
				(unsigned int *)&rarvm_data->mem[rarvm_data->R[7] & RARVM_MEMMASK]);
			rarvm_data->R[7] += 4;
			break;
		case VM_MOVZX:
			SET_VALUE(FALSE, op1, GET_VALUE(TRUE, op2));
			break;
		case VM_MOVSX:
			SET_VALUE(FALSE, op1, (signed char)GET_VALUE(TRUE, op2));
			break;
		case VM_XCHG:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			SET_VALUE(cmd->byte_mode, op1, GET_VALUE(cmd->byte_mode, op2));
			SET_VALUE(cmd->byte_mode, op2, value1);
			break;
		case VM_MUL:
			result = GET_VALUE(cmd->byte_mode, op1) * GET_VALUE(cmd->byte_mode, op2);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_DIV:
			divider = GET_VALUE(cmd->byte_mode, op2);
			if (divider != 0) {
				result = GET_VALUE(cmd->byte_mode, op1) / divider;
				SET_VALUE(cmd->byte_mode, op1, result);
			}
			break;
		case VM_ADC:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			FC = (rarvm_data->Flags & VM_FC);
			result = UINT32(value1+GET_VALUE(cmd->byte_mode, op2)+FC);
			rarvm_data->Flags = result==0 ? VM_FZ:(result<value1 ||
				(result==value1 && FC))|(result&VM_FS);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_SBB:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			FC = (rarvm_data->Flags & VM_FC);
			result = UINT32(value1-GET_VALUE(cmd->byte_mode, op2)-FC);
			rarvm_data->Flags = result==0 ? VM_FZ:(result>value1 ||
				(result==value1 && FC))|(result&VM_FS);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_RET:
			if (rarvm_data->R[7] >= RARVM_MEMSIZE) {
				return TRUE;
			}
			SET_IP(GET_VALUE(FALSE, (unsigned int *)&rarvm_data->mem[rarvm_data->R[7] &
				RARVM_MEMMASK]));
			rarvm_data->R[7] += 4;
			continue;
		case VM_STANDARD:
			execute_standard_filter(rarvm_data,
					(rarvm_standard_filters_t)cmd->op1.data);
			break;
		case VM_PRINT:
			/* DEBUG */
			break;
		}
		cmd++;
		--max_ops;
	}
}

int rarvm_execute(rarvm_data_t *rarvm_data, struct rarvm_prepared_program *prg)
{
	unsigned int global_size, static_size, new_pos, new_size, data_size;
	struct rarvm_prepared_command *prepared_code;
	
	rar_dbgmsg("in rarvm_execute\n");
	memcpy(rarvm_data->R, prg->init_r, sizeof(prg->init_r));
	global_size = MIN(prg->global_size, VM_GLOBALMEMSIZE);
	if (global_size) {
		memcpy(rarvm_data->mem+VM_GLOBALMEMADDR, &prg->global_data[0], global_size);
	}
	static_size = MIN(prg->static_size, VM_GLOBALMEMSIZE-global_size);
	if (static_size) {
		memcpy(rarvm_data->mem+VM_GLOBALMEMADDR+global_size,
				&prg->static_data[0], static_size);
	}
	
	rarvm_data->R[7] = RARVM_MEMSIZE;
	rarvm_data->Flags = 0;
	
	prepared_code=prg->alt_cmd ? prg->alt_cmd : &prg->cmd.array[0];
	if(!prepared_code) {
	    cli_dbgmsg("unrar: rarvm_execute: prepared_code == NULL\n");
	    return FALSE;
	}
	if (!rarvm_execute_code(rarvm_data, prepared_code, prg->cmd_count)) {
		prepared_code[0].op_code = VM_RET;
	}
	new_pos = GET_VALUE(FALSE, &rarvm_data->mem[VM_GLOBALMEMADDR+0x20])&RARVM_MEMMASK;
	new_size = GET_VALUE(FALSE, &rarvm_data->mem[VM_GLOBALMEMADDR+0x1c])&RARVM_MEMMASK;
	if (new_pos+new_size >= RARVM_MEMSIZE) {
		new_pos = new_size = 0;
	}
	prg->filtered_data = rarvm_data->mem + new_pos;
	prg->filtered_data_size = new_size;
	
	if (prg->global_data) {
		free(prg->global_data);
		prg->global_data = NULL;
		prg->global_size = 0;
	}
	data_size = MIN(GET_VALUE(FALSE,
		(unsigned int *)&rarvm_data->mem[VM_GLOBALMEMADDR+0x30]),VM_GLOBALMEMSIZE);
	if (data_size != 0) {
		prg->global_size += data_size+VM_FIXEDGLOBALSIZE;
		prg->global_data = cli_realloc2(prg->global_data, prg->global_size);
		if(!prg->global_data) {
		    cli_dbgmsg("unrar: rarvm_execute: cli_realloc2 failed for prg->global_data\n");
		    return FALSE;
		}
		memcpy(prg->global_data, &rarvm_data->mem[VM_GLOBALMEMADDR],
				data_size+VM_FIXEDGLOBALSIZE);
	}

	return TRUE;
}

void rarvm_decode_arg(rarvm_data_t *rarvm_data, rarvm_input_t *rarvm_input,
		struct rarvm_prepared_operand *op, int byte_mode)
{
	uint16_t data;
	
	data = rarvm_getbits(rarvm_input);
	if (data & 0x8000) {
		op->type = VM_OPREG;
		op->data = (data >> 12) & 7;
		op->addr = &rarvm_data->R[op->data];
		rarvm_addbits(rarvm_input,4);
	} else if ((data & 0xc000) == 0) {
		op->type = VM_OPINT;
		if (byte_mode) {
			op->data = (data>>6) & 0xff;
			rarvm_addbits(rarvm_input,10);
		} else {
			rarvm_addbits(rarvm_input,2);
			op->data = rarvm_read_data(rarvm_input);
		}
	} else {
		op->type = VM_OPREGMEM;
		if ((data & 0x2000) == 0) {
			op->data = (data >> 10) & 7;
			op->addr = &rarvm_data->R[op->data];
			op->base = 0;
			rarvm_addbits(rarvm_input,6);
		} else {
			if ((data & 0x1000) == 0) {
				op->data = (data >> 9) & 7;
				op->addr = &rarvm_data->R[op->data];
				rarvm_addbits(rarvm_input,7);
			} else {
				op->data = 0;
				rarvm_addbits(rarvm_input,4);
			}
			op->base = rarvm_read_data(rarvm_input);
		}
	}
}

void rarvm_optimize(struct rarvm_prepared_program *prg)
{
	struct rarvm_prepared_command *code, *cmd;
	int code_size, i, flags_required, j, flags;
	
	code = prg->cmd.array;
	code_size = prg->cmd_count;
	
	for (i=0 ; i < code_size ; i++) {
		cmd = &code[i];
		switch(cmd->op_code) {
			case VM_MOV:
				cmd->op_code = cmd->byte_mode ? VM_MOVB:VM_MOVD;
				continue;
			case VM_CMP:
				cmd->op_code = cmd->byte_mode ? VM_CMPB:VM_CMPD;
				continue;
		}
		if ((vm_cmdflags[cmd->op_code] & VMCF_CHFLAGS) == 0) {
			continue;
		}
		flags_required = FALSE;
		for (j=i+1 ; j < code_size ; j++) {
			flags = vm_cmdflags[code[j].op_code];
			if (flags & (VMCF_JUMP|VMCF_PROC|VMCF_USEFLAGS)) {
				flags_required=TRUE;
				break;
			}
			if (flags & VMCF_CHFLAGS) {
				break;
			}
		}
		if (flags_required) {
			continue;
		}
		switch(cmd->op_code) {
			case VM_ADD:
				cmd->op_code = cmd->byte_mode ? VM_ADDB:VM_ADDD;
				continue;
			case VM_SUB:
				cmd->op_code = cmd->byte_mode ? VM_SUBB:VM_SUBD;
				continue;
			case VM_INC:
				cmd->op_code = cmd->byte_mode ? VM_INCB:VM_INCD;
				continue;
			case VM_DEC:
				cmd->op_code = cmd->byte_mode ? VM_DECB:VM_DECD;
				continue;
			case VM_NEG:
				cmd->op_code = cmd->byte_mode ? VM_NEGB:VM_NEGD;
				continue;
		}
	}
}

int rarvm_prepare(rarvm_data_t *rarvm_data, rarvm_input_t *rarvm_input, unsigned char *code,
		int code_size, struct rarvm_prepared_program *prg)
{
	unsigned char xor_sum;
	int i, op_num, distance;
	rarvm_standard_filters_t filter_type;
	struct rarvm_prepared_command *cur_cmd;
	uint32_t data_flag, data;
 	struct rarvm_prepared_command *cmd;
 	
 	rar_dbgmsg("in rarvm_prepare code_size=%d\n", code_size);
	rarvm_input->in_addr = rarvm_input->in_bit = 0;
	memcpy(rarvm_input->in_buf, code, MIN(code_size, 0x8000));
	xor_sum = 0;
	for (i=1 ; i<code_size; i++) {
		rar_dbgmsg("code[%d]=%d\n", i, code[i]);
		xor_sum ^= code[i];
	}
	rar_dbgmsg("xor_sum=%d\n", xor_sum);
	rarvm_addbits(rarvm_input,8);
	
	prg->cmd_count = 0;
	if (xor_sum == code[0]) {
		filter_type = is_standard_filter(code, code_size);
		rar_dbgmsg("filter_type=%d\n", filter_type);
		if (filter_type != VMSF_NONE) {
			rar_cmd_array_add(&prg->cmd, 1);
			cur_cmd = &prg->cmd.array[prg->cmd_count++];
			cur_cmd->op_code = VM_STANDARD;
			cur_cmd->op1.data = filter_type;
			cur_cmd->op1.addr = &cur_cmd->op1.data;
			cur_cmd->op2.addr = &cur_cmd->op2.data;
			cur_cmd->op1.type = cur_cmd->op2.type = VM_OPNONE;
			code_size = 0;
		}

		data_flag = rarvm_getbits(rarvm_input);
		rar_dbgmsg("data_flag=%u\n", data_flag);
		rarvm_addbits(rarvm_input, 1);
		if (data_flag & 0x8000) {
			int data_size = rarvm_read_data(rarvm_input)+1;
			rar_dbgmsg("data_size=%d\n", data_size);
			prg->static_data = cli_malloc(data_size);
			if(!prg->static_data) {
			    cli_dbgmsg("unrar: rarvm_prepare: cli_malloc failed for prg->static_data\n");
			    return FALSE;
			}
			for (i=0 ; rarvm_input->in_addr < code_size && i < data_size ; i++) {
				prg->static_size++;
				prg->static_data = cli_realloc2(prg->static_data, prg->static_size);
				if(!prg->static_data) {
				    cli_dbgmsg("unrar: rarvm_prepare: cli_realloc2 failed for prg->static_data\n");
				    return FALSE;
				}
				prg->static_data[i] = rarvm_getbits(rarvm_input) >> 8;
				rarvm_addbits(rarvm_input, 8);
			}
		}
		while (rarvm_input->in_addr < code_size) {
			rar_cmd_array_add(&prg->cmd, 1);
			cur_cmd = &prg->cmd.array[prg->cmd_count];
			data = rarvm_getbits(rarvm_input);
			rar_dbgmsg("data: %u\n", data);
			if ((data & 0x8000) == 0) {
				cur_cmd->op_code = (rarvm_commands_t) (data>>12);
				rarvm_addbits(rarvm_input, 4);
			} else {
				cur_cmd->op_code = (rarvm_commands_t) ((data>>10)-24);
				rarvm_addbits(rarvm_input, 6);
			}
			if (vm_cmdflags[cur_cmd->op_code] & VMCF_BYTEMODE) {
				cur_cmd->byte_mode = rarvm_getbits(rarvm_input) >> 15;
				rarvm_addbits(rarvm_input, 1);
			} else {
				cur_cmd->byte_mode = 0;
			}
			cur_cmd->op1.type = cur_cmd->op2.type = VM_OPNONE;
			op_num = (vm_cmdflags[cur_cmd->op_code] & VMCF_OPMASK);
			rar_dbgmsg("op_num: %d\n", op_num);
			cur_cmd->op1.addr = cur_cmd->op2.addr = NULL;
			if (op_num > 0) {
				rarvm_decode_arg(rarvm_data, rarvm_input,
					&cur_cmd->op1, cur_cmd->byte_mode);
				if (op_num == 2) {
					rarvm_decode_arg(rarvm_data, rarvm_input,
							&cur_cmd->op2, cur_cmd->byte_mode);
				} else {
					if (cur_cmd->op1.type == VM_OPINT &&
							(vm_cmdflags[cur_cmd->op_code] &
							(VMCF_JUMP|VMCF_PROC))) {
						distance = cur_cmd->op1.data;
						rar_dbgmsg("distance = %d\n", distance);
						if (distance >= 256) {
							distance -= 256;
						} else {
							if (distance >=136) {
								distance -= 264;
							} else {
								if (distance >= 16) {
									distance -= 8;
								} else if (distance >= 8) {
									distance -= 16;
								}
							}
							distance += prg->cmd_count;
						}
						rar_dbgmsg("distance = %d\n", distance);
						cur_cmd->op1.data = distance;
					}
				}
			}
			prg->cmd_count++;
		}
	}
	rar_cmd_array_add(&prg->cmd,1);
	cur_cmd = &prg->cmd.array[prg->cmd_count++];
	cur_cmd->op_code = VM_RET;
	cur_cmd->op1.addr = &cur_cmd->op1.data;
	cur_cmd->op2.addr = &cur_cmd->op2.data;
	cur_cmd->op1.type = cur_cmd->op2.type = VM_OPNONE;
	
	for (i=0 ; i < prg->cmd_count ; i++) {
		cmd = &prg->cmd.array[i];
		rar_dbgmsg("op_code[%d]=%d\n", i, cmd->op_code);
		if (cmd->op1.addr == NULL) {
			cmd->op1.addr = &cmd->op1.data;
		}
		if (cmd->op2.addr == NULL) {
			cmd->op2.addr = &cmd->op2.data;
		}
	}
	

	if (code_size!=0) {
		rarvm_optimize(prg);
	}

	return TRUE;
}
