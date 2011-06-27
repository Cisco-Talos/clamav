/*
 *  ClamAV PE emulator
 *
 *  Copyright (C) 2010 - 2011, Sourcefire, Inc.
 *
 *  Authors: Török Edvin, aCaB
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
 */
#include "emulator.h"
#include "vmm.h"
#include "others.h"
#include "disasm-common.h"
#include "disasm.h"
#include "pe.h"
#include "flags.h"
#include "structs.h"
#include "imports.h"
#include <string.h>


#define MAXREG (sizeof(reg_masks) / sizeof(reg_masks[0]))

struct DIS_mem_arg {
    enum X86REGS scale_reg;/**< register used as scale */
    enum X86REGS add_reg;/**< register used as displacemenet */
    uint8_t scale;/**< scale as immediate number */
    int32_t displacement;/**< displacement as immediate number */
};

enum operand {
    OPERAND_CALC, /* just calculate, i.e. lea not mov */
    OPERAND_READ, /* calculate and read from memory */
    OPERAND_WRITEREG,
    OPERAND_WRITEMEM
};

#define DEFINE_MEM(first, last, bits) \
    [first ... last] = {~0u >> (32 - bits), 0, 0, bits, bits - 1}
static const desc_t mem_desc [] = {
    DEFINE_MEM(SIZED, SIZED, 32),
    DEFINE_MEM(SIZEW, SIZEW, 16),
    DEFINE_MEM(SIZEB, SIZEB,  8)
};

void mem_push(cli_emu_t *state, unsigned size, uint32_t value)
{
    int32_t esp;

    esp = state->reg_val[REG_ESP];
    esp -= size;
    state->reg_val[REG_ESP] = esp;
    cli_dbgmsg("push %x -> %08x\n", value, esp);
    switch (size) {
	case 2:
	    cli_emu_vmm_write16(state->mem, esp, value);
	    break;
	case 4:
	    cli_emu_vmm_write32(state->mem, esp, value);
	    break;
	default:
	    break;
    }
}

typedef struct {
    PEB peb;
    PEB_LDR_DATA ldr_data;
    RTL_USER_PROCESS_PARAMETERS params;
    KUSER_SHARED_DATA userdata;
    WCHAR unicode[2048];
    uint32_t unicode_n;
} os_t;

static uint32_t offaddr(uint32_t base, const os_t *p1, const void *p2)
{
    return base + (char*)p2 - (char*)p1;
}

static int make_unicode_string(os_t *OS, uint32_t base, UNICODE_STRING *s, const char* str)
{
    WCHAR *w;
    unsigned i;
    unsigned len = strlen(str) + 1;

    s->Length = s->MaximumLength = 2*len;
    w = &OS->unicode[OS->unicode_n];
    OS->unicode_n += s->Length;

    if (2*OS->unicode_n > sizeof(OS->unicode))
	return -1;
    for (i=0;i<len;i++) {
	w[2*i] = str[i];
	w[2*i+1] = 0;
    }
    s->Buffer = offaddr(base, OS, w);
    return 0;
}

#define LIBMAPPING (MAPPING_END+0x0f000000)
#define EC32(x) (x) = le32_to_host(x) /* Convert little endian to host */
uint32_t map_dll(const struct dll_desc *dll)
{
    /*FIXME: this is not a real mapping, just a fake handle
     * TODO: this should be a pointer to the mapped memory of a fake dll */
    unsigned dll_idx = dll - &all_dlls[0];
    return LIBMAPPING + dll_idx * 4;
}

static void SetupList(void *head, uint32_t element_size, uint32_t elements, uint32_t addr)
{
    unsigned i;
    LIST_ENTRY *le = head;

    le->Flink = le->Blink = addr;
    for (i=0;i<elements;) {
	uint32_t next_addr = addr + element_size;
	le->Flink = next_addr;
	i++;
	le = (LIST_ENTRY*)((char*)head + element_size);
	le->Blink = addr;
	le->Flink = next_addr;
	addr = next_addr;
    }
}

#define PESALIGN(o,a) (((a))?(((o)/(a)+((o)%(a)!=0))*(a)):(o))
static int pe_setup(cli_emu_t *emu, struct cli_pe_hook_data *pedata)
{
    TEB teb;/* this is FS:0x00 here */
    LDR_DATA_TABLE_ENTRY *table = NULL;
    os_t OS;
    uint32_t pebaddr, stacksize, size, va, i, tableaddr;

    memset(&OS, 0, sizeof(OS));
    memset(&teb, 0, sizeof(teb));

    /* TODO: we could map at fixed 0x7efdd000, but if we don't its easier to
     * detect if any apps are using that hardcoded address (malware mostly) */
    cli_emu_vmm_alloc(emu->mem, sizeof(OS), &pebaddr);

    /* FILL in PEB / TEB here */
    stacksize = PESALIGN(pedata->opt32.SizeOfStackReserve, 4096);
    cli_emu_vmm_alloc(emu->mem, stacksize, &teb.NtTib.StackLimit);
    teb.NtTib.StackBase = teb.NtTib.StackLimit + stacksize;
    cli_dbgmsg("Mapped stack: %08x - %08x\n", teb.NtTib.StackLimit, teb.NtTib.StackLimit);
    teb.NtTib.Version = 7680;
    teb.NtTib.Self = emu->mem->fs_offset;

    teb.ClientId.UniqueProcess = -1;
    teb.ClientId.UniqueThread = -2;
    teb.Peb = pebaddr;
    teb.CurrentLocale = 1033;

    memcpy(teb.StaticUnicodeBuffer, L"1337", 10);
    teb.StaticUnicodeString.Buffer = emu->mem->fs_offset +(char*) &teb.StaticUnicodeBuffer - (char*)&teb;
    teb.StaticUnicodeString.Length = 10;
    teb.StaticUnicodeString.MaximumLength = sizeof(teb.StaticUnicodeBuffer);

    /* WinXP */
    OS.peb.OSMajorVersion = 5;
    OS.peb.OSMinorVersion = 1;
    OS.peb.OSBuildNumber = 2600;
    OS.peb.OSPlatformId = 2;
    OS.peb.Mutant = INVALID_HANDLE_VALUE;
    OS.peb.NumberOfProcessors = 1;

    va = pedata->opt32.ImageBase + pedata->opt32.DataDirectory[1].VirtualAddress;
    size = pedata->opt32.DataDirectory[1].Size;
    if (size) {
	table = calloc(1 + size / sizeof(struct IMAGE_IMPORT),sizeof(*table));
	cli_emu_vmm_alloc(emu->mem, sizeof(*table)*(1 + size/sizeof(struct IMAGE_IMPORT)), &tableaddr);
    }
    i = 1;
    while (size >= sizeof(struct IMAGE_IMPORT)) {
	struct IMAGE_IMPORT import;
	const struct dll_desc *dll;
	uint32_t dll_idx;
	char *dllname;

	cli_emu_vmm_read_r(emu->mem, va, &import, sizeof(import));
	size -= sizeof(struct IMAGE_IMPORT);
	va += sizeof(struct IMAGE_IMPORT);
	if (!import.DllName)
	    break;
	EC32(import.OrigThunk);
	EC32(import.Fwd);
	EC32(import.DllName);
	EC32(import.Thunk);

	dllname = cli_emu_vmm_read_string(emu->mem, pedata->opt32.ImageBase + import.DllName, 64);
	if (!dllname)
	    break;;
	dll = lookup_dll(dllname);

	table[i].DllBase = map_dll(dll);
	table[i].EntryPoint = table[i].DllBase;
	make_unicode_string(&OS, pebaddr, &table[i].FullDllName, dllname);/*FIXME: this is full path*/
	make_unicode_string(&OS, pebaddr, &table[i].BaseDllName, dllname);
	table[i].CheckSum = pedata->opt32.CheckSum;
	table[i].TimeDateStamp = pedata->file_hdr.TimeDateStamp;

	i++;
	free(dllname);
    }
    if (i > 1) {
	SetupList(&table[0].InLoadOrderLinks, sizeof(table[0]), i, tableaddr);
	SetupList(&table[0].InMemoryOrderLinks, sizeof(table[0]), i, tableaddr);
	SetupList(&table[0].InInitializationOrderLinks, sizeof(table[0]), i, tableaddr);
	memcpy(&OS.ldr_data.InMemoryOrderModuleList, &table[0].InMemoryOrderLinks, sizeof(LIST_ENTRY));
	memcpy(&OS.ldr_data.InLoadOrderModuleList, &table[0].InLoadOrderLinks, sizeof(LIST_ENTRY));
	memcpy(&OS.ldr_data.InInitializationOrderModuleList, &table[0].InInitializationOrderLinks, sizeof(LIST_ENTRY));
    }

    OS.ldr_data.Length = sizeof(OS.ldr_data);
    OS.ldr_data.Initialized = 1;
    OS.ldr_data.SsHandle = 0;

    OS.peb.LdrData = offaddr(pebaddr, &OS, &OS.ldr_data);

    OS.peb.ProcessParameters = offaddr(pebaddr, &OS, &OS.params);
    OS.params.AllocationSize = 4096;
    OS.params.Size = sizeof(OS.params);
    OS.params.Flags = PARAMS_ALREADY_NORMALIZED;
    OS.params.ConsoleHandle = INVALID_HANDLE_VALUE;
    OS.params.hStdInput = (HANDLE)3;
    OS.params.hStdOutput = (HANDLE)7;
    OS.params.hStdError = (HANDLE)11;
    OS.params.CurrentDirectory.Handle = INVALID_HANDLE_VALUE;

    OS.peb.ProcessHeap = HANDLE_HEAP;
    OS.peb.EnvironmentUpdateCount = 1;

    /* TODO: map at USER_SHARED_DATA? */
    teb.SharedUserData = offaddr(pebaddr, &OS, &OS.userdata);
    OS.userdata.TickCountMultiplier = 1;
    OS.userdata.TickCount.High2Time = 0x1337;
    OS.userdata.TickCount.High1Time = 0x1337;
    OS.userdata.Cookie = 0x1337;
    OS.userdata.NtProductType = NtProductWinNt;
    OS.userdata.ProductTypeIsValid = TRUE;
    OS.userdata.NtMajorVersion = OS.peb.OSMajorVersion;
    OS.userdata.NtMinorVersion = OS.peb.OSMinorVersion;
    OS.userdata.AlternativeArchitecture = StandardDesign;

    OS.peb.ImageBaseAddress = (HMODULE)pedata->opt32.ImageBase;

    /* end of PEB/TEB*/
    cli_emu_vmm_write(emu->mem, emu->mem->fs_offset, &teb, sizeof(teb));
    cli_emu_vmm_write(emu->mem, pebaddr, &OS, sizeof(OS));
    /* TODO: make PEB RO? */

    /* init registers */
    emu->reg_val[REG_ESP] = teb.NtTib.StackBase;
    emu->reg_val[REG_EBP] = teb.NtTib.StackBase + 0x28;
    emu->reg_val[REG_EBX] = emu->mem->fs_offset;
    emu->reg_val[REG_EAX] = 0;

    if (pedata->opt32.Subsystem == 1) {
	/* subsys native */
	/*FIXME:drivers take driverobject, registrypath*/

    } else {
	if (pedata->opt32.DllCharacteristics & 1) {
	    uint32_t handle = OS.peb.ImageBaseAddress;
	    uint32_t reason = DLL_PROCESS_ATTACH;
	    uint32_t reserved = 0;
	    /* DLL */
	    mem_push(emu, 4, reserved);
	    mem_push(emu, 4, reason);
	    mem_push(emu, 4, handle);
	} else {
	    mem_push(emu, 4, teb.Peb);
	}
    }

    mem_push(emu, 4, MAPPING_END-0x42);
    emu->eflags = 0x2 | (1 << bit_if) | (1 << bit_af) | (1 << bit_pf);
    return 0;
}

cli_emu_t* cli_emulator_new(emu_vmm_t *v, struct cli_pe_hook_data *pedata)
{
    uint32_t stack, stackend, stacksize;
    cli_emu_t *emu = cli_calloc(1, sizeof(*emu));
    if (!emu)
	return NULL;
    emu->mem = v;
    emu->eip = cli_emu_vmm_rva2va(v, pedata->opt32.AddressOfEntryPoint);
    memset(emu->cached_disasm, 0, sizeof(emu->cached_disasm));

    pe_setup(emu, pedata);

    /* TODO: init registers */
    return emu;
}

void cli_emulator_free(cli_emu_t *emu)
{
    free(emu);
}

#define UNIMPLEMENTED_REG(v) cli_emu_vmm_raise((v), -EMU_ERR_REG, reg)
#define INVALID_SIZE(v) cli_emu_vmm_raise((v), -EMU_ERR_SIZE, 0)

static always_inline void get_reg(emu_vmm_t *mem, desc_t *desc, enum X86REGS reg)
{
    if (reg >= MAXREG) {
	if (reg != REG_INVALID)
	    UNIMPLEMENTED_REG(mem);
	desc->idx = REGIDX_INVALID;
	return;
    }
    desc->mask = reg_masks[reg].rw_mask;
    desc->shift = reg_masks[reg].rw_shift;
    desc->idx = reg - reg_masks[reg].sub;
    desc->carry_bit = reg_masks[reg].carry_bit;
    desc->sign_bit = reg_masks[reg].carry_bit;
}

/** Disassembles one X86 instruction starting at the specified offset.
  \group_disasm
 * @param[out] result disassembly result
 * @param[in] offset start disassembling from this offset, in the current file
 * @param[in] len max amount of bytes to disassemble
 * @return offset where disassembly ended*/
static uint32_t
DisassembleAt(emu_vmm_t *v, struct dis_instr* result, uint32_t offset)
{
    struct DISASM_RESULT res;
    unsigned i;
    uint8_t dis[32];
    const uint8_t *next;

    cli_emu_vmm_read_x(v, offset, dis, sizeof(dis));

    next = cli_disasm_one(dis, sizeof(dis), &res, 1);
    result->operation_size = res.opsize;
    result->address_size = res.adsize;
    result->segment = res.segment;
    result->opcode = (enum X86OPS) cli_readint16(&res.real_op);
    for (i=0;i<3;i++) {
	enum DIS_SIZE size = (enum DIS_SIZE) res.arg[i][1];/* not valid for REG */
	struct dis_arg *arg = &result->arg[i];
	arg->access_size = SIZE_INVALID;
	switch ((enum DIS_ACCESS)res.arg[i][0]) {
	    case ACCESS_MEM:
		get_reg(v, &arg->scale_reg, (enum X86REGS)res.arg[i][2]);
		get_reg(v, &arg->add_reg, (enum X86REGS)res.arg[i][3]);
		arg->scale = res.arg[i][4];
		if (arg->scale == 1 && res.arg[i][3] == REG_INVALID) {
		    memcpy(&arg->add_reg, &arg->scale_reg, sizeof(arg->scale_reg));
		    arg->scale_reg.idx = REGIDX_INVALID;
		}
		if (arg->scale == 0)
		    arg->scale_reg.idx = REGIDX_INVALID;
		arg->displacement = cli_readint32((const uint32_t*)&res.arg[i][6]);
		arg->access_size = size; /* not valid for REG */
		if (result->segment == REG_FS)
		    arg->displacement += v->fs_offset;

		break;
	    case ACCESS_REG:
		get_reg(v, &arg->add_reg, (enum X86REGS)res.arg[i][1]);
		arg->scale_reg.idx = REGIDX_INVALID;
		arg->displacement = 0;
		arg->access_size = SIZE_INVALID;
		break;
	    case ACCESS_REL:
		arg->access_size = SIZE_REL;
		/* fall-through */
	    default: {
		uint32_t c = cli_readint32((const uint32_t*)&res.arg[i][6]);
		if (c && c != 0xffffffff)
		    cli_dbgmsg("truncating 64-bit immediate\n");
		arg->scale_reg.idx = REGIDX_INVALID;
		arg->add_reg.idx = REGIDX_INVALID;
		arg->scale = 0;
		switch (size) {
		    case SIZEB:
			arg->displacement = *(const int8_t*)&res.arg[i][2];
			break;
		    case SIZEW:
			arg->displacement = cli_readint16((const int16_t*)&res.arg[i][2]);
			break;
		    case SIZED:
		    default:
			arg->displacement = cli_readint32((const int32_t*)&res.arg[i][2]);
			break;
		}
		break;
	    }
	}
    }
    return offset + next - dis;
}

static always_inline struct dis_instr* disasm(cli_emu_t *emu)
{
    int ret;
    struct dis_instr *instr;
    uint32_t idx = emu->eip & (DISASM_CACHE_SIZE-1);
    instr = &emu->cached_disasm[idx];
//    if (instr->va != emu->eip) {
	cli_dbgmsg("eip = %08x\n", emu->eip);
	if ((ret = DisassembleAt(emu->mem, instr, emu->eip)) < 0)
	    return NULL;
	instr->len = ret - emu->eip;
	instr->va = emu->eip;
	/* TODO discard cache when writing to this page! */
  //  }
    return instr;
}

static always_inline uint32_t readreg(const cli_emu_t *emu,
				       const desc_t *reg)
{
    return (emu->reg_val[reg->idx] & reg->mask) >> reg->shift;
}

static always_inline void read_reg(const cli_emu_t *emu, enum X86REGS reg, uint32_t *value)
{
    desc_t desc;
    get_reg(emu->mem, &desc, reg);
    if (desc.idx == REGIDX_INVALID)
	cli_emu_vmm_raise(emu->mem, -EMU_ERR_REG, desc.idx);
    *value = readreg(emu, &desc);
}

static always_inline void writereg(cli_emu_t *emu, const desc_t *reg, uint32_t value)
{
    if (reg->idx == REGIDX_INVALID)
	cli_emu_vmm_raise(emu->mem, -EMU_ERR_REG, reg->idx);
    emu->reg_val[reg->idx] = (emu->reg_val[reg->idx] & (~reg->mask)) |
	((value << reg->shift) & reg->mask);
}

static always_inline int write_reg(cli_emu_t *emu, enum X86REGS reg, uint32_t value)
{
    desc_t desc;
    get_reg(emu->mem, &desc, reg);
    writereg(emu, &desc, value);
    return 0;
}

static always_inline uint32_t calcreg(const cli_emu_t *emu, const struct dis_arg *arg)
{
    uint32_t value = arg->displacement + readreg(emu, &arg->add_reg);
    if (arg->scale_reg.idx != REGIDX_INVALID)
	value += arg->scale * readreg(emu, &arg->scale_reg);
    return value;
}

static always_inline void mem_read(const cli_emu_t *emu, uint32_t addr, enum DIS_SIZE size, uint32_t *value)
{
    switch (size) {
	case SIZE_INVALID:
	    break;
	case SIZEB:
	    cli_emu_vmm_read8(emu->mem, addr, value);
	    break;
	case SIZEW:
	    cli_emu_vmm_read16(emu->mem, addr, value);
	    break;
	case SIZED:
	    cli_emu_vmm_read32(emu->mem, addr, value);
	    break;
	default:
	    cli_emu_vmm_raise(emu->mem, -EMU_ERR_SIZE, emu->eip);
	    break;
    }
}

static always_inline void read_operand(const cli_emu_t *emu,
				      const struct dis_arg *arg, uint32_t *value)
{
    *value = calcreg(emu, arg);
    mem_read(emu, *value, arg->access_size, value);
}

static always_inline void mem_write(cli_emu_t *emu, uint32_t addr, enum DIS_SIZE size, uint32_t value)
{
    switch (size) {
	case SIZEB:
	    cli_emu_vmm_write8(emu->mem, addr, value);
	    break;
	case SIZEW:
	    cli_emu_vmm_write16(emu->mem, addr, value);
	    break;
	case SIZED:
	    cli_emu_vmm_write32(emu->mem, addr, value);
	    break;
	default:
	    cli_emu_vmm_raise(emu->mem, -EMU_ERR_SIZE, emu->eip);
	    break;
    }
}

static always_inline void write_operand(cli_emu_t *emu,
				       const struct dis_arg *arg, uint32_t value)
{
    if (arg->access_size == SIZE_INVALID) {
	writereg(emu, &arg->add_reg, value);
    } else {
	/* TODO: check for FS segment */
	uint32_t addr = calcreg(emu, arg);
	mem_write(emu, addr, arg->access_size, value);
    }
}

#define READ_OPERAND(value, op) read_operand(state, &instr->arg[(op)], &(value))

#define WRITE_RESULT(op, value) write_operand(state, &instr->arg[(op)], (value))

#define NOSTACK do { printf("Stack overflowed\n"); return -1;} while(0)

static always_inline void emu_mov(cli_emu_t *state, instr_t *instr)
{
    //TODO: FS segment support, the rest of segments are equal anyway on win32
    uint32_t reg;
    READ_OPERAND(reg, 1);
    WRITE_RESULT(0, reg);
}

static always_inline void emu_movzx(cli_emu_t *state, instr_t *instr)
{
    //TODO: FS segment support, the rest of segments are equal anyway on win32
    uint32_t reg;
    READ_OPERAND(reg, 1);
    /* zero-extend already done by READ_OPERAND */
    WRITE_RESULT(0, reg);
}

static always_inline void emu_bswap(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg;
    READ_OPERAND(reg, 0);
    switch (instr->arg[0].access_size) {
	case SIZEW:
	    reg = cbswap16(reg);
	    break;
	case SIZED:
	    reg = cbswap32(reg);
	    break;
	default:
	    break;
    }

    WRITE_RESULT(0, reg);
}

#define MEM_PUSH(val) mem_push(state, instr->operation_size ? 2 : 4, (val))

#define MEM_POP(val) mem_pop(state, instr->operation_size ? 2: 4, (val))

static always_inline void emu_push(cli_emu_t *state, instr_t *instr)
{
    uint32_t value;

    READ_OPERAND(value, 0);
    MEM_PUSH(value);
}

static always_inline void emu_pushf(cli_emu_t *state, instr_t *instr)
{
    MEM_PUSH(state->eflags&0xfcffff);
}

void mem_pop(cli_emu_t *state, int size, uint32_t *value)
{
    uint32_t esp;

    esp = state->reg_val[REG_ESP];
    switch (size) {
	case 2:
	    cli_emu_vmm_read16(state->mem, esp, value);
	    break;
	case 4:
	    cli_emu_vmm_read32(state->mem, esp, value);
	    break;
    }

    esp += size;
    state->reg_val[REG_ESP] = esp;
}

static always_inline void emu_pop(cli_emu_t *state, struct dis_instr *instr)
{
    uint32_t value;
    MEM_POP(&value);
    WRITE_RESULT(0, value);
}

/* IF, IOPL, RF, VIP, and VIF, and reserved bits can't be modified */
static const int32_t popf_allowed =
 (1 << bit_cf) |
 (1 << bit_pf) |
 (1 << bit_af) |
 (1 << bit_zf) |
 (1 << bit_sf) |
 (1 << bit_tf) |
 (1 << bit_df) |
 (1 << bit_of) |
 (1 << bit_nt) |
 (1 << bit_ac) |
 (1 << bit_id);

static always_inline void emu_popf(cli_emu_t *state, struct dis_instr *instr)
{
    uint32_t value;
    MEM_POP(&value);

    state->eflags = (value & popf_allowed) |
	(state->eflags & !popf_allowed);
    state->eflags &= ~(1<<bit_vip) | (1<<bit_vif);
}

static always_inline void emu_cld(cli_emu_t *state, struct dis_instr *instr)
{
    state->eflags &= ~(1 << bit_df);
    state->eflags_def |= 1 << bit_df;
}

static always_inline void emu_std(cli_emu_t *state, instr_t *instr)
{
    state->eflags |= 1 << bit_df;
    state->eflags_def |= 1 << bit_df;
}

static always_inline void emu_inc(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg;
    READ_OPERAND(reg, 0);
    WRITE_RESULT(0, ++reg);
    /* FIXME: inc byte ptr [addr] */
    calc_flags_inc(state, reg, &instr->arg[0].add_reg);
}

static always_inline void emu_dec(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg;
    READ_OPERAND(reg, 0);
    WRITE_RESULT(0, --reg);
    /* FIXME: inc byte ptr [addr] */
    calc_flags_dec(state, reg, &instr->arg[0].add_reg);
}
// returns 1 if loop should not be entered
static int emu_prefix_pre(cli_emu_t *state, int8_t ad16, int8_t repe_is_rep)
{
    if (state->prefix_repe || state->prefix_repne) {
	uint32_t cnt;
	read_reg(state, ad16 ? REG_CX : REG_ECX, &cnt);
	if (!cnt)
	    return 1;
    }
    return 0;
}

static int emu_prefix_post(cli_emu_t *state, int8_t ad16, int8_t repe_is_rep)
{
    if (state->prefix_repe || state->prefix_repne) {
	uint32_t cnt;
	read_reg(state, ad16 ? REG_CX : REG_ECX, &cnt);
	cnt--;
	write_reg(state, ad16 ? REG_CX : REG_ECX, cnt);
	if (!cnt)
	    return 0;
	if (state->prefix_repe && !repe_is_rep &&
	    !(state->eflags & (1 << bit_zf)))
	    return 0;
	if (state->prefix_repne &&
	    (state->eflags & (1 << bit_zf)))
	    return 0;
	return 1;
    }
    return 0;
}

static always_inline void emu_lodsx(cli_emu_t *state, instr_t *instr, enum DIS_SIZE size, enum X86REGS reg, uint32_t add)
{
    uint32_t esi;
    uint32_t val;

    if (emu_prefix_pre(state, instr->address_size, 1))
	return;
    //TODO:address size
    do {
	esi = state->reg_val[REG_ESI];
	read_reg(state, REG_ESI, &esi);
	mem_read(state, esi, size, &val);
	write_reg(state, reg, val);
	if (state->eflags & (1 << bit_df)) {
	    esi -= add;
	} else {
	    esi += add;
	}
	write_reg(state, REG_ESI, esi);
    } while (emu_prefix_post(state, instr->address_size, 1));
}

static always_inline void emu_stosx(cli_emu_t *state, instr_t *instr, enum DIS_SIZE size, enum X86REGS reg, uint32_t add)
{
    uint32_t edi;
    uint32_t val;

    if (emu_prefix_pre(state, instr->address_size, 1))
	return;
    //TODO:address size
    do {
	read_reg(state, REG_EDI, &edi);
	read_reg(state, reg, &val);
	mem_write(state, edi, size, val);
	if (state->eflags & (1 << bit_df)) {
	    edi -= add;
	} else {
	    edi += add;
	}
	write_reg(state, REG_EDI, edi);
    } while (emu_prefix_post(state, instr->address_size, 1));
}

static always_inline void emu_xor(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);
    reg1 ^= reg2;
    /* TODO: only calculate flags on demand */
    if (instr->arg[0].access_size == SIZE_INVALID)
	calc_flags_test(state, reg1, &instr->arg[0].add_reg);
    else
	calc_flags_test(state, reg1, &mem_desc[instr->arg[0].access_size]);
    WRITE_RESULT(0, reg1);
}

static always_inline void emu_shl(cli_emu_t *state, instr_t *instr)
{
    uint8_t largeshift;
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);

    const desc_t *desc =
	(instr->arg[0].access_size == SIZE_INVALID) ?
	&instr->arg[0].add_reg :
	&mem_desc[instr->arg[0].access_size];
    largeshift = reg2 >= desc->carry_bit;
    reg2 &= 0x1f;

    if (!reg2)
	return;
    uint64_t result = (uint64_t)reg1 << (uint8_t)reg2;
    uint8_t cf = (result >> desc->carry_bit) & 1;
    reg1 = result;
    if (reg2 == 1) {
	uint8_t of = ((result >> desc->sign_bit) & 1) ^ cf;
	state->eflags = (state->eflags & ~((1<< bit_cf) | (1 << bit_of))) |
			 (cf << bit_cf) |
			 (of << bit_of);
	state->eflags_def |= (1<<bit_cf) | (1<<bit_of);
    } else {
	state->eflags = (state->eflags & ~(1<< bit_cf)) |
			 (cf << bit_cf);
	state->eflags_def |= (1<<bit_cf);
	//OF undefined for shift > 1
	state->eflags_def &= ~(1<<bit_of);
    }
    if (largeshift)
	state->eflags_def &= ~(1<<bit_cf);
    WRITE_RESULT(0, reg1);
}

static always_inline void emu_shr(cli_emu_t *state, instr_t *instr)
{
    uint8_t largeshift;
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);

    const desc_t *desc =
	(instr->arg[0].access_size == SIZE_INVALID) ?
	&instr->arg[0].add_reg :
	&mem_desc[instr->arg[0].access_size];
    largeshift = reg2 >= desc->carry_bit;
    reg2 &= 0x1f;

    if (!reg2)
	return;
    uint32_t result = reg1;
    result >>= (uint8_t)(reg2 - 1);
    uint8_t cf = (result & 1);
    reg1 = result >> 1;
    if (reg2 == 1) {
	uint8_t of = ((result >> desc->sign_bit) & 1);
	state->eflags = (state->eflags & ~((1<< bit_cf) | (1 << bit_of))) |
			 (cf << bit_cf) |
			 (of << bit_of);
	state->eflags_def |= (1<<bit_cf) | (1<<bit_of);
    } else {
	state->eflags = (state->eflags & ~(1<< bit_cf)) |
			 (cf << bit_cf);
	state->eflags_def |= (1<<bit_cf);
	//OF undefined for shift > 1
	state->eflags_def &= ~(1<<bit_of);
    }
    if (largeshift)
	state->eflags_def &= ~(1<<bit_cf);
    WRITE_RESULT(0, reg1);
}

static always_inline void emu_sar(cli_emu_t *state, instr_t *instr)
{
    uint8_t largeshift;
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);

    const desc_t *desc =
	(instr->arg[0].access_size == SIZE_INVALID) ?
	&instr->arg[0].add_reg :
	&mem_desc[instr->arg[0].access_size];
    largeshift = reg2 >= desc->carry_bit;
    reg2 &= 0x1f;

    if (!reg2)
	return;
    int32_t result = reg1;
    CLI_SAR(result, (uint8_t)(reg2-1));
    uint8_t cf = (result & 1);
    reg1 = CLI_SRS(result, 1);
    if (reg2 == 1) {
	uint8_t of = 0;
	state->eflags = (state->eflags & ~((1<< bit_cf) | (1 << bit_of))) |
			 (cf << bit_cf) |
			 (of << bit_of);
	state->eflags_def |= (1<<bit_cf) | (1<<bit_of);
    } else {
	state->eflags = (state->eflags & ~(1<< bit_cf)) |
			 (cf << bit_cf);
	state->eflags_def |= (1<<bit_cf);
	//of undefined for shift > 1
	state->eflags_def &= ~(1<<bit_of);
    }
    if (largeshift)
	state->eflags_def &= ~(1<<bit_cf);
    WRITE_RESULT(0, reg1);
}

#define ROL(a,b,n) a = ( a << (b) ) | ( a >> (((n) - (b))) )
#define ROR(a,b,n) a = ( a >> (b) ) | ( a << (((n) - (b))) )

static always_inline void emu_rol(cli_emu_t *state, instr_t *instr)
{
    uint8_t largeshift;
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);

    const desc_t *desc =
	(instr->arg[0].access_size == SIZE_INVALID) ?
	&instr->arg[0].add_reg :
	&mem_desc[instr->arg[0].access_size];
    largeshift = reg2 >= desc->carry_bit;

    /* See Intel manual 4-312 Vol. 2B */
    if (reg2 == 1)
	state->eflags_def |= 1 << bit_of;//OF defined
    else
	state->eflags_def &= ~(1 << bit_of);//OF undef

    reg2 &= 0x1f;
    uint8_t msb;
    uint8_t cf;
    switch (desc->carry_bit) {
	case 8:
	    reg2 %= 8;
	    if (!reg2)
		return;
	    ROL(reg1, reg2, 8);
	    cf = reg1 & 1;
	    msb = (reg1 >> 7)&1;
	    break;
	case 16:
	    reg2 %= 16;
	    if (!reg2)
		return;
	    ROL(reg1, reg2, 16);
	    cf = reg1 & 1;
	    msb = (reg1 >> 15)&1;
	case 32:
	    if (!reg2)
		return;
	    ROL(reg1, reg2, 32);
	    cf = reg1 & 1;
	    msb = (reg1 >> 31)&1;
	    break;
	default:
	    INVALID_SIZE(state->mem);
    }

    uint8_t of = msb ^ cf;
    state->eflags = (state->eflags & ~((1<< bit_cf) | (1 << bit_of))) |
	(cf << bit_cf) |
	(of << bit_of);

    state->eflags_def |= (1 << bit_cf);
    WRITE_RESULT(0, reg1);
}

static always_inline void emu_ror(cli_emu_t *state, instr_t *instr)
{
    uint8_t largeshift;
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);

    const desc_t *desc =
	(instr->arg[0].access_size == SIZE_INVALID) ?
	&instr->arg[0].add_reg :
	&mem_desc[instr->arg[0].access_size];
    largeshift = reg2 >= desc->carry_bit;

    /* See Intel manual 4-312 Vol. 2B */
    if (reg2 == 1)
	state->eflags_def |= 1 << bit_of;//OF defined
    else
	state->eflags_def &= ~(1 << bit_of);//OF undef

    reg2 &= 0x1f;
    uint8_t msb, of;
    switch (desc->carry_bit) {
	case 8:
	    reg2 %= 8;
	    if (!reg2)
		return;
	    ROR(reg1, reg2, 8);
	    msb = (reg1 >> 7)&1;
	    of = msb ^ ((reg1 >> 6)&1);
	    break;
	case 16:
	    reg2 %= 16;
	    if (!reg2)
		return;
	    ROR(reg1, reg2, 16);
	    msb = (reg1 >> 15)&1;
	    of = msb ^ ((reg1 >> 14)&1);
	case 32:
	    if (!reg2)
		return;
	    ROR(reg1, reg2, 32);
	    msb = (reg1 >> 31)&1;
	    of = msb ^ ((reg1 >> 30)&1);
	    break;
	default:
	    INVALID_SIZE(state->mem);
    }

    uint8_t cf = msb;
    state->eflags = (state->eflags & ~((1<< bit_cf) | (1 << bit_of))) |
	(cf << bit_cf) |
	(of << bit_of);

    state->eflags_def |= (1 << bit_cf);
    WRITE_RESULT(0, reg1);
}

static always_inline void emu_and(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);
    reg1 &= reg2;
    if (instr->arg[0].access_size == SIZE_INVALID)
	calc_flags_test(state, reg1, &instr->arg[0].add_reg);
    else
	calc_flags_test(state, reg1, &mem_desc[instr->arg[0].access_size]);
    WRITE_RESULT(0, reg1);
}

static always_inline void emu_test(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);
    if (instr->arg[0].access_size == SIZE_INVALID)
	calc_flags_test(state, reg1, &instr->arg[0].add_reg);
    else
	calc_flags_test(state, reg1, &mem_desc[instr->arg[0].access_size]);
}

static always_inline void emu_or(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);
    reg1 |= reg2;
    if (instr->arg[0].access_size == SIZE_INVALID)
	calc_flags_test(state, reg1, &instr->arg[0].add_reg);
    else
	calc_flags_test(state, reg1, &mem_desc[instr->arg[0].access_size]);
    WRITE_RESULT(0, reg1);
}
static always_inline void emu_sub(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);
    if (instr->arg[0].access_size == SIZE_INVALID)
	calc_flags_addsub(state, reg1, reg2, &instr->arg[0].add_reg, 1);
    else
	calc_flags_addsub(state, reg1, reg2, &mem_desc[instr->arg[0].access_size], 1);
    reg1 -= reg2;
    WRITE_RESULT(0, reg1);
}

static always_inline void emu_cmp(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);
    if (instr->arg[0].access_size == SIZE_INVALID)
	calc_flags_addsub(state, reg1, reg2, &instr->arg[0].add_reg, 1);
    else
	calc_flags_addsub(state, reg1, reg2, &mem_desc[instr->arg[0].access_size], 1);
}

static always_inline uint8_t emu_flags(const cli_emu_t *state, uint8_t bit)
{
    return (state->eflags >> bit) & 1;
}
static always_inline void emu_adc(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);
    reg1 += emu_flags(state, bit_cf);
    if (instr->arg[0].access_size == SIZE_INVALID)
	calc_flags_addsub(state, reg1, reg2, &instr->arg[0].add_reg, 0);
    else
	calc_flags_addsub(state, reg1, reg2, &mem_desc[instr->arg[0].access_size], 0);
    reg1 += reg2;
    WRITE_RESULT(0, reg1);
}

static always_inline void emu_sbb(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);
    reg1 -= emu_flags(state, bit_cf);
    if (instr->arg[0].access_size == SIZE_INVALID)
	calc_flags_addsub(state, reg1, reg2, &instr->arg[0].add_reg, 1);
    else
	calc_flags_addsub(state, reg1, reg2, &mem_desc[instr->arg[0].access_size], 1);
    reg1 -= reg2;
    WRITE_RESULT(0, reg1);
}

static always_inline void emu_add(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg1, reg2;
    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);
    if (instr->arg[0].access_size == SIZE_INVALID)
	calc_flags_addsub(state, reg1, reg2, &instr->arg[0].add_reg, 0);
    else
	calc_flags_addsub(state, reg1, reg2, &mem_desc[instr->arg[0].access_size], 0);
    reg1 += reg2;
    WRITE_RESULT(0, reg1);
}

static const int16_t mul_flags = (1 << bit_cf) | (1 << bit_of);
static always_inline void emu_mul(cli_emu_t *state, instr_t *instr)
{
    uint32_t reg1, reg2;
    uint64_t result;
    int8_t of;
    desc_t reg_eax, reg_edx;

    READ_OPERAND(reg1, 0);
    READ_OPERAND(reg2, 1);

    switch (instr->arg[0].access_size) {
	case SIZEB:
	    write_reg(state, REG_AX, reg1 * reg2);
	    of = reg1 & 0xff00 ? 1 : 0;
	    break;
	case SIZED:
	    reg1 *= reg2;
	    write_reg(state, REG_DX, reg1 >> 16);
	    write_reg(state, REG_AX, reg1 & 0xffff);
	    of = reg1 & 0xffff0000 ? 1 : 0;
	    break;
	case SIZEW:
	    result = ((uint64_t)reg1) * reg2;
	    write_reg(state, REG_EDX, result >> 32);
	    write_reg(state, REG_EAX, result);
	    of = (result >> 32) ? 1 : 0;
	    break;
    }

    state->eflags = (state->eflags & ~mul_flags) |
	(of << bit_of) |
	(of << bit_cf);
    state->eflags_def |= mul_flags;
    /* TODO:sf,zf,af,pf undefined */
}

static always_inline int emu_loop(cli_emu_t *state, instr_t *instr)
{
    uint32_t cnt;
    read_reg(state, instr->address_size ? REG_CX : REG_ECX, &cnt);
    if (--cnt) {
	/* branch cond = 1 */
	if (!instr->operation_size) {
	    int8_t rel = instr->arg[0].displacement;
	    state->eip += rel;
	} else {
	    /* Intel Manual 3-598 Vol. 2A */
	    /* TODO: is this right, rel8 not taken into account? */
	    state->eip &= 0xffff;
	}
    }
    if (write_reg(state, instr->address_size ? REG_CX : REG_ECX, cnt) == -1)
	return -1;
    return 0;
}

static always_inline void emu_jmp(cli_emu_t *state, instr_t *instr)
{
    struct dis_arg *arg = &instr->arg[0];
    if (arg->access_size == SIZE_REL) {
	state->eip += arg->displacement;
    } else {
	uint32_t value;
	READ_OPERAND(value, 0);
	state->eip = value;
    }
    if (instr->operation_size)
	state->eip &= 0xffff;
}

static always_inline void emu_call(cli_emu_t *state, instr_t *instr)
{
    struct dis_arg *arg = &instr->arg[0];

    MEM_PUSH(state->eip);

    if (arg->access_size == SIZE_REL) {
	state->eip += arg->displacement;
    } else {
	uint32_t value;
	READ_OPERAND(value, 0);
	state->eip = value;
    }
    if (instr->operation_size)
	state->eip &= 0xffff;
}

static always_inline void emu_ret(cli_emu_t *state, instr_t *instr)
{
    uint32_t esp;
    struct dis_arg *arg = &instr->arg[0];

    cli_dbgmsg("ret: esp = %x\n", state->reg_val[REG_ESP]);
    MEM_POP(&state->eip);
    esp = state->reg_val[REG_ESP];

    if (arg->displacement) {
	if (instr->address_size) {
	    uint16_t sp = esp;
	    sp += arg->displacement;
	    esp = (esp & 0xffff00000) | sp;
	}
	else
	    esp += arg->displacement;
    }
    state->reg_val[REG_ESP] = esp;
}

static always_inline void emu_leave(cli_emu_t *state, instr_t *instr)
{
    state->reg_val[REG_ESP] = state->reg_val[REG_EBP];
    MEM_POP(&state->reg_val[REG_EBP]);
}

static always_inline void emu_movsx(cli_emu_t *state, instr_t *instr, enum DIS_SIZE size, uint32_t add)
{
    uint32_t esi, edi;
    uint32_t val;

    if (emu_prefix_pre(state, instr->address_size, 1))
	return;
    //TODO:address size
    do {
	read_reg(state, REG_ESI, &esi);
	read_reg(state, REG_EDI, &edi);
	mem_read(state, esi, size, &val);
	mem_write(state, edi, size, val);
	if (state->eflags & (1 << bit_df)) {
	    edi -= add;
	    esi -= add;
	} else {
	    edi += add;
	    esi += add;
	}
	write_reg(state, REG_ESI, esi);
	write_reg(state, REG_EDI, edi);
    } while (emu_prefix_post(state, instr->address_size, 1));
}

static always_inline void emu_pusha(cli_emu_t *state, instr_t *instr)
{
    uint32_t esp = state->reg_val[REG_ESP];
    if (instr->operation_size) {
	uint16_t data[8];
	/* 16 */
	esp -= 16;
	data[0] = le16_to_host(state->reg_val[REG_EDI]&0xffff);
	data[1] = le16_to_host(state->reg_val[REG_ESI]&0xffff);
	data[2] = le16_to_host(state->reg_val[REG_EBP]&0xffff);

	data[3] = le16_to_host(state->reg_val[REG_ESP]&0xffff);

	data[4] = le16_to_host(state->reg_val[REG_EBX]&0xffff);
	data[5] = le16_to_host(state->reg_val[REG_EDX]&0xffff);
	data[6] = le16_to_host(state->reg_val[REG_ECX]&0xffff);
	data[7] = le16_to_host(state->reg_val[REG_EAX]&0xffff);
	cli_emu_vmm_write(state->mem, esp, data, 16);
    } else {
	uint32_t data[8];
	/* 32 */
	esp -= 32;
	cli_writeint32(&data[0], state->reg_val[REG_EDI]);
	cli_writeint32(&data[1], state->reg_val[REG_ESI]);
	cli_writeint32(&data[2], state->reg_val[REG_EBP]);
	cli_writeint32(&data[3], state->reg_val[REG_ESP]);
	cli_writeint32(&data[4], state->reg_val[REG_EBX]);
	cli_writeint32(&data[5], state->reg_val[REG_EDX]);
	cli_writeint32(&data[6], state->reg_val[REG_ECX]);
	cli_writeint32(&data[7], state->reg_val[REG_EAX]);
	cli_emu_vmm_write(state->mem, esp, data, 32);
    }
    state->reg_val[REG_ESP] = esp;
}

static void write16reg(cli_emu_t *state, enum X86REGS reg, uint16_t val)
{
    state->reg_val[reg] &= 0xff00;
    state->reg_val[reg] |= val;
}

static always_inline void emu_popa(cli_emu_t *state, instr_t *instr)
{
    uint32_t esp = state->reg_val[REG_ESP];
    if (instr->operation_size) {
	uint16_t data[8];
	/* 16 */
	cli_emu_vmm_read_r(state->mem, esp, data, 16);
	write16reg(state, REG_EDI, le16_to_host(data[0]));
	write16reg(state, REG_EDX, le16_to_host(data[1]));
	write16reg(state, REG_ESI, le16_to_host(data[2]));
	write16reg(state, REG_EBP, le16_to_host(data[3]));
	write16reg(state, REG_EBX, le16_to_host(data[4]));
	write16reg(state, REG_EDX, le16_to_host(data[5]));
	write16reg(state, REG_ECX, le16_to_host(data[6]));
	write16reg(state, REG_EAX, le16_to_host(data[7]));
	esp += 16;
    } else {
	uint32_t data[8];
	/* 32 */
	cli_emu_vmm_read_r(state->mem, esp, data, 32);
	cli_writeint32(&state->reg_val[REG_EDI], data[0]);
	cli_writeint32(&state->reg_val[REG_EDX], data[1]);
	cli_writeint32(&state->reg_val[REG_ESI], data[2]);
	cli_writeint32(&state->reg_val[REG_EBP], data[3]);
	cli_writeint32(&state->reg_val[REG_EBX], data[4]);
	cli_writeint32(&state->reg_val[REG_EDX], data[5]);
	cli_writeint32(&state->reg_val[REG_ECX], data[6]);
	cli_writeint32(&state->reg_val[REG_EAX], data[7]);
	esp += 32;
    }
    state->reg_val[REG_ESP] = esp;
}

static always_inline void emu_scasx(cli_emu_t *state, instr_t *instr,
		     enum X86REGS reg, enum DIS_SIZE size, int8_t add)
{
    uint32_t edi;
    uint32_t src;
    uint32_t a;

    read_reg(state, instr->address_size ? REG_DI : REG_EDI, &edi);
    read_reg(state, reg, &a);
    if (emu_prefix_pre(state, instr->address_size, 0))
	return;
    do {
	desc_t reg_desc;
	mem_read(state, edi, size, &src);
	get_reg(state->mem, &reg_desc, reg);
	calc_flags_addsub(state, a, src, &reg_desc, 1);
	if (state->eflags & (1 << bit_df)) {
	    edi -= add;
	} else {
	    edi += add;
	}
	if (instr->address_size)
	    edi &= 0xffff;
    } while (emu_prefix_post(state, instr->address_size, 0));
    write_reg(state, instr->address_size ? REG_DI : REG_EDI, edi);
}

static always_inline void emu_stc(cli_emu_t *state, instr_t *instr)
{
    state->eflags |= 1 << bit_cf;
    state->eflags_def |= 1 << bit_cf;
}

static always_inline void emu_clc(cli_emu_t *state, instr_t *instr)
{
    state->eflags &= ~(1 << bit_cf);
    state->eflags_def |= 1 << bit_cf;
}
static always_inline void emu_xchg(cli_emu_t *state, instr_t *instr)
{
    //TODO: FS segment support, the rest of segments are equal anyway on win32
    uint32_t reg0, reg1;
    READ_OPERAND(reg0, 0);
    READ_OPERAND(reg1, 1);
    WRITE_RESULT(0, reg1);
    WRITE_RESULT(1, reg0);
}
static always_inline void emu_lea(cli_emu_t *state, instr_t *instr)
{
    const struct dis_arg *arg = &instr->arg[1];
    uint32_t addr = calcreg(state, arg);
    WRITE_RESULT(0, addr);
}

int cli_emulator_step(cli_emu_t *emu)
{
    struct dis_instr *instr;
    struct import_description *import;

    if (emu->eip >= MAPPING_END - 0x42) {
	if (emu->eip == MAPPING_END - 0x42) {
	    cli_dbgmsg("emulated program exited\n");
	    return -2;
	}
	if (emu->eip < MAPPING_END+4) {
	    cli_dbgmsg("emulated program jumped to first_import-4\n");
	    return -2;
	}
	import = cli_emu_vmm_get_import(emu->mem, emu->eip);
	if (import) {
	    if (import->handler(emu, import->description, import->bytes) < 0)
		return -1;
	    printf("=%d\n", emu->reg_val[REG_EAX]);
	    return 0;
	}
    }

    instr = disasm(emu);
    if (!instr) {
	printf("can't disasm\n");
	return -1;
    }
    emu->eip += instr->len;
    switch (instr->opcode) {
	case OP_MOV:
	    emu_mov(emu, instr);
	    break;
	case OP_MOVZX:
	    emu_movzx(emu, instr);
	    break;
	case OP_PUSH:
	    emu_push(emu, instr);
	    break;
	case OP_POP:
	    emu_pop(emu, instr);
	    break;
	case OP_PUSHFD:
	    emu_pushf(emu, instr);
	    break;
	case OP_POPFD:
	    emu_popf(emu, instr);
	    break;
	case OP_INC:
	    emu_inc(emu, instr);
	    break;
	case OP_DEC:
	    emu_dec(emu, instr);
	    break;
	case OP_CLD:
	    emu_cld(emu, instr);
	    break;
	case OP_STD:
	    emu_std(emu, instr);
	    break;
	case OP_LODSB:
	    emu_lodsx(emu, instr, SIZEB, REG_AL, 1);
	    break;
	case OP_LODSW:
	    emu_lodsx(emu, instr, SIZEW, REG_AX, 2);
	    break;
	case OP_LODSD:
	    emu_lodsx(emu, instr, SIZED, REG_EAX, 4);
	    break;
	case OP_STOSB:
	    emu_stosx(emu, instr, SIZEB, REG_AL, 1);
	    break;
	case OP_STOSW:
	    emu_stosx(emu, instr, SIZEW, REG_AX, 2);
	    break;
	case OP_STOSD:
	    emu_stosx(emu, instr, SIZED, REG_EAX, 4);
	    break;
	case OP_MOVSB:
	    emu_movsx(emu, instr, SIZEB, 1);
	    break;
	case OP_MOVSW:
	    emu_movsx(emu, instr, SIZEW, 2);
	    break;
	case OP_MOVSD:
	    emu_movsx(emu, instr, SIZED, 4);
	    break;
	case OP_XOR:
	    emu_xor(emu, instr);
	    break;
	case OP_AND:
	    emu_and(emu, instr);
	    break;
	case OP_TEST:
	    emu_test(emu, instr);
	    break;
	case OP_OR:
	    emu_or(emu, instr);
	    break;
	case OP_SUB:
	    emu_sub(emu, instr);
	    break;
	case OP_ADC:
	    emu_adc(emu, instr);
	    break;
	case OP_SBB:
	    emu_sbb(emu, instr);
	case OP_ADD:
	    emu_add(emu, instr);
	    break;
	case OP_MUL:
	    emu_mul(emu, instr);
	    break;
	case OP_SHL:
	    emu_shl(emu, instr);
	    break;
	case OP_SHR:
	    emu_shr(emu, instr);
	    break;
	case OP_SAR:
	    emu_sar(emu, instr);
	    break;
	case OP_ROL:
	    emu_rol(emu, instr);
	    break;
	case OP_ROR:
	    emu_ror(emu, instr);
	    break;
	case OP_LOOP:
	    emu_loop(emu, instr);
	    break;
	case OP_CMP:
	    emu_cmp(emu, instr);
	    break;
	case OP_JMP:
	    emu_jmp(emu, instr);
	    break;
	case OP_JECXZ:
	    if (!emu->reg_val[REG_ECX] ||
		(instr->operation_size == 2 && !emu->reg_val[REG_CX]))
		emu_jmp(emu, instr);
	    break;
	case OP_JO:
	    if (emu_flags(emu, bit_of) == 1)
		emu_jmp(emu, instr);
	    break;
	case OP_JNO:
	    if (emu_flags(emu, bit_of) == 0)
		emu_jmp(emu, instr);
	    break;
	case OP_JC:
	    if (emu_flags(emu, bit_cf) == 1)
		emu_jmp(emu, instr);
	    break;
	case OP_JNC:
	    if (emu_flags(emu, bit_cf) == 0)
		emu_jmp(emu, instr);
	    break;
	case OP_JZ:
	    if (emu_flags(emu, bit_zf) == 1)
		emu_jmp(emu, instr);
	    break;
	case OP_JNZ:
	    if (emu_flags(emu, bit_zf) == 0)
		emu_jmp(emu, instr);
	    break;
	case OP_JBE:
	    if (emu_flags(emu, bit_cf) == 1 || emu_flags(emu, bit_zf) == 1)
		emu_jmp(emu, instr);
	    break;
	case OP_JA:
	    if (emu_flags(emu, bit_cf) == 0 && emu_flags(emu, bit_zf) == 0)
		emu_jmp(emu, instr);
	    break;
	case OP_JS:
	    if (emu_flags(emu, bit_sf) == 1)
		emu_jmp(emu, instr);
	    break;
	case OP_JNS:
	    if (emu_flags(emu, bit_sf) == 0)
		emu_jmp(emu, instr);
	    break;
	case OP_JP:
	    if (emu_flags(emu, bit_pf) == 1)
		emu_jmp(emu, instr);
	    break;
	case OP_JNP:
	    if (emu_flags(emu, bit_pf) == 0)
		emu_jmp(emu, instr);
	    break;
	case OP_JL:
	    if (emu_flags(emu, bit_sf) != emu_flags(emu, bit_of))
		emu_jmp(emu, instr);
	    break;
	case OP_JGE:
	    if (emu_flags(emu, bit_sf) == emu_flags(emu, bit_of))
		emu_jmp(emu, instr);
	    break;
	case OP_JLE:
	    if (emu_flags(emu, bit_zf) == 1 ||
		emu_flags(emu, bit_sf) != emu_flags(emu, bit_of))
		emu_jmp(emu, instr);
	    break;
	case OP_JG:
	    if (emu_flags(emu, bit_zf) == 0 &&
		    emu_flags(emu, bit_sf) == emu_flags(emu, bit_of))
		emu_jmp(emu, instr);
	    break;
	case OP_CALL:
	    emu_call(emu, instr);
	    break;
	case OP_RETN:
	    emu_ret(emu, instr);
	    break;
	case OP_PUSHAD:
	    emu_pusha(emu, instr);
	    break;
	case OP_POPAD:
	    emu_popa(emu, instr);
	    break;
	case OP_LEA:
	    emu_lea(emu, instr);
	    break;
	case OP_XCHG:
	    emu_xchg(emu, instr);
	    break;
	case OP_SCASB:
	    emu_scasx(emu, instr, REG_AL, SIZEB, 1);
	    break;
	case OP_SCASW:
	    emu_scasx(emu, instr, REG_AX, SIZEW, 2);
	    break;
	case OP_SCASD:
	    emu_scasx(emu, instr, REG_EAX, SIZED, 4);
	    break;
	case OP_CLC:
	    emu_clc(emu, instr);
	    break;
	case OP_STC:
	    emu_stc(emu, instr);
	    break;
	case OP_NOP:
	    /* NOP is nop */
	    break;
	case OP_BSWAP:
	    emu_bswap(emu, instr);
	    break;
	case OP_INT3:
	    cli_emu_vmm_raise(emu->mem, -EMU_ERR_INT3, emu->eip);
	    break;
	case OP_LEAVE:
	    emu_leave(emu, instr);
	    break;
	case OP_PREFIX_REPE:
	    emu->prefix_repe = 1;
	    /* TODO: check if prefix is valid in next instr */
	    /* TODO: only take into account last rep prefix, so just use one var
	     * here */
	    return 0;
	case OP_PREFIX_REPNE:
	    emu->prefix_repne = 1;
	    return 0;
	case OP_PREFIX_LOCK:
	    return 0;
	default:
	    cli_dbgmsg("opcode not yet implemented\n");
	    return -1;
    }
    emu->prefix_repe = 0;
    emu->prefix_repne = 0;
    return 0;
}

static const char flags_display[] = "aVR-N--ODITSZ-A-P-C";
void cli_emulator_dbgstate(cli_emu_t *emu)
{
    char flags[sizeof(flags_display)];
    uint32_t i, j;
    uint32_t eflags = emu->eflags;

    for (i=0,j=sizeof(flags_display)-2;i<sizeof(flags_display)-1;i++,j--) {
	if (flags_display[i] == '-') {
	    flags[i] = '-';
	    continue;
	}
	if (eflags & (1 << j)) {
	    flags[i] = flags_display[i];
	}
	else
	    flags[i] = ' ';
    }
    flags[i] = '\0';

    cli_dbgmsg("Register dump:\n"
	       "EIP:%08x ESP:%08x EBP:%08x EFLAGS:%08x(%s)\n"
	       "EAX:%08x EBX:%08x ECX:%08x EDX:%08x\n"
	       "ESI:%08x EDI:%08x\n",
	       emu->eip, emu->reg_val[REG_ESP], emu->reg_val[REG_EBP],
	       eflags, flags,
	       emu->reg_val[REG_EAX], emu->reg_val[REG_EBX],
	       emu->reg_val[REG_ECX], emu->reg_val[REG_EDX],
	       emu->reg_val[REG_ESI], emu->reg_val[REG_EDI]);
}

int hook_generic_stdcall(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    if (bytes != 254) {
	printf("Called stdcall API %s@%d\n", desc ? desc : "??", bytes);
	cli_dbgmsg("Called stdcall API %s@%d\n", desc ? desc : "??", bytes);
	mem_pop(emu, 4, &emu->eip);
	emu->reg_val[REG_ESP] += bytes;
	emu->reg_val[REG_EAX] = 0;
	return 0;
    } else {
	/* 254 - magic for varargs */
	printf("Called varargs API %s\n", desc ? desc : "??");
	mem_pop(emu, 4, &emu->eip);
	emu->reg_val[REG_EAX] = 0;
	/* caller cleans up */
	return 0;
    }
}

static const uint8_t seh_code[] = {
    0xff, 0xd0,
    0x83, 0xf8, 0x00,
    0x75, 0x28,
    0x8b, 0x44, 0x24, 0x08,
    0x8b, 0xa0, 0xc4, 0x00, 0x00, 0x00,
    0xff, 0xb0, 0xb8, 0x00, 0x00, 0x00,
    0x89, 0xa0, 0xc4, 0x00, 0x00, 0x00,
    0x8d, 0xa0, 0x9c, 0x00, 0x00, 0x00,
    0x5f, 0x5e, 0x5b, 0x5a, 0x59, 0x58, 0x5d,
    0x8b, 0x64, 0x24, 0x0c,
    0xc3,
    0x8b, 0x44, 0x24, 0x0c,
    0x8b, 0x58, 0x04,
    0x89, 0x5c, 0x24, 0x0c,
    0x8b, 0x00,
    0xeb, 0xc2
};
/*
 * 00401000 <foo>:
  401000:       ff d0                   call   *%eax
  401002:       83 f8 00                cmp    $0x0,%eax
  401005:       75 28                   jne    40102f <foo+0x2f>
  401007:       8b 44 24 08             mov    0x8(%esp),%eax
  40100b:       8b a0 c4 00 00 00       mov    0xc4(%eax),%esp
  401011:       ff b0 b8 00 00 00       pushl  0xb8(%eax)
  401017:       89 a0 c4 00 00 00       mov    %esp,0xc4(%eax)
  40101d:       8d a0 9c 00 00 00       lea    0x9c(%eax),%esp
  401023:       5f                      pop    %edi
  401024:       5e                      pop    %esi
  401025:       5b                      pop    %ebx
  401026:       5a                      pop    %edx
  401027:       59                      pop    %ecx
  401028:       58                      pop    %eax
  401029:       5d                      pop    %ebp
  40102a:       8b 64 24 0c             mov    0xc(%esp),%esp
  40102e:       c3                      ret    
  40102f:       8b 44 24 0c             mov    0xc(%esp),%eax
  401033:       8b 58 04                mov    0x4(%eax),%ebx
  401036:       89 5c 24 0c             mov    %ebx,0xc(%esp)
  40103a:       8b 00                   mov    (%eax),%eax
  40103c:       eb c2                   jmp    401000 <foo>

 */
int cli_emulator_seh(cli_emu_t *emu, int rc)
{
    EXCEPTION_REGISTRATION_RECORD record;
    CONTEXT context;
    uint32_t recordaddr, contextaddr, seh_code_addr;
    uint32_t seh_handler_addr, next_addr;

    if (emu->in_seh) {
	printf("exception raised while handling exception\n");
	return -1;
    }
    emu->in_seh = 1;
    cli_emu_vmm_read32(emu->mem, emu->mem->fs_offset, &seh_handler_addr);
    if (!seh_handler_addr) {
	emu->in_seh = 0;
	return -1;
    }
    cli_emu_vmm_read32(emu->mem, seh_handler_addr, &next_addr);
    cli_emu_vmm_read32(emu->mem, seh_handler_addr+4, &seh_handler_addr);

    memset(&record, 0, sizeof(record));
    memset(&context, 0, sizeof(context));
    record.ExceptionAddress = emu->mem->except_addr;
    switch (-rc) {
	case EMU_ERR_VMM_READ:
	case EMU_ERR_VMM_WRITE:
	    record.ExceptionCode = 0xC0000005;
	    break;
	case EMU_ERR_INT3:
	    record.ExceptionCode = 0x80000003;
	    break;
	default:
	    record.ExceptionFlags = 1;
	    record.ExceptionCode = 0xC000001D;
	    break;
    }
    context.Edi = emu->reg_val[REG_EDI];
    context.Esi = emu->reg_val[REG_ESI];
    context.Ebx = emu->reg_val[REG_EBX];
    context.Edx = emu->reg_val[REG_EDX];
    context.Ecx = emu->reg_val[REG_ECX];
    context.Eax = emu->reg_val[REG_EAX];
    context.Ebp = emu->reg_val[REG_EBP];
    context.Eip = emu->eip;
    context.EFlags = emu->eflags;
    context.Esp = emu->reg_val[REG_ESP];
    cli_emu_vmm_alloc(emu->mem, 4096, &recordaddr);
    cli_emu_vmm_write(emu->mem, recordaddr, &record, sizeof(record));
    contextaddr = recordaddr + sizeof(record);
    cli_emu_vmm_write(emu->mem, contextaddr, &context, sizeof(context));
    seh_code_addr = contextaddr + sizeof(context);
    cli_emu_vmm_write(emu->mem, seh_code_addr, seh_code, sizeof(seh_code));

    mem_push(emu, 4, next_addr);/* dispatchercontext ??*/
    mem_push(emu, 4, contextaddr);/* contextrecord */
    mem_push(emu, 4, emu->reg_val[REG_ESP]);/* establisherframe */
    mem_push(emu, 4, recordaddr);/* exceptionrecord */

    emu->reg_val[REG_EAX] = seh_handler_addr;
    emu->eip = seh_code_addr;
    emu->in_seh = 0;
    return 0;
}

