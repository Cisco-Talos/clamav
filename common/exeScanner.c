/*
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2005-2010 Gianluigi Tiesi <sherpya@netfarm.it>
 *
 *  Authors: Gianluigi Tiesi
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

#include "exescanner.h"

/* -1 = wildchar - -2 = stop here */
sigs_t signatures[] = {
    {{0x60, 0xbe, -1, -1, -1, -1, 0x8d, 0xbe, -1, -1, -1, 0xff, 0x57, -2},
     "UPX",
     .0f},
    {{0x94, 0xbc, 0x5d, 0x07, 0x42, 0x00, 0xb9, 0x1d, 0x00, 0x00, 0x00, 0x80,
      0x34, 0x0c, 0x44, 0xe2},
     "UPXSHiT",
     .0f},
    {{0xbe, 0xa4, 0x01, 0x40, 0x00, 0xad, 0x93, 0xad, 0x97, 0xad, 0x56, 0x96,
      0xb2, 0x80, 0xa4, 0xb6},
     "FSG 1.33",
     .0f},
    {{0x4d, 0x5a, -1, -1, -1, -1, -1, -1, -1, -1, 0x00, 0x00, 0x50, 0x45, 0x00,
      0x00},
     "FSG 2.00",
     .0f},
    {{0x4d, 0x5a, 0x4b, 0x45, 0x52, 0x4e, 0x45, 0x4c, 0x33, 0x32, 0x2e, 0x44,
      0x4c, 0x4c, 0x00, 0x00},
     "WinUpack 0.39",
     .0f},
    {{0xbe, 0x88, 0x01, 0x40, 0x00, 0xad, 0x8b, 0xf8, 0x95, 0xad, 0x91, 0xf3,
      0xa5, 0xad, 0xb5, 0x1c},
     "Upack 2.4/2.9",
     .0f},
    {{0xbe, 0x48, 0x01, 0x40, 0x00, 0xad, 0x8b, 0xf8, 0x95, 0xa5, 0x33, 0xc0,
      0x33, 0xc9, 0xab, 0x48},
     "Upack 1.1/1.2",
     .0f},
    {{0x83, 0xec, 0x20, 0x53, 0x55, 0x56, 0x33, 0xdb, 0x57, 0x89, 0x5c, 0x24,
      0x18, 0xc7, 0x44, 0x24},
     "NullSoft PiMP",
     .0f},
    {{0xe9, -1, -1, -1, 0xff, 0x0c, -1, -1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00},
     "Mew 11 1.2",
     .0f},
    {{0x60, 0xe9, 0x3d, 0x04, 0x00, 0x00, -2}, "ASPack 2.11", .0f},
    {{0x60, 0xe8, 0x03, 0x00, 0x00, 0x00, 0xe9, 0xeb, 0x04, 0x5d, 0x45, 0x55,
      0xc3, 0xe8, 0x01, 0x00},
     "ASPack 2.12",
     .0f},
    {{0x55, 0x83, 0xc4, 0x04, 0x76, 0x08, 0x7a, 0x06, 0x74, 0x04, 0x66, 0x83,
      0xea, 0x00, 0xf5, 0x50},
     "Morphine 1.4/2.7",
     .0f},
    {{0x56, 0x72, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x0b, 0xd2, 0xf9,
      0x84, 0xdb, 0x68, 0x34},
     "Morphine 1.4/2.7 [2]",
     .0f},
    {{0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x5d,
      0x8b, 0xd5, 0x81, 0xed},
     "PEDiminisher 0.1",
     .0f},

    {{0xe8, 0xf6, 0x03, 0x00, 0x00, 0xe9, 0x9e, 0xfd, 0xff, 0xff, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc},
     "MSVC8 Release",
     -1.0f},
    {{0xe9, -1, -1, -1, 0x00, 0xe9, -1, -1, -1, 0x00, 0xe9, -1, -1, -1, 0x00,
      0xe9},
     "MSVC8 Debug",
     -1.0f},

    {{0xe8, -1, -1, 0x00, 0x00, 0xe9, 0x16, 0xfe, 0xff, 0xff, -2},
     "MSVC6 Release",
     -2.0f},

    {{0xe9, 0x96, 0xee, 0x0e, 0x00, 0xb8, 0x6c, 0x02, 0x58, 0x00, 0xe8, 0xae,
      0xe4, 0x0e, 0x00, 0x83},
     "MSVC6 Release (2)",
     -1.0f},
    {{0x55, 0x8b, 0xec, 0x6a, 0xff, 0x68, 0xb0, 0x41, 0x40, 0x00, 0x68, 0x10,
      0x36, 0x40, 0x00, 0x64},
     "MSVC6 Release (3)",
     -1.0f},
    {{0x55, 0x8b, 0xec, 0x53, 0x8b, 0x5d, 0x08, 0x56, 0x8b, 0x75, 0x0c, 0x57,
      0x8b, 0x7d, 0x10, 0x85},
     "MSVC6 Release (4)",
     -1.0f},

    {{0x83, 0x7c, 0x24, 0x08, 0x01, 0x75, 0x05, 0xe8, -1, -1, 0x00, 0x00, 0xff,
      0x74, 0x24, 0x04},
     "MSVC6 Release DLL",
     -1.0f},
    {{0xff, 0x25, -1, -1, -1, -1, 0xcc, 0xcc, 0x03, 0x30, 0x01, 0x00, 0x07,
      0x00, 0x00, 0x00},
     "DotNet",
     -1.0f},
    {{0x55, 0x89, 0xe5, -2}, "MinGW", -1.0f},
    {{0}, 0, 0}};

int sigcmp(const uint8_t *data, const int16_t *sig, size_t n)
{
    uint8_t *d = (uint8_t *)data;
    int16_t *s = (int16_t *)sig;
    while (n-- != 0) {
        if (*s == -2)
            return 0;
        if ((*s != -1) && (*d != *s))
            return (*d < *s) ? -1 : +1;
        d++;
        s++;
    }
    return 0;
}

sigs_t *checksig(uint8_t *data)
{
    int i = 0;
    while (signatures[i].name) {
        if (!sigcmp(data, signatures[i].sig, 16))
            return &signatures[i];
        i++;
    }
    return NULL;
}

double calc_entropy(const unsigned char *data, size_t size)
{
    double entropy = .0f;
    size_t p[256];
    size_t c, i;

    memset(p, 0, sizeof(p));

    for (c = 0; c < size; c++)
        p[data[c]]++;

    for (i = 0; i < 256; i++)
        if (p[i])
            entropy -= ((double)p[i] / size) * log((double)p[i] / size);
    return entropy;
}

#define FILLBYTES(dst)                                    \
    if (IsBadReadPtr(seek, sizeof(dst))) {                \
        logg(LOGG_ERROR, "exeScanner: Bad pointer!!!\n"); \
        goto cleanup;                                     \
    }                                                     \
    memcpy(&dst, seek, sizeof(dst));

/* Packed exe heuristic detection, errors are handled as like of non packed data
 */
int is_packed(const char *filename)
{
    int packed = 0;
    int i = 0, c = 0;
    int badsection = 0;
    double entropy = 0.0;
    sigs_t *sig    = NULL;
    uint16_t e_mz;
    uint32_t e_lfanew, e_magic;
    uint32_t epoff      = 0;
    unsigned char *seek = NULL, *s_start = NULL, *ep = NULL, *lpMapAddress = NULL;
    PIMAGE_FILE_HEADER pehdr;
    PIMAGE_OPTIONAL_HEADER32 opthdr;
    PIMAGE_SECTION_HEADER sechdr;
    char secname[IMAGE_SIZEOF_SHORT_NAME];

    HANDLE hFile = INVALID_HANDLE_VALUE, hMapFile = NULL;

    hFile = CreateFileA(filename, GENERIC_READ, 0, NULL, OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        elogg(LOGG_INFO, "exeScanner: CreateFileA failed %lu\n", GetLastError());
        return packed; /* Returning packed, the module is loaded so it must exists
                      on disk */
    }

    hMapFile = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, "exeScanner");
    if (!hMapFile) {
        elogg(LOGG_INFO, "exeScanner: CreateFileMappingA() failed %lu\n", GetLastError());
        goto cleanup;
    }

    lpMapAddress = (LPBYTE)MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
    if (!lpMapAddress) {
        elogg(LOGG_INFO, "exeScanner: MapViewOfFile() failed %lu\n", GetLastError());
        goto cleanup;
    }

    seek = lpMapAddress;

    /* DOS Signature 'MZ' */
    FILLBYTES(e_mz);
    if (e_mz != IMAGE_DOS_SIGNATURE) {
        elogg(LOGG_INFO, "exeScanner: DOS Signature not found\n");
        goto cleanup;
    }

    seek += 0x3c;

    FILLBYTES(e_lfanew);
    if (!e_lfanew) {
        elogg(LOGG_INFO, "exeScanner: Invalid PE offset\n");
        goto cleanup;
    }
    seek = lpMapAddress + e_lfanew;

    /* PE Signature 'PE' */
    FILLBYTES(e_magic);
    if (e_magic != IMAGE_NT_SIGNATURE) {
        elogg(LOGG_INFO, "exeScanner: PE Signature not found\n");
        goto cleanup;
    }
    seek += sizeof(e_magic);

    if (IsBadReadPtr(seek, sizeof(IMAGE_FILE_HEADER)))
        goto cleanup;
    pehdr = (PIMAGE_FILE_HEADER)seek;
    seek += sizeof(IMAGE_FILE_HEADER);

    if (IsBadReadPtr(seek, sizeof(IMAGE_OPTIONAL_HEADER32)))
        goto cleanup;
    opthdr = (PIMAGE_OPTIONAL_HEADER32)seek;
    seek += sizeof(IMAGE_OPTIONAL_HEADER32);

    if (pehdr->Machine != IMAGE_FILE_MACHINE_I386) {
        elogg(LOGG_INFO, "exeScanner: Not an x86 executable\n");
        goto cleanup;
    }

    /* Invalid sections number */
    if ((pehdr->NumberOfSections < 1) || (pehdr->NumberOfSections > 32)) {
        elogg(LOGG_INFO, "exeScanner: Invalid sections number\n");
        packed = 1;
        goto cleanup;
    }

    for (i = 0; i < pehdr->NumberOfSections; i++) {
        double section_entropy = .0f;
        if (IsBadReadPtr(seek, sizeof(IMAGE_SECTION_HEADER)))
            goto cleanup;
        sechdr = (PIMAGE_SECTION_HEADER)seek;
        seek += sizeof(IMAGE_SECTION_HEADER);

        if (opthdr->AddressOfEntryPoint >= sechdr->VirtualAddress)
            epoff = opthdr->AddressOfEntryPoint - sechdr->VirtualAddress +
                    sechdr->PointerToRawData;

        s_start = lpMapAddress + sechdr->PointerToRawData;
        if (!IsBadReadPtr(s_start, sechdr->SizeOfRawData))
            section_entropy = calc_entropy(s_start, sechdr->SizeOfRawData);

        entropy = MAX(entropy, section_entropy);

        /* Sanitize the section name */
        memcpy(secname, sechdr->Name, IMAGE_SIZEOF_SHORT_NAME);
        for (c = 0; (c < IMAGE_SIZEOF_SHORT_NAME) && secname[c]; c++)
            if (!isprint(secname[c]))
                secname[c] = '?';
        secname[IMAGE_SIZEOF_SHORT_NAME - 1] = 0;

        elogg(LOGG_INFO, "exeScanner: Section name: [%s] - Entropy %f\n", secname,
              section_entropy);

        if (!sechdr->SizeOfRawData)
            badsection = 1;
    }

    elogg(LOGG_INFO, "exeScanner: Max entropy = %f\n", entropy);
    /* EP Check */
    elogg(LOGG_INFO, "exeScanner: Entry Point rva: 0x%lx - raw: 0x%lx\n",
          opthdr->AddressOfEntryPoint, epoff);

    ep = lpMapAddress + epoff;
    if (!IsBadReadPtr(ep, EP_SIGNATURE_SIZE)) {
#ifdef DUMP_SIGNATURE
        int i;
        for (i = 0; i < EP_SIGNATURE_SIZE; i++)
            elogg(LOGG_INFO, "%02x ", ep[i]);
        elogg(LOGG_INFO, "\n[C Code]: ");
        for (i = 0; i < EP_SIGNATURE_SIZE - 1; i++)
            elogg(LOGG_INFO, "0x%02x, ", ep[i]);
        elogg(LOGG_INFO, "0x%02x\n", ep[i]);
#endif
        if ((sig = checksig(ep))) {
            elogg(LOGG_INFO, "exeScanner: Signature check: %s\n", sig->name);
            entropy += sig->score;
            packed = (sig->score >= .0f);
            if (sig->score < .0f)
                elogg(
                    "exeScanner: Whitelisted signature found, lowering entropy to %f\n",
                    entropy);
        } else
            elogg(LOGG_INFO, "exeScanner: Signature check: Nothing found\n");
    } else
        elogg(LOGG_INFO, "exeScanner: Invalid address of Entry Point\n");

    if (badsection) {
        if ((entropy == .0f) || (entropy > ENTROPY_THRESHOLD)) {
            elogg(LOGG_INFO, "exeScanner: found zero SizeOfRawData and entropy %f\n", entropy);
            packed = 1;
            goto cleanup;
        }
    }

cleanup:
    if (lpMapAddress)
        UnmapViewOfFile(lpMapAddress);
    if (hMapFile)
        CloseHandle(hMapFile);
    CloseHandle(hFile);
    return packed;
}
