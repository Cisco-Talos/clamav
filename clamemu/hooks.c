/*
 *  ClamAV bytecode emulator VMM
 *
 *  Copyright (C) 2011 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
#include "imports.h"
const struct hook_desc user32_dll_hooks[] = {
};

const struct hook_desc kernel32_dll_hooks[] = {
};

const struct hook_desc wsock32_dll_hooks[] = {
};
const unsigned user32_dll_hooks_n = sizeof(user32_dll_hooks)/sizeof(user32_dll_hooks[0]);
const unsigned kernel32_dll_hooks_n = sizeof(kernel32_dll_hooks)/sizeof(kernel32_dll_hooks[0]);
const unsigned wsock32_dll_hooks_n = sizeof(wsock32_dll_hooks)/sizeof(wsock32_dll_hooks[0]);
