.intel_syntax noprefix
.globl foo
foo:
   call eax
   cmp eax, 0
   jne .L_continue_search
.L_continue:
   mov eax, [esp+8]
   mov esp, [eax + 0xc4];//esp
   push [eax + 0xb8];//eip
   mov [eax + 0xc4], esp;//modified esp
   lea esp, [eax + 0x9c];//edi
   pop edi
   pop esi
   pop ebx
   pop edx
   pop ecx
   pop eax
   pop ebp
   mov esp, [esp+12]
   ret
.L_continue_search:
   mov eax, [esp+12];//next seh registration
   mov ebx, [eax+4];//next next seh reg.
   mov [esp+12], ebx
   mov eax, [eax];//next seh reg's handler
   jmp foo
