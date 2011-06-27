.intel_syntax noprefix
.globl _main
_main:
mov esi, offset flat:_foo
mov ecx, 10000000
back:
xor byte ptr [esi], 0x42
loop back
ret
.comm _foo, 10000000
