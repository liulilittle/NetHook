# NetHook
it is a can make .net / clr applications can be the underlying hook winapi, and modify api execution flow. 

you can use it to accomplish want in RING3 layer any hook a winapi.
in the open source code, contains a code demo.

in the nethook use the code asm code.
1. x86 // E9 00 00 00 00
    jmp rva

2. x64 // 48 B8 00 00 00 00 00 00 00 00 FF E0
   mov rax, va
   jmp rax

but of course, there are many ways, and not just above two, for example, in x64, you also can do.
  mov rax, va // 48H B8H XX XX XX XX XX XX XX XX 50H C3H
  push rax
  ret
