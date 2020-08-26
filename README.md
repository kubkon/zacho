# zacho

...or Zig's Mach-O parser. This project reinforces my understanding of the Mach-O file format
since I am the one who is, well, trying to come up with a well designed (static) Mach-O linker
in Zig's stage2 compiler toolchain.

Anyway, this project might be a bit of a roller-coaster ride: I might add a lot of features at
once, just to then leave the project for a prolonged period of time. Fear not, this will most
likely be because I am busy implementing the linker proper.

## Building and running

To build it, get yourself a copy of stage1 Zig compiler, and run

```zig
$ zig build
```

The generated binary expects you pass a path to a Mach-O file. For example, for a simple
binary which invokes exit syscall

```asm
.section __TEXT,__text
.globl _main
_main:
  mov $0x2000001, %rax
  mov $1, %rbx
  syscall
```

Running `zacho` on the generated Mach-O file would yield

```
Header {
  Magic number: 0xfeedfacf
  CPU type: 0x1000007
  CPU sub-type: 0x3
  File type: 0x2
  Number of load commands: 14
  Size of load commands: 744
  Flags: 0x200085
  Reserved: 0x0
}

Load command {
  Command: LC_SEGMENT_64
  Command size: 72
  Segment name: __PAGEZERO
  VM address: 0x0000000000000000
  VM size: 4294967296
  File offset: 0x0000000000000000
  File size: 0
  Maximum VM protection: 0x0
  Initial VM protection: 0x0
  Number of sections: 0
  Flags: 0x0
  Sections: {
  }
}
Load command {
  Command: LC_SEGMENT_64
  Command size: 232
  Segment name: __TEXT
  VM address: 0x0000000100000000
  VM size: 4096
  File offset: 0x0000000000000000
  File size: 4096
  Maximum VM protection: 0x5
  Initial VM protection: 0x5
  Number of sections: 2
  Flags: 0x0
  Sections: {
    {
      Section name: __text
      Segment name: __TEXT
      Address: 0x0000000100000fa8
      Size: 16
      Offset: 0x0000000000000fa8
      Alignment: 0
      Relocations offset: 0x0000000000000000
      Number of relocations: 0
      Flags: 0x80000400
      Reserved1 : 0x0
      Reserved2: 0
      Reserved3: 0
    }
    {
      Section name: __unwind_info
      Segment name: __TEXT
      Address: 0x0000000100000fb8
      Size: 72
      Offset: 0x0000000000000fb8
      Alignment: 2
      Relocations offset: 0x0000000000000000
      Number of relocations: 0
      Flags: 0x0
      Reserved1 : 0x0
      Reserved2: 0
      Reserved3: 0
    }
  }
}
Load command {
  Command: LC_SEGMENT_64
  Command size: 72
  Segment name: __LINKEDIT
  VM address: 0x0000000100001000
  VM size: 4096
  File offset: 0x0000000000001000
  File size: 152
  Maximum VM protection: 0x1
  Initial VM protection: 0x1
  Number of sections: 0
  Flags: 0x0
  Sections: {
  }
}
Load command {
  Command: 2147483682(??)
  Command size: 48
  Raw contents: 0x00000000000000000000000000000000000000000000000000000000000000000010000030000000
}
Load command {
  Command: 2(??)
  Command size: 24
  Raw contents: 0x38100000030000006810000030000000
}
Load command {
  Command: 11(??)
  Command size: 80
  Raw contents: 0x000000000000000000000000020000000200000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
}
Load command {
  Command: 14(??)
  Command size: 32
  Raw contents: 0x0c0000002f7573722f6c69622f64796c6400000000000000
}
Load command {
  Command: 27(??)
  Command size: 24
  Raw contents: 0xcc0b056566ae3dc38c5e542ccaa19ab0
}
Load command {
  Command: 50(??)
  Command size: 32
  Raw contents: 0x01000000000f0a0000000000010000000300000000062c02
}
Load command {
  Command: 42(??)
  Command size: 16
  Raw contents: 0x0000000000000000
}
Load command {
  Command: 2147483688(??)
  Command size: 24
  Raw contents: 0xa80f0000000000000000000000000000
}
Load command {
  Command: 12(??)
  Command size: 56
  Raw contents: 0x180000000200000000000100000001002f7573722f6c69622f6c696253797374656d2e422e64796c6962000000000000
}
Load command {
  Command: 38(??)
  Command size: 16
  Raw contents: 0x3010000008000000
}
Load command {
  Command: 41(??)
  Command size: 16
  Raw contents: 0x3810000000000000
}

__TEXT
file = { 0, 4096 }
address = { 0x0000000100000000, 0x0000000100001000 }

  __TEXT,__text
  file = { 4008, 4024 }
  address = { 0x0000000100000fa8, 0x0000000100000fb8 }

  0x48c7c00100000248c7c3010000000f05

  __TEXT,__unwind_info
  file = { 4024, 4096 }
  address = { 0x0000000100000fb8, 0x0000000100001000 }

  0x010000001c000000000000001c000000000000001c00000002000000a80f00003400000034000000b90f00000000000034000000030000000c000100100001000000000000000000

__LINKEDIT
file = { 4096, 4248 }
address = { 0x0000000100001000, 0x0000000100002000 }

```
