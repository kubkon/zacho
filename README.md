# zacho

...or Zig's Mach-O parser. This project started off as a dummy scratchpad for reinforcing my
understanding of the Mach-O file format while I was working on the Zig's stage2 Mach-O linker
(I still am working on it, in case anyone was asking).

My current vision for `zacho` is for it to be a cross-platform version of `otool` and `pagestuff`
macOS utilities. These seem to be very useful when battling the Darwin kernel and `dyld` when those
refuse to load your hand-crafter binary, or you just like looking at Mach-O dissected output.

## Usage

```
Usage: zacho [options] file

General options:
-c, --code-signature        Print the contents of code signature (if any)
-d, --dyld-info             Print the contents of dyld rebase and bind opcodes
-e, --exports-trie          Print export trie (if any)
-h, --header                Print the Mach-O header
-i, --indirect-symbol-table Print the indirect symbol table
-l, --load-commands         Print load commands
-r, --relocations           Print relocation entries (if any)
-s, --symbol-table          Print the symbol table
-u, --unwind-info           Print the contents of (compact) unwind info section (if any)
-v, --verbose               Print more detailed info for each flag
--archive-index             Print archive index (if any)
--string-table              Print the string table
--data-in-code              Print data-in-code entries (if any)
--hex-dump=[name]           Dump section contents as bytes
--string-dump=[name]        Dump section contents as strings
--verify-memory-layout      Print virtual memory layout and verify there is no overlap
--help                      Display this help and exit
```

## Building from source

Building from source requires nightly [Zig](https://ziglang.org/download/).

```
$ git clone https://github.com/kubkon/zacho.git
$ zig build
```

Additionally, on macOS, you will need to provide Foundation and Security frameworks.
