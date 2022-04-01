# zacho

...or Zig's Mach-O parser. This project started off as a dummy scratchpad for reinforcing my
understanding of the Mach-O file format while I was working on the Zig's stage2 Mach-O linker
(I still am working on it, in case anyone was asking).

My current vision for `zacho` is for it to be a cross-platform version of `otool` and `pagestuff`
macOS utilities. These seem to be very useful when battling the Darwin kernel and `dyld` when those
refuse to load your hand-crafter binary, or you just like looking at Mach-O dissected output.

## Usage

```
zacho --help
zacho [-hl] [--help] <FILE>
	    --help         	   Display this help and exit.
	-h, --header       	   Print the Mach-O header.
	-l, --load-commands	   Print load commands.
  -c, --code-signature   Print the contents of code signature (if any).
```

Currently, `zacho` will let you print parsed Mach-O header, and print formatted load commands.
I should point here out that I'm basing the flags on `otool` so if you're familiar with those,
`zacho` should feel like second home to you.

## Building from source

Building from source requires [Zig nightly](https://ziglang.org/download/).

```
$ git clone https://github.com/kubkon/zacho.git --recursive
$ zig build
```
