# rp++: a fast ROP gadget finder for PE/ELF/Mach-O x86/x64/ARM/ARM64 binaries

![Builds](https://github.com/0vercl0k/rp/workflows/Builds/badge.svg)

## Overview

**rp++** or **rp** is a C++ [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) gadget finder for [PE](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)/[ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)/[Mach-O](https://en.wikipedia.org/wiki/Mach-O) executables and x86/x64/ARM/ARM64 architectures.

<p align='center'>
<img src='pics/rp.gif'>
</p>

## Finding ROP gadgets

To find ROP gadget you need to specify a file with the `--file` / `-f` option and use the `--rop` / `-r` option specifying the maximum the number of instructions in the gadget:

<p align='center'>
<img src='pics/rp-r.gif'>
</p>

You can customize the base address of the module with the `--va` option (if you pass a base of `0`, then you get relative offsets) and you can also use the `--raw` option to analyze raw code dumps.

## Finding pointers

Oftentimes when building ROP chains, you might need to find pointers to integers with specific values. To look for those, you can use the `--search-int` option like in the below:

<p align='center'>
<img src='pics/rp-sint.gif'>
</p>

Other times, you might need to find pointers to specific strings. To look for those, you can use the `--search-hexa` option like in the below:

<p align='center'>
<img src='pics/rp-shexa.gif'>
</p>

You can also use the `--va` option to specify your own base address.

## Build

You can find shell scripts in [src/build](src/build) for every supported platforms; below is the Linux example:

```
src/build$ chmod u+x ./build-release.sh && ./build-release.sh
-- The C compiler identification is GNU 9.3.0
-- The CXX compiler identification is GNU 9.3.0
[...]
[16/16] Linking CXX executable rp-lin-x64
```

## WinDBG extension

rp++ can also be built as a WinDBG extension, so gadgets can be found from inside the debugger against the module currently being debugged. This is an opt-in build flavour selected with the `RP_WINDBG_EXT` CMake option (default `OFF`); the standalone executable is unaffected.

The rp++ core is shared unchanged between the two builds: only the entry point differs (`rp/main.cpp` for the executable, `windbg/rp_windbg.cpp` for the extension), and the extension is a plain consumer of the existing core API.

Build the extension into its own directory:

```
cmake -S src -B src/build-ext -DRP_WINDBG_EXT=ON
cmake --build src/build-ext --config RelWithDebInfo
```

Then load it in WinDBG and invoke `!rp` with the same options as the command line tool (passed as a single string). With no `-f` / `--file`, the current debuggee's main module is analyzed:

```
0:000> .load rp.dll
0:000> !rp --rop 5 --unique
```

## Authors

* Axel '[0vercl0k](https://twitter.com/0vercl0k)' Souchet
