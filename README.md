# rp++

Windows:
[![Build status](https://ci.appveyor.com/api/projects/status/2s47yk2vl30a3wsy?svg=true)](https://ci.appveyor.com/project/0vercl0k/rp)

Linux/OSX:
[![Build Status](https://travis-ci.org/0vercl0k/rp.svg?branch=master)](https://travis-ci.org/0vercl0k/rp)

## Description

rp++ is a full-cpp written tool that aims to find ROP sequences in PE/Elf/Mach-O (doesn't support the FAT binaries) x86/x64/ARM binaries.

It is open-source, sort-of documented with Doxygen and has been tested on several OS: Ubuntu14 / Windows 8.1 / Mac OSX Lion (10.7.3). Moreover, it is x64 compatible.

By the way, the tool is a standalone executable ; you will upload static-compiled binaries for each OS.

There are also some other things you will be able to do with rp++, like finding hexadecimal values, or strings, etc. ; it's always handy to have those kind of features during CTFs for example.


## It's quite fast

Yeah, here are some benchmarks I have done on my personal laptop (Win7 x64, Intel i7 Q720 @ 1.6GHz, 4GB RAM -- quite some times ago though, it's just to give you an idea of what you can expect):

	- Target: ntoskrnl.exe x64 version 6.1.7601.17790
		D:\rp-win-x64.exe --file=ntoskrnl.exe --rop=8 > n
		~80s for a total of 267356 gadgets found.

	- Target: chrome.exe x86 version 18.0.1025.168
		D:\rp-win-x64.exe --file=chrome.exe --rop=8 > n
		~13s for a total of 75459 gadgets found.

	- Target: cmd.exe x86 version v6.1.7600
		D:\rp-win-x64.exe --file=cmd.exe --rop=8 > n
		~15s for a total of 18818 gadgets found.

	- Target: bash x86 version 4.1.5.1
		D:\rp-win-x64.exe --file=bash-x86 --rop=8 > n
		~12s for a total of 45385 gadgets found.


## Screenshot!

rp++-v1 on Win7 x64 / Debian Squeeze x64 / FreeBSD x64 / Mac OSX Lion x64:
<img src="http://image.noelshack.com/fichiers/2014/31/1406551461-rop-mosaic.png">

## ./rp++-v2 --help

####USAGE:
<pre>
./rp++ [-hv] [-f &lt;binary path&gt;] [-i &lt;1,2,3&gt;] [-r &lt;positive int&gt;] [--raw=&lt;archi&gt;] [--unique] [--search-hexa=&lt;\x90A\x90&gt;]
[--search-int=&lt;int in hex&gt;] [--colors] [--rva=&lt;0xdeadbeef&gt;] [--bad-bytes=&lt;\x90A\x90&gt;] [--thumb]
</pre>

####OPTIONS:
<pre>
  -f, --file=&lt;binary path&gt;  give binary path
  -i, --info=&lt;1,2,3&gt;        display information about the binary header
  -r, --rop=&lt;positive int&gt;  find useful gadget for your future exploits, arg is the gadget maximum size in instructions
  --raw=&lt;archi&gt;             find gadgets in a raw file, 'archi' must be in the following list: x86, x64, arm
  --unique                  display only unique gadget
  --search-hexa=&lt;\x90A\x90&gt; try to find hex values
  --search-int=&lt;int in hex&gt; try to find a pointer on a specific integer value
  -h, --help                print this help and exit
  -v, --version             print version information and exit
  --colors                  enable colors
  --rva=&lt;0xdeadbeef&gt;        don't use the image base of the binary, but yours instead
  --bad-bytes=&lt;\x90A\x90&gt;   the bytes you don't want to see in the gadgets' addresses
  --thumb                   enable thumb mode when looking for ARM gadgets
</pre>

## Standalone binaries

### rp++-v2
Soooon!

### rp++-v2-beta

Binaries have been generated for:
  * Windows compiled with VS 2012 on Win8.1 x64,
  * Linux compiled with GCC 4.8.2 on Ubuntu14 x64,

Find them here:
https://github.com/0vercl0k/rp/releases/tag/v2-beta

### rp++-v1
I've generated binaries for:
  * Windows compiled with VS 2010 on Win7 x64,
  * Linux compiled with GCC 4.4.5 on Debian x64 6.0.1,
  * FreeBSD compiled with GCC 4.2.1 on FreeBSD 8.2,
  * Mac OSX compiled with GCC 4.2.1 on OSX 10.7.3 (not statically linked though).

Binaries have been uploaded here:
https://github.com/0vercl0k/rp/releases/tag/v1

## Build-it yourself
### On Linux-like platforms:
<pre>
$ aptitude install libboost-dev cmake clang-3.5
$ git clone https://github.com/0vercl0k/rp.git
$ cd rp
$ git checkout next
$ git submodule update --init --recursive
$ mkdir build && cd build
$ CXX=/usr/bin/clang++ cmake .. && make
$ # Binary should now be in ../bin :-)
</pre>

### On Windows:
1. Download CMake & boost.1.60.0
2. Launch CMake & generate a VS project inside the directory you want
3. Launch the generated VS project
4. Compile!

## Contact
I really want to improve this project, so really, if you have any remark regarding this tool (it includes: feature request, bug report or buying me beers), feel free to contact me ; I'm reachable on IRC/twitter/email/github.

If you have added cool features/fixes and you want them to be merged, send me queries, if I like them I'll merge them.

Thanks to the beta-testers:
  * Ivanlef0u,
  * Heurs,
  * Ufox,
  * Dad`.

Thanks to:
   * Alexander Huemer for pointing me out the IA64 mistake,
   * Baboon (for the MZ signature),
   * NK (for the typo),
   * Tr4nce (for the output bug in --search-int).
