What is rp++ ?
==============

rp++ is a full-cpp written tool that aims to find ROP sequences in PE/Elf/Mach-O (doesn't support the FAT binaries) x86/x64 binaries.
It is open-source, documented with Doxygen (well, I'm trying to..) and has been tested on several OS: Debian / Windows 7 / FreeBSD / Mac OSX Lion (10.7.3). Moreover, it is x64 compatible.
I almost forgot, it handles both Intel and AT&T syntax (beloved BeaEngine).
By the way, the tool is a standalone executable ; I will upload static-compiled binaries for each OS.

You can build very easily rp++ with CMake, it will generate a project file for your prefered IDE.
There are some other things you will be able to do with rp++, like finding hexadecimal values, or strings, etc.

Also, the cool thing I really enjoy with rp++ is that I can find ROP gadgets on ELF/Mach-O on my Windows desktop -- I don't have to boot my VM and setup a ropeme installation, or to install ImmunityDbg.

Benchmark: Is it efficient ?
=================

Yeah, here are some benchmarks I have done on my personal laptop (Win7 x64, Intel i7 Q720 @ 1.6GHz, 4GB RAM):

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


Screenshots
============

rp++ on Win7 x64 / Debian Squeeze x64 / FreeBSD x64 / Mac OSX Lion x64:
<img src="http://image.noelshack.com/fichiers/2014/31/1406551461-rop-mosaic.png">

How to use it ?
===============

#### USAGE:
<pre>
./rp++ [-hv] [-f &lt;binary path&gt;] [-i &lt;1,2,3&gt;] [-r &lt;positive int&gt;] [--raw=&lt;archi&gt;]
 [--atsyntax] [--unique] [--search-hexa=&lt;\x90A\x90&gt;] [--search-int=&lt;int in hex&gt;]
</pre>

#### OPTIONS:
<pre>
  -f, --file=&lt;binary path&gt;  give binary path
  -i, --info=&lt;1,2,3&gt;        display information about the binary header
  -r, --rop=&lt;positive int&gt;  find useful gadget for your future exploits, arg is the gadget maximum size in instructions
  --raw=&lt;archi&gt;             find gadgets in a raw file, 'archi' must be in the following list: x86, x64
  --atsyntax                enable the at&t syntax
  --unique                  display only unique gadget
  --search-hexa=&lt;\x90A\x90&gt; try to find hex values
  --search-int=&lt;int in hex&gt; try to find a pointer on a specific integer value
  -h, --help                print this help and exit
  -v, --version             print version information and exit
</pre>

Where I can download standalone binaries ?
=========================================
I've generated an x86 and an x64 versions for Windows (compiled with VS 2010 on Win7 x64), Linux (compiled with gcc 4.4.5 on Debian x64 6.0.1), FreeBSD (compiled with gcc 4.2.1 on FreeBSD 8.2) and Mac OSX (compiled with gcc 4.2.1 on OSX 10.7.3 ; not statically linked): 
https://github.com/0vercl0k/rp/downloads

Here are the sha1sums:
<pre>
a2e71e88a5c14c81ae184258184e5d83082f184d *rp-fbsd-x64
29c2d5462865d28042bffe9e723d25c19f0da1f7 *rp-fbsd-x86
57e23ef42954a08c9833099d87544e2166c58b94 *rp-lin-x64
efcaf2a9584a23559e3e5b109eb37cbde89f8b29 *rp-lin-x86
5c612b3eff470b613ea06ebbbb882f0aaef8e3b4 *rp-osx-x64
2e32273b657b44d6b9a56e89ec2e2c2731713d87 *rp-osx-x86
e5e6930eb469e92f79b59941330f23daf62800be *rp-win-x64.exe
f83d4d9f9e73a60a31e495e2fbd2404c560f1a27 *rp-win-x86.exe
</pre>

Contact
=======

Actually, I really want to improve this project, so really, if you have any remark regarding this tool (it includes: feature request, bug report or buying me beers), feel free to contact me -- You can contact me via IRC/twitter/email!

If you have coded cool features and you want to share them, send me merge queries, if I like them I'll merge them.

Thanks to the beta-testers: Ivanlef0u, Heurs, Ufox & Dad`.
Thanks to : Alexander Huemer for pointing me out the IA64 mistake, Baboon (for the MZ signature), NK (for the typo), Tr4nce (for the output bug in --search-int).
