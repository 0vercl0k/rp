What is rp++ ?
==============

rp++ is a full-cpp written tool that aims to find ROP sequences in PE/Elf/Mach-O x86/x64 binaries.
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

		D:\rp-win-x64.exe --file=ntoskrnl.exe --rop=8 --unique > n
		~40s for a total of 101450 unique gadgets found.

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
<img src="http://img194.imageshack.us/img194/7567/ropmosaic.png">

How to use it ?
===============

####USAGE:
<pre>
./rp++ [-hv] [-f &lt;binary path&gt;] [-i &lt;1,2,3&gt;] [-r &lt;positive int&gt;] [--raw=&lt;archi&gt;]
 [--atsyntax] [--unique] [--search-hexa=&lt;\x90A\x90&gt;] [--search-int=&lt;int in hex&gt;]
</pre>

####OPTIONS:
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

Contact
=======

Actually, I really want to improve this project, so really, if you have any remark regarding this tool (it includes: feature request, bug report or buying me beers), feel free to contact me -- You can contact me via IRC/twitter/email!

Thanks to the beta-testers: Ivanlef0u, Heurs & Ufox.