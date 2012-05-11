What is rp++ ?
==============

rp++ is a full-cpp written tool that aims to find ROP sequences in PE/Elf/Mach-O x86/x64 binaries.
It is open-source and has been tested on several OS: Debian / Windows 7 / FreeBSD / Mac OSX Lion (10.7.3). Moreover, it is x64 compatible.
I almost forgot, it handles Intel and AT&T syntax (beloved BeaEngine).
By the way, the tool is a standalone executable, very handy.

You can build very easily rp++ with CMake, it will generate a project file for your prefered IDE.
There are some other things you will be able with rp++, like finding hexadecimal value, or strings, etc.

Also, the cool thing I really enjoy with rp++ is that I can find ROP gadgets on ELF/Mach-O on my Windows desktop -- I haven't to boot my VM and setup a ropeme installation, or to install ImmunityDbg.
The other cool thing is, well, I'm trying to comment my code with Doxygen.

Benchmark: Is it efficient ?
=================

Yeah, here are some benchmarks I have done on my personal laptop:

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

Contact
=======

Actually, I really want to improve this project, so really, if you have any remarks regarding this tool (it includes: feature request, bug report or buying me beers), feel free to contact me -- I'm reachable on IRC/twitter/email!