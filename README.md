What is rp++ ?
==============

rp++ is a full-cpp written tool that aims to find ROP sequences in PE/Elf/Mach-O x86/x64 binaries.
It is open-source and has been tested on several OS: Debian / Windows 7 / FreeBSD / Mac OSX Snow Leopard. Moreover, it is x64 compatible.
I almost forgot, it handles Intel and AT&T syntax (beloved BeaEngine).

You can build very easily rp++ with CMake, it will generate a project file for your prefered IDE.
There are some other things you will be able with rp++, like finding hexadecimal value, or strings, etc.

Also, the cool thing I really enjoy with rp++ is that I can find ROP gadgets on ELF/Mach-O on my Windows desktop -- I haven't to boot my VM and setup a ropeme installation, or to install ImmunityDbg.
The other cool thing is, well, I'm trying to comment my code with Doxygen.

Is it efficient ?
=================

Yeah, here are some benchmarks I have done on my personal laptop:


Screenshots
============


Actually, I really want to improve this project, so really, if you have any remarks regarding this tool (it includes: feature request, bug report or buying me beers), feel free to contact me -- I'm reachable on IRC/twitter/email!