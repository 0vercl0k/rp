rp++
==============

Thanks to rp++ you are able to research sequences of instruction ended by a ret one, also called a gadget.
It handles PE/ELF x86/x64 binaries and it is written fully in cpp ; thus very efficient.
Also, the tool is multiplatform so you can find gadgets in a PE executable on your unix station.


Installation
------------
bla


Usage
-----

<b>Syntax</b>

./rp &lt;file&gt; &lt;options&gt;

<b>Options</b>

<pre>
-d: Display several information concerning the binary
    Specify the level of verbosity, 0 (default) to 3

-r: Find a bunch of gadgets usable in your future exploits
    Specify the maximum number of instruction your gadgets will have (btw, the final instruction doesn't count)

-v: Display the version of rp++ you are using
</pre>

<b>Exemple</b>
bla