#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    test_ia32_opcode.py - You can verify the opcode/instr in the ia32.cpp thanks to the MIASM framework (thx NK!)
#    Copyright (C) 2012 Axel "0vercl0k" Souchet - http://www.twitter.com/0vercl0k
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import re
from miasm.arch.ia32_arch import *
from miasm.core import asmbloc
from miasm.core.bin_stream import  bin_stream


def clean_assembly(instr):
    '''
    just clean the useless space in the instruction string
    '''
    id_1, id_2 = -1, -1
    for i in range(len(instr)):
        if instr[i] == ' ':
            if id_1 == -1:
                id_1 = i
        else:
            if id_1 != -1:
                id_2 = i
                break
    
    # if we have instruction without operand
    if id_2 == -1:
        return '%s' % instr[: id_1]
    return '%s %s' % (instr[: id_1], instr[id_2 :])

def hexa_representation_to_bytes(s):
    '''
    it gives you the binary representation of a string like '\\x41\\x42'
    '''
    out, i = '', 0
    try:
        while i < len(s):
            if s[i] == '\\' and (i+3) < len(s) and s[i+1] == 'x':
                out += chr(int(s[i+2:i+4], 16))
                i += 4
            else:
                out += s[i]
                i += 1
    except:
        return None
    return out
    
def di(bin_s):
    '''
    Disassemble some x86 assembly
    di(\x90A\x90)
    '''
    bin = hexa_representation_to_bytes(bin_s)
    if bin == None:
        return 'An error occured'

    job_done, symbol_pool = set(), asmbloc.asm_symbol_pool()
    all_bloc = asmbloc.dis_bloc_all(x86_mn, bin_stream(bin), 0, job_done, symbol_pool)
    
    disassembly_dic = {}
    for i in all_bloc:
        for b in i.lines:
            # hmm ok, re-order the different instruction from each blocs
            disassembly_dic[b.offset] = b
            
    disass, offset = '', 0
    for k in sorted(disassembly_dic.keys()):
        # add the label for the different blocs ; except for the main label
        if symbol_pool.getby_offset(k) and k != 0:
            disass += '%s: ' % symbol_pool.getby_offset(k).name
        disass += '%s ; ' % clean_assembly(str(disassembly_dic[k]))
    if disass == '':
        return 'No disassembly found.'
    return disass

def get_opcodes():
    '''
    It returns you an array of dictionary ; each dictionary looks like this:
    {
        'disass' : 'mov eax, [ebx] ; bla'
        'opcodes' : '\xaa\xbb',
        'size' : 2
    }
    '''
    f = open('../src/ia32.cpp', 'r')
    data = f.read()
    f.close()

    ret = []
    for ins, ops, size in re.findall('Gadget\("(.+)", "(.+)", ([0-9]+)\)', data):
        ret.append({
            'disass' : ins,
            'opcodes' : ops,
            'size' : size
        })
    return ret

def main(argc, argv):
    f = open('./out', 'w')
    for instr in get_opcodes():
        print instr['disass']
        disass = di(instr['opcodes'])
        f.write('opcodes: %s -> %s (in src: %s)\n' % (instr['opcodes'], disass, instr['disass']))
    f.close()
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))