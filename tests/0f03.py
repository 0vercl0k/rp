#!/usr/bin/python
# -*- coding: utf-8 -*-
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
#    along with this program.  If not, see <http://www.gnu.org/licenses/>
#
# @author : beaengine@gmail.com

from headers.BeaEnginePython import *
from nose.tools import *

class TestSuite:
    def test(self):

        # 0F 03 /r
        # LSL r16, r16/m16

        Buffer = bytes.fromhex('660f03e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'lsl')
        assert_equal(myDisasm.repr(), 'lsl sp, ax')

        # 0F 03 /r
        # LSL reg, r32/m16

        Buffer = bytes.fromhex('0f03e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'lsl')
        assert_equal(myDisasm.repr(), 'lsl esp, eax')

        Buffer = bytes.fromhex('0f039000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'lsl')
        assert_equal(myDisasm.repr(), 'lsl edx, word ptr [rax+00000000h]')


        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('{:02x}0f039000000000'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'lsl')
        assert_equal(myDisasm.repr(), 'lsl rdx, word ptr [rax+00000000h]')

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('{:02x}0f03e0'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf03)
        assert_equal(myDisasm.infos.Reserved_.MOD_, 0x3)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'lsl')
        assert_equal(myDisasm.repr(), 'lsl rsp, eax')

        Buffer = bytes.fromhex('f00f03e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'lsl')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
