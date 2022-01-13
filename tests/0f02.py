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

        # 0F 02 /r
        # LAR r16, r16/m16

        Buffer = bytes.fromhex('660f02e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf02)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'lar')
        assert_equal(myDisasm.repr(), 'lar sp, ax')

        # 0F 02 /r
        # LAR reg, r32/m16

        Buffer = bytes.fromhex('0f02e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf02)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'lar')
        assert_equal(myDisasm.repr(), 'lar esp, eax')

        Buffer = bytes.fromhex('0f029011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf02)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'lar')
        assert_equal(myDisasm.repr(), 'lar edx, word ptr [rax+44332211h]')


        Buffer = bytes.fromhex('f00f02e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf02)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'lar')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
