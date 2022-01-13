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
        # 0F c1 /r
        # XADD r/m32, r32

        Buffer = bytes.fromhex('0fc19011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfc1')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'xadd')
        assert_equal(myDisasm.repr(), 'xadd dword ptr [rax+44332211h], edx')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)
        assert_equal(myDisasm.infos.Operand2.AccessMode, READ + WRITE)

        # REX + 0F C1 /r
        # XADD r/m32*, r32*

        Buffer = bytes.fromhex('410fc19011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfc1')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'xadd')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)
        assert_equal(myDisasm.infos.Operand2.AccessMode, READ + WRITE)
        assert_equal(myDisasm.repr(), 'xadd dword ptr [r8+44332211h], edx')

        # if LOCK and destination is not memory

        Buffer = bytes.fromhex('f00fc1c011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfc1')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'xadd')
        assert_equal(myDisasm.repr(), 'lock xadd eax, eax')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
