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

        # MOD == 1

        Buffer = bytes.fromhex('8f442401')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pop')
        assert_equal(myDisasm.repr(), 'pop qword ptr [rsp+09h]')

        Buffer = bytes.fromhex('8f442401')
        myDisasm = Disasm(Buffer)
        myDisasm.infos.Archi = 32
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pop')
        assert_equal(myDisasm.repr(), 'pop dword ptr [esp+05h]')

        Buffer = bytes.fromhex('8f4301')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pop')
        assert_equal(myDisasm.repr(), 'pop qword ptr [rbx+01h]')


        # MOD == 00

        Buffer = bytes.fromhex('8f042400')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pop')
        assert_equal(myDisasm.repr(), 'pop qword ptr [rsp+08h]')

        Buffer = bytes.fromhex('8f042400')
        myDisasm = Disasm(Buffer)
        myDisasm.infos.Archi = 32
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pop')
        assert_equal(myDisasm.repr(), 'pop dword ptr [esp+04h]')


        Buffer = bytes.fromhex('8f03')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pop')
        assert_equal(myDisasm.repr(), 'pop qword ptr [rbx]')

        # MOD == 2

        Buffer = bytes.fromhex('8f842401000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pop')
        assert_equal(myDisasm.repr(), 'pop qword ptr [rsp+00000009h]')

        Buffer = bytes.fromhex('8f8301000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pop')
        assert_equal(myDisasm.repr(), 'pop qword ptr [rbx+00000001h]')

        # MOD == 3

        Buffer = bytes.fromhex('8fc4')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pop')
        assert_equal(myDisasm.repr(), 'pop rsp')
