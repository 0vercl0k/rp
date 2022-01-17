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

        # 0F 38 F0 /r
        # MOVBE r32, m32

        Buffer = bytes.fromhex('0f38f020')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38f0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movbe')
        assert_equal(myDisasm.repr(), 'movbe esp, dword ptr [rax]')

        # REX.W + 0F 38 F0 /r
        # MOVBE r64, m64

        myREX = REX()
        myREX.W = 1

        Buffer = bytes.fromhex('{:02x}0f38f027'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38f0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movbe')
        assert_equal(myDisasm.repr(), 'movbe rsp, qword ptr [rdi]')


        # F2 0F 38 F0 /r
        # CRC32 r32, r/m8

        Buffer = bytes.fromhex('f20f38f020')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38f0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'crc32')
        assert_equal(myDisasm.repr(), 'crc32 esp, byte ptr [rax]')

        # F2 REX 0F 38 F0 /r
        # CRC32 r32, r/m8*

        myREX = REX()

        Buffer = bytes.fromhex('f2{:02x}0f38f027'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38f0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'crc32')
        assert_equal(myDisasm.repr(), 'crc32 esp, byte ptr [rdi]')

        # F2 REX.W 0F 38 F0 /r
        # CRC32 r64, r/m8

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f2{:02x}0f38f027'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38f0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'crc32')
        assert_equal(myDisasm.repr(), 'crc32 rsp, byte ptr [rdi]')
