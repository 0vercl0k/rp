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

        # VEX.NDS.LZ.0F38.W0 F5 /r
        # BZHI r32a, r/m32, r32b

        myVEX = VEX('VEX.NDS.LZ.0F38.W0')
        myVEX.vvvv = 0b1111
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f500'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'bzhi')
        assert_equal(myDisasm.repr(), 'bzhi eax, dword ptr [r8], al')

        # VEX.NDS.LZ.0F38.W1 F5 /r
        # BZHI r64a, r/m64, r64b

        myVEX = VEX('VEX.NDS.LZ.0F38.W1')
        myVEX.vvvv = 0b1111
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f500'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'bzhi')
        assert_equal(myDisasm.repr(), 'bzhi rax, qword ptr [r8], al')

        myVEX = VEX('VEX.NDS.LZ.0F38.W1')
        myVEX.vvvv = 0b1111
        myVEX.R = 1
        myVEX.L = 1
        Buffer = bytes.fromhex('{}f500'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'bzhi')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # VEX.NDS.LZ.F3.0F38.W0 F5 /r
        # PEXT r32a, r32b, r/m32

        myVEX = VEX('VEX.NDS.LZ.F3.0F38.W0')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f500'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pext')
        assert_equal(myDisasm.repr(), 'pext eax, ecx, dword ptr [r8]')

        # VEX.NDS.LZ.F3.0F38.W1 F5 /r
        # PEXT r64a, r64b, r/m64

        myVEX = VEX('VEX.NDS.LZ.F3.0F38.W1')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f500'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pext')
        assert_equal(myDisasm.repr(), 'pext rax, rcx, qword ptr [r8]')

        # VEX.NDS.LZ.F2.0F38.W0 F5 /r
        # PDEP r32a, r32b, r/m32

        myVEX = VEX('VEX.NDS.LZ.F2.0F38.W0')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f500'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pdep')
        assert_equal(myDisasm.repr(), 'pdep eax, ecx, dword ptr [r8]')

        # VEX.NDS.LZ.F2.0F38.W1 F5 /r
        # PDEP r64a, r64b, r/m64

        myVEX = VEX('VEX.NDS.LZ.F2.0F38.W1')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f500'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pdep')
        assert_equal(myDisasm.repr(), 'pdep rax, rcx, qword ptr [r8]')

        # 66 0F 38 F5
        # WRUSSD

        Buffer = bytes.fromhex('660f38f500')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38f5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'wrussd')
        assert_equal(myDisasm.repr(), 'wrussd dword ptr [rax], eax')

        # 66 REX.W 0F 38 F5
        # WRUSSQ

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('66{:02x}0f38f500'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38f5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'wrussq')
        assert_equal(myDisasm.repr(), 'wrussq qword ptr [rax], rax')
