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


        # VEX.NDS.LZ.0F38.W0 F7 /r
        # BEXTR r32a, r/m32, r32b

        myVEX = VEX('VEX.NDS.LZ.0F38.W0')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f700'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf7)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'bextr')
        assert_equal(myDisasm.repr(), 'bextr eax, dword ptr [r8], cl')

        # VEX.NDS.LZ.0F38.W1 F7 /r
        # BEXTR r64a, r/m64, r64b

        myVEX = VEX('VEX.NDS.LZ.0F38.W1')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f700'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf7)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'bextr')
        assert_equal(myDisasm.repr(), 'bextr rax, qword ptr [r8], cl')

        # VEX.NDS.LZ.F3.0F38.W0 F7 /r
        # SARX r32a, r/m32, r32b

        myVEX = VEX('VEX.NDS.LZ.F3.0F38.W0')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f700'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf7)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sarx')
        assert_equal(myDisasm.repr(), 'sarx eax, dword ptr [r8], cl')

        # VEX.NDS.LZ.66.0F38.W0 F7 /r
        # SHLX r32a, r/m32, r32b

        myVEX = VEX('VEX.NDS.LZ.66.0F38.W0')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f700'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf7)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'shlx')
        assert_equal(myDisasm.repr(), 'shlx eax, dword ptr [r8], cl')

        # VEX.NDS.LZ.F2.0F38.W0 F7 /r
        # SHRX r32a, r/m32, r32b

        myVEX = VEX('VEX.NDS.LZ.F2.0F38.W0')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f700'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf7)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'shrx')
        assert_equal(myDisasm.repr(), 'shrx eax, dword ptr [r8], cl')

        # VEX.NDS.LZ.F3.0F38.W1 F7 /r
        # SARX r64a, r/m64, r64b

        myVEX = VEX('VEX.NDS.LZ.F3.0F38.W1')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f700'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf7)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sarx')
        assert_equal(myDisasm.repr(), 'sarx rax, qword ptr [r8], cl')

        # VEX.NDS.LZ.66.0F38.W1 F7 /r
        # SHLX r64a, r/m64, r64b

        myVEX = VEX('VEX.NDS.LZ.66.0F38.W1')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f700'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf7)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'shlx')
        assert_equal(myDisasm.repr(), 'shlx rax, qword ptr [r8], cl')

        # VEX.NDS.LZ.F2.0F38.W1 F7 /r
        # SHRX r64a, r/m64, r64b

        myVEX = VEX('VEX.NDS.LZ.F2.0F38.W1')
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.L = 0
        Buffer = bytes.fromhex('{}f700'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf7)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'shrx')
        assert_equal(myDisasm.repr(), 'shrx rax, qword ptr [r8], cl')
