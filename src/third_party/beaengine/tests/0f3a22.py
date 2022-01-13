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


        # 66 0F 3A 22 /r ib
        # PINSRD xmm1, r/m32, imm8

        Buffer = bytes.fromhex('660f3a222011')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3a22)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pinsrd')
        assert_equal(myDisasm.repr(), 'pinsrd xmm4, dword ptr [rax], 11h')

        Buffer = bytes.fromhex('660f3a22c011')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3a22)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pinsrd')
        assert_equal(myDisasm.repr(), 'pinsrd xmm0, eax, 11h')

        # 66 REX.W 0F 3A 22 /r ib
        # PINSRQ xmm1, r/m64, imm8

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('66{:02x}0f3a222011'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3a22)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pinsrq')
        assert_equal(myDisasm.repr(), 'pinsrq xmm4, qword ptr [rax], 11h')

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('66{:02x}0f3a22c011'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3a22)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pinsrq')
        assert_equal(myDisasm.repr(), 'pinsrq xmm0, rax, 11h')


        # VEX.128.66.0F3A.W0 22 /r ib
        # VPINSRD xmm1, xmm2, r/m32, imm8

        myVEX = VEX('VEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}22e011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x22)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrd')
        assert_equal(myDisasm.repr(), 'vpinsrd xmm12, xmm0, r8d, 11h')

        myVEX = VEX('VEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}222011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x22)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrd')
        assert_equal(myDisasm.repr(), 'vpinsrd xmm12, xmm0, dword ptr [r8], 11h')

        # VEX.128.66.0F3A.W1 22 /r ib
        # VPINSRQ xmm1, xmm2, r/m64, imm8

        myVEX = VEX('VEX.128.66.0F3A.W1')
        Buffer = bytes.fromhex('{}22e011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x22)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrq')
        assert_equal(myDisasm.repr(), 'vpinsrq xmm12, xmm0, r8d, 11h')

        # EVEX.128.66.0F3A.W0 22 /r ib
        # VPINSRD xmm1, xmm2, r32/m32, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}222011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x22)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrd')
        assert_equal(myDisasm.repr(), 'vpinsrd xmm28, xmm16, dword ptr [r8], 11h')

        # EVEX.128.66.0F3A.W1 22 /r ib
        # VPINSRQ xmm1, xmm2, r64/m64, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.W1')
        Buffer = bytes.fromhex('{}222011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x22)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrq')
        assert_equal(myDisasm.repr(), 'vpinsrq xmm28, xmm16, qword ptr [r8], 11h')
