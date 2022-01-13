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


        # 66 0F 3A 20 /r ib
        # PINSRB xmm1, r32/m8, imm8

        Buffer = bytes.fromhex('660f3a202011')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3a20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pinsrb')
        assert_equal(myDisasm.repr(), 'pinsrb xmm4, byte ptr [rax], 11h')

        Buffer = bytes.fromhex('660f3a20c011')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3a20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pinsrb')
        assert_equal(myDisasm.repr(), 'pinsrb xmm0, eax, 11h')

        # VEX.128.66.0F3A.W0 20 /r ib
        # VPINSRB xmm1, xmm2, r32/m8, imm8

        myVEX = VEX('VEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}20e011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrb')
        assert_equal(myDisasm.repr(), 'vpinsrb xmm12, xmm0, r8d, 11h')

        myVEX = VEX('VEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}202011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrb')
        assert_equal(myDisasm.repr(), 'vpinsrb xmm12, xmm0, byte ptr [r8], 11h')

        # EVEX.128.66.0F3A.WIG 20 /r ib
        # VPINSRB xmm1, xmm2, r32/m8, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.WIG')
        Buffer = bytes.fromhex('{}202011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrb')
        assert_equal(myDisasm.repr(), 'vpinsrb xmm28, xmm16, byte ptr [r8], 11h')
