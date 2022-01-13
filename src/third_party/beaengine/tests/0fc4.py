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


        # NP 0F C4 /r ib1
        # PINSRW mm, r32/m16, imm8

        Buffer = bytes.fromhex('0fc42022')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pinsrw')
        assert_equal(myDisasm.repr(), 'pinsrw mm4, word ptr [rax], 22h')
        assert_equal(myDisasm.infos.Instruction.Immediat, 0x22)

        Buffer = bytes.fromhex('0fc4c022')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pinsrw')
        assert_equal(myDisasm.repr(), 'pinsrw mm0, eax, 22h')
        assert_equal(myDisasm.infos.Instruction.Immediat, 0x22)

        # 66 0F C4 /r ib
        # PINSRW xmm, r32/m16, imm8

        Buffer = bytes.fromhex('660fc42022')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pinsrw')
        assert_equal(myDisasm.repr(), 'pinsrw xmm4, word ptr [rax], 22h')
        assert_equal(myDisasm.infos.Instruction.Immediat, 0x22)

        # VEX.NDS.128.66.0F.W0 C4 /r ib
        # VPINSRW xmm1, xmm2, r32/m16, imm8

        myVEX = VEX('VEX.NDS.128.66.0F.W0')

        Buffer = bytes.fromhex('{}c410f0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrw')
        assert_equal(myDisasm.repr(), 'vpinsrw xmm10, xmm15, word ptr [r8], F0h')


        myVEX = VEX('VEX.NDS.128.66.0F.W0')
        Buffer = bytes.fromhex('{}c4c0f0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrw')
        assert_equal(myDisasm.repr(), 'vpinsrw xmm8, xmm15, r8d, F0h')

        # EVEX.NDS.128.66.0F.WIG C4 /r ib
        # VPINSRW xmm1, xmm2, r32/m16, imm8

        myEVEX = EVEX('EVEX.NDS.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}c416bb'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpinsrw')
        assert_equal(myDisasm.repr(), 'vpinsrw xmm26, xmm31, word ptr [r14], BBh')
