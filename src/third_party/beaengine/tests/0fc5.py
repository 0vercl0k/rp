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


        # NP 0F C5 /r ib1
        # PEXTRW reg, mm, imm8

        Buffer = bytes.fromhex('0fc5c022')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfc5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pextrw')
        assert_equal(myDisasm.repr(), 'pextrw ax, mm0, 22h')
        assert_equal(myDisasm.infos.Instruction.Immediat, 0x22)

        # 66 0F C5 /r ib
        # PEXTRW reg, xmm, imm8

        Buffer = bytes.fromhex('660fc5c022')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfc5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pextrw')
        assert_equal(myDisasm.repr(), 'pextrw ax, xmm0, 22h')
        assert_equal(myDisasm.infos.Instruction.Immediat, 0x22)

        # VEX.128.66.0F.W0 C5 /r ib
        # VPEXTRW reg, xmm1, imm8

        myVEX = VEX('VEX.128.66.0F.W0')
        Buffer = bytes.fromhex('{}c5c0f0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpextrw')
        assert_equal(myDisasm.repr(), 'vpextrw r8w, xmm8, F0h')


        # EVEX.128.66.0F.WIG C5 /r ib
        # VPEXTRW reg, xmm1, imm8

        myEVEX = EVEX('EVEX.128.66.0F.WIG')
        myEVEX.Rprime = 1
        Buffer = bytes.fromhex('{}c5c0bb'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpextrw')
        assert_equal(myDisasm.repr(), 'vpextrw r8w, xmm24, BBh')


        # If VEX.L = 1 or EVEX.L’L > 0.

        myVEX = VEX('VEX.128.66.0F.W0')
        myVEX.L = 1
        Buffer = bytes.fromhex('{}c5c0f0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpextrw')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        myEVEX = EVEX('EVEX.128.66.0F.WIG')
        myEVEX.LL = 1
        Buffer = bytes.fromhex('{}c5c0bb'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpextrw')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # If VEX.vvvv != 1111B or EVEX.vvvv != 1111B.

        myVEX = VEX('VEX.128.66.0F.W0')
        myVEX.vvvv = 0b1110
        Buffer = bytes.fromhex('{}c5c0f0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpextrw')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        myEVEX = EVEX('EVEX.128.66.0F.WIG')
        myEVEX.vvvv = 0b1110
        Buffer = bytes.fromhex('{}c5c0bb'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc5)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpextrw')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
