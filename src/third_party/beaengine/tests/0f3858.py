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

        # VEX.128.66.0F38.W0 58 /r
        # VPBROADCASTD xmm1, xmm2/m32

        myVEX = VEX('VEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}5810'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastd')
        assert_equal(myDisasm.repr(), 'vpbroadcastd xmm10, dword ptr [r8]')

        # VEX.256.66.0F38.W0 58 /r
        # VPBROADCASTD ymm1, xmm2/m32

        myVEX = VEX('VEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}5810'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastd')
        assert_equal(myDisasm.repr(), 'vpbroadcastd ymm10, dword ptr [r8]')

        # EVEX.128.66.0F38.W0 58 /r
        # VPBROADCASTD xmm1 {k1}{z}, xmm2/m32

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}580e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastd')
        assert_equal(myDisasm.repr(), 'vpbroadcastd xmm25, dword ptr [r14]')

        # EVEX.256.66.0F38.W0 58 /r
        # VPBROADCASTD ymm1 {k1}{z}, xmm2/m32

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}580e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastd')
        assert_equal(myDisasm.repr(), 'vpbroadcastd ymm25, dword ptr [r14]')

        # EVEX.512.66.0F38.W0 58 /r
        # VPBROADCASTD zmm1 {k1}{z}, xmm2/m32

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}580e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastd')
        assert_equal(myDisasm.repr(), 'vpbroadcastd zmm25, dword ptr [r14]')
