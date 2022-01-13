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


        # VEX.128.66.0F38.W0 78 /r
        # VPBROADCASTB xmm1, xmm2/m8

        myVEX = VEX('VEX.128.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}7820'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x78)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastb')
        assert_equal(myDisasm.repr(), 'vpbroadcastb xmm12, byte ptr [r8]')

        # VEX.256.66.0F38.W0 78 /r
        # VPBROADCASTB ymm1, xmm2/m8

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}7820'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x78)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastb')
        assert_equal(myDisasm.repr(), 'vpbroadcastb ymm12, byte ptr [r8]')

        # EVEX.128.66.0F38.W0 78 /r
        # VPBROADCASTB xmm1{k1}{z}, xmm2/m8

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}780e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x78)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastb')
        assert_equal(myDisasm.repr(), 'vpbroadcastb xmm25, byte ptr [r14]')

        # EVEX.256.66.0F38.W0 78 /r
        # VPBROADCASTB ymm1{k1}{z}, xmm2/m8

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}780e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x78)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastb')
        assert_equal(myDisasm.repr(), 'vpbroadcastb ymm25, byte ptr [r14]')

        # EVEX.512.66.0F38.W0 78 /r
        # VPBROADCASTB zmm1{k1}{z}, xmm2/m8

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}780e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x78)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastb')
        assert_equal(myDisasm.repr(), 'vpbroadcastb zmm25, byte ptr [r14]')
