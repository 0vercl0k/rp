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

        # NP 0F 72 /6 ib
        # pslld mm1, imm8

        Buffer = bytes.fromhex('0f72f011')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf72)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pslld')
        assert_equal(myDisasm.repr(), 'pslld mm0, 11h')

        # 66 0F 72 /6 ib
        # pslld xmm1, imm8

        Buffer = bytes.fromhex('660f72f011')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf72)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pslld')
        assert_equal(myDisasm.repr(), 'pslld xmm0, 11h')

        # VEX.NDD.128.66.0F.WIG 72 /6 ib
        # Vpslld xmm1, xmm2, imm8

        myVEX = VEX('VEX.NDD.128.66.0F.WIG')
        myVEX.B = 1
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}72f011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x72)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpslld')
        assert_equal(myDisasm.repr(), 'vpslld xmm0, xmm0, 11h')

        # VEX.NDD.256.66.0F.WIG 72 /6 ib
        # Vpslld ymm1, ymm2, imm8

        myVEX = VEX('VEX.NDD.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}72f011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x72)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpslld')
        assert_equal(myDisasm.repr(), 'vpslld ymm15, ymm8, 11h')

        # EVEX.NDD.128.66.0F.WIG 72 /6 ib
        # Vpslld xmm1 {k1}{z}, xmm2/m128, imm8

        myEVEX = EVEX('EVEX.NDD.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}723211'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x72)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpslld')
        assert_equal(myDisasm.repr(), 'vpslld xmm31, xmmword ptr [r10], 11h')

        # EVEX.NDD.256.66.0F.WIG 72 /6 ib
        # Vpslld ymm1 {k1}{z}, ymm2/m256, imm8

        myEVEX = EVEX('EVEX.NDD.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}723211'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x72)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpslld')
        assert_equal(myDisasm.repr(), 'vpslld ymm31, ymmword ptr [r10], 11h')

        # EVEX.NDD.512.66.0F.WIG 72 /6 ib
        # Vpslld zmm1 {k1}{z}, zmm2/m512, imm8

        myEVEX = EVEX('EVEX.NDD.512.66.0F.WIG')
        Buffer = bytes.fromhex('{}723211'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x72)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpslld')
        assert_equal(myDisasm.repr(), 'vpslld zmm31, zmmword ptr [r10], 11h')
