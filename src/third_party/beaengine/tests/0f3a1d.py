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


        # VEX.128.66.0F3A.W0 1D /r ib
        # VCVTPS2PH xmm1/m64, xmm2, imm8

        myVEX = VEX('VEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1dc011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2ph')
        assert_equal(myDisasm.repr(), 'vcvtps2ph xmm8, xmm8, 11h')

        myVEX = VEX('VEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1d2011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2ph')
        assert_equal(myDisasm.repr(), 'vcvtps2ph qword ptr [r8], xmm12, 11h')

        # VEX.256.66.0F3A.W0 1D /r ib
        # VCVTPS2PH xmm1/m128, ymm2, imm8

        myVEX = VEX('VEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1de011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2ph')
        assert_equal(myDisasm.repr(), 'vcvtps2ph xmm8, ymm12, 11h')

        myVEX = VEX('VEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1d2011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2ph')
        assert_equal(myDisasm.repr(), 'vcvtps2ph xmmword ptr [r8], ymm12, 11h')

        # EVEX.128.66.0F3A.W0 1D /r ib
        # VCVTPS2PH xmm1/m64 {k1}{z}, xmm2, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1d2011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2ph')
        assert_equal(myDisasm.repr(), 'vcvtps2ph qword ptr [r8], xmm28, 11h')

        myEVEX = EVEX('EVEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1de011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2ph')
        assert_equal(myDisasm.repr(), 'vcvtps2ph xmm24, xmm28, 11h')

        # EVEX.256.66.0F3A.W0 1D /r ib
        # VCVTPS2PH xmm1/m128 {k1}{z}, ymm2, imm8

        myEVEX = EVEX('EVEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1d2011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2ph')
        assert_equal(myDisasm.repr(), 'vcvtps2ph xmmword ptr [r8], ymm28, 11h')

        myEVEX = EVEX('EVEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1de011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2ph')
        assert_equal(myDisasm.repr(), 'vcvtps2ph xmm24, ymm28, 11h')

        # EVEX.512.66.0F3A.W0 1D /r ib
        # VCVTPS2PH ymm1/m256 {k1}{z}, zmm2{sae}, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1d2011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2ph')
        assert_equal(myDisasm.repr(), 'vcvtps2ph ymmword ptr [r8], zmm28, 11h')

        myEVEX = EVEX('EVEX.512.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1de011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2ph')
        assert_equal(myDisasm.repr(), 'vcvtps2ph ymm24, zmm28, 11h')
