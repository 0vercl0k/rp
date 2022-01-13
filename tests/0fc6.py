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


        # NP 0F C6 /r ib
        # SHUFPS xmm1, xmm3/m128, imm8

        Buffer = bytes.fromhex('0fc6c022')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'shufps')
        assert_equal(myDisasm.repr(), 'shufps xmm0, xmm0, 22h')

        Buffer = bytes.fromhex('0fc62022')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'shufps')
        assert_equal(myDisasm.repr(), 'shufps xmm4, xmmword ptr [rax], 22h')

        # VEX.NDS.128.0F.WIG C6 /r ib
        # VSHUFPS xmm1, xmm2, xmm3/m128, imm8

        myVEX = VEX('VEX.NDS.128.0F.WIG')
        Buffer = bytes.fromhex('{}c620f0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vshufps')
        assert_equal(myDisasm.repr(), 'vshufps xmm12, xmm15, xmmword ptr [r8], F0h')

        # VEX.NDS.256.0F.WIG C6 /r ib
        # VSHUFPS ymm1, ymm2, ymm3/m256, imm8

        myVEX = VEX('VEX.NDS.256.0F.WIG')
        Buffer = bytes.fromhex('{}c620f0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vshufps')
        assert_equal(myDisasm.repr(), 'vshufps ymm12, ymm15, ymmword ptr [r8], F0h')

        # EVEX.NDS.128.0F.W0 C6 /r ib
        # VSHUFPS xmm1{k1}{z}, xmm2, xmm3/m128/m32bcst, imm8

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}c6c0bb'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vshufps')
        assert_equal(myDisasm.repr(), 'vshufps xmm24, xmm31, xmm24, BBh')

        # EVEX.NDS.256.0F.W0 C6 /r ib
        # VSHUFPS ymm1{k1}{z}, ymm2, ymm3/m256/m32bcst, imm8

        myEVEX = EVEX('EVEX.NDS.256.0F.W0')
        Buffer = bytes.fromhex('{}c6c0bb'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vshufps')
        assert_equal(myDisasm.repr(), 'vshufps ymm24, ymm31, ymm24, BBh')

        # EVEX.NDS.512.0F.W0 C6 /r ib
        # VSHUFPS zmm1{k1}{z}, zmm2, zmm3/m512/m32bcst, imm8

        myEVEX = EVEX('EVEX.NDS.512.0F.W0')
        Buffer = bytes.fromhex('{}c6c0bb'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vshufps')
        assert_equal(myDisasm.repr(), 'vshufps zmm24, zmm31, zmm24, BBh')

        # 66 0F C6 /r ib
        # SHUFPD xmm1, xmm2/m128, imm8

        Buffer = bytes.fromhex('660fc6c022')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'shufpd')
        assert_equal(myDisasm.repr(), 'shufpd xmm0, xmm0, 22h')

        # VEX.NDS.128.66.0F.WIG C6 /r ib
        # VSHUFPD xmm1, xmm2, xmm3/m128, imm8

        myVEX = VEX('VEX.NDS.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}c6c0f0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vshufpd')
        assert_equal(myDisasm.repr(), 'vshufpd xmm8, xmm15, xmm8, F0h')

        # VEX.NDS.256.66.0F.WIG C6 /r ib
        # VSHUFPD ymm1, ymm2, ymm3/m256, imm8

        myVEX = VEX('VEX.NDS.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}c6c0f0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vshufpd')
        assert_equal(myDisasm.repr(), 'vshufpd ymm8, ymm15, ymm8, F0h')

        # EVEX.NDS.128.66.0F.W1 C6 /r ib
        # VSHUFPD xmm1{k1}{z}, xmm2, xmm3/m128/m64bcst, imm8

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        Buffer = bytes.fromhex('{}c6c0bb'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vshufpd')
        assert_equal(myDisasm.repr(), 'vshufpd xmm24, xmm31, xmm24, BBh')

        # EVEX.NDS.256.66.0F.W1 C6 /r ib
        # VSHUFPD ymm1{k1}{z}, ymm2, ymm3/m256/m64bcst, imm8

        myEVEX = EVEX('EVEX.NDS.256.66.0F.W1')
        Buffer = bytes.fromhex('{}c6c0bb'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vshufpd')
        assert_equal(myDisasm.repr(), 'vshufpd ymm24, ymm31, ymm24, BBh')

        # EVEX.NDS.512.66.0F.W1 C6 /r ib
        # VSHUFPD zmm1{k1}{z}, zmm2, zmm3/m512/m64bcst, imm8

        myEVEX = EVEX('EVEX.NDS.512.66.0F.W1')
        Buffer = bytes.fromhex('{}c6c0bb'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vshufpd')
        assert_equal(myDisasm.repr(), 'vshufpd zmm24, zmm31, zmm24, BBh')
