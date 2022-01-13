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

        # NP 0F 5B /r
        # CVTDQ2PS xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f5b209000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtdq2ps')
        assert_equal(myDisasm.repr(), 'cvtdq2ps xmm4, xmmword ptr [rax]')

        # VEX.128.0F.WIG 5B /r
        # VCVTDQ2PS xmm1, xmm2/m128

        myVEX = VEX('VEX.128.0F.WIG')
        Buffer = bytes.fromhex('{}5b20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtdq2ps')
        assert_equal(myDisasm.repr(), 'vcvtdq2ps xmm12, xmmword ptr [r8]')

        # VEX.256.0F.WIG 5B /r
        # VCVTDQ2PS ymm1, ymm2/m256

        myVEX = VEX('VEX.256.0F.WIG')
        Buffer = bytes.fromhex('{}5b20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtdq2ps')
        assert_equal(myDisasm.repr(), 'vcvtdq2ps ymm12, ymmword ptr [r8]')

        # EVEX.128.0F.W0 5B /r
        # VCVTDQ2PS xmm1 {k1}{z}, xmm2/m128/m32bcst

        myEVEX = EVEX('EVEX.128.0F.W0')
        Buffer = bytes.fromhex('{}5b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtdq2ps')
        assert_equal(myDisasm.repr(), 'vcvtdq2ps xmm28, xmmword ptr [r8]')

        # EVEX.256.0F.W0 5B /r
        # VCVTDQ2PS ymm1 {k1}{z}, ymm2/m256/m32bcst

        myEVEX = EVEX('EVEX.256.0F.W0')
        Buffer = bytes.fromhex('{}5b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtdq2ps')
        assert_equal(myDisasm.repr(), 'vcvtdq2ps ymm28, ymmword ptr [r8]')

        # EVEX.512.0F.W0 5B /r
        # VCVTDQ2PS zmm1 {k1}{z}, zmm2/m512/m32bcst{er}

        myEVEX = EVEX('EVEX.512.0F.W0')
        Buffer = bytes.fromhex('{}5b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtdq2ps')
        assert_equal(myDisasm.repr(), 'vcvtdq2ps zmm28, zmmword ptr [r8]')

        # 66 0F 5B /r
        # CVTPS2DQ xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f5b209000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtps2dq')
        assert_equal(myDisasm.repr(), 'cvtps2dq xmm4, xmmword ptr [rax]')

        # VEX.128.66.0F.WIG 5B /r
        # VCVTPS2DQ xmm1, xmm2/m128

        myVEX = VEX('VEX.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}5b20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2dq')
        assert_equal(myDisasm.repr(), 'vcvtps2dq xmm12, xmmword ptr [r8]')

        # VEX.256.66.0F.WIG 5B /r
        # VCVTPS2DQ ymm1, ymm2/m256

        myVEX = VEX('VEX.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}5b20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2dq')
        assert_equal(myDisasm.repr(), 'vcvtps2dq ymm12, ymmword ptr [r8]')

        # EVEX.128.66.0F.W0 5B /r
        # VCVTPS2DQ xmm1 {k1}{z}, xmm2/m128/m32bcst

        myEVEX = EVEX('EVEX.128.66.0F.W0')
        Buffer = bytes.fromhex('{}5b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2dq')
        assert_equal(myDisasm.repr(), 'vcvtps2dq xmm28, xmmword ptr [r8]')

        # EVEX.256.66.0F.W0 5B /r
        # VCVTPS2DQ ymm1 {k1}{z}, ymm2/m256/m32bcst

        myEVEX = EVEX('EVEX.256.66.0F.W0')
        Buffer = bytes.fromhex('{}5b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2dq')
        assert_equal(myDisasm.repr(), 'vcvtps2dq ymm28, ymmword ptr [r8]')

        # EVEX.512.66.0F.W0 5B /r
        # VCVTPS2DQ zmm1 {k1}{z}, zmm2/m512/m32bcst{er}

        myEVEX = EVEX('EVEX.512.66.0F.W0')
        Buffer = bytes.fromhex('{}5b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2dq')
        assert_equal(myDisasm.repr(), 'vcvtps2dq zmm28, zmmword ptr [r8]')

        # F3 0F 5B /r
        # CVTTPS2DQ xmm1, xmm2/m128

        Buffer = bytes.fromhex('f30f5b209000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvttps2dq')
        assert_equal(myDisasm.repr(), 'cvttps2dq xmm4, xmmword ptr [rax]')

        # VEX.128.F3.0F.WIG 5B /r
        # VCVTTPS2DQ xmm1, xmm2/m128

        myVEX = VEX('VEX.128.F3.0F.WIG')
        Buffer = bytes.fromhex('{}5b20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttps2dq')
        assert_equal(myDisasm.repr(), 'vcvttps2dq xmm12, xmmword ptr [r8]')

        # VEX.256.F3.0F.WIG 5B /r
        # VCVTTPS2DQ ymm1, ymm2/m256

        myVEX = VEX('VEX.256.F3.0F.WIG')
        Buffer = bytes.fromhex('{}5b20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttps2dq')
        assert_equal(myDisasm.repr(), 'vcvttps2dq ymm12, ymmword ptr [r8]')

        # EVEX.128.F3.0F.W0 5B /r
        # VCVTTPS2DQ xmm1 {k1}{z}, xmm2/m128/m32bcst

        myEVEX = EVEX('EVEX.128.F3.0F.W0')
        Buffer = bytes.fromhex('{}5b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttps2dq')
        assert_equal(myDisasm.repr(), 'vcvttps2dq xmm28, xmmword ptr [r8]')

        # EVEX.256.F3.0F.W0 5B /r
        # VCVTTPS2DQ ymm1 {k1}{z}, ymm2/m256/m32bcst

        myEVEX = EVEX('EVEX.256.F3.0F.W0')
        Buffer = bytes.fromhex('{}5b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttps2dq')
        assert_equal(myDisasm.repr(), 'vcvttps2dq ymm28, ymmword ptr [r8]')

        # EVEX.512.F3.0F.W0 5B /r
        # VCVTTPS2DQ zmm1 {k1}{z}, zmm2/m512/m32bcst {sae}

        myEVEX = EVEX('EVEX.512.F3.0F.W0')
        Buffer = bytes.fromhex('{}5b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttps2dq')
        assert_equal(myDisasm.repr(), 'vcvttps2dq zmm28, zmmword ptr [r8]')
