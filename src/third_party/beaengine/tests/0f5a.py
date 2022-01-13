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

        # NP 0F 5A /r
        # CVTPS2PD xmm1, xmm2/m64

        Buffer = bytes.fromhex('0f5a209000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtps2pd')
        assert_equal(myDisasm.repr(), 'cvtps2pd xmm4, qword ptr [rax]')

        # VEX.128.0F.WIG 5A /r
        # VCVTPS2PD xmm1, xmm2/m64

        myVEX = VEX('VEX.128.0F.WIG')
        Buffer = bytes.fromhex('{}5a20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2pd')
        assert_equal(myDisasm.repr(), 'vcvtps2pd xmm12, qword ptr [r8]')

        # VEX.256.0F.WIG 5A /r
        # VCVTPS2PD ymm1, xmm2/m128

        myVEX = VEX('VEX.256.0F.WIG')
        Buffer = bytes.fromhex('{}5a20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2pd')
        assert_equal(myDisasm.repr(), 'vcvtps2pd ymm12, xmmword ptr [r8]')

        # EVEX.128.0F.W0 5A /r
        # VCVTPS2PD xmm1 {k1}{z}, xmm2/m64/m32bcst

        myEVEX = EVEX('EVEX.128.0F.W0')
        Buffer = bytes.fromhex('{}5a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2pd')
        assert_equal(myDisasm.repr(), 'vcvtps2pd xmm28, qword ptr [r8]')

        # EVEX.256.0F.W0 5A /r
        # VCVTPS2PD ymm1 {k1}{z}, xmm2/m128/m32bcst

        myEVEX = EVEX('EVEX.256.0F.W0')
        Buffer = bytes.fromhex('{}5a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2pd')
        assert_equal(myDisasm.repr(), 'vcvtps2pd ymm28, xmmword ptr [r8]')

        # EVEX.512.0F.W0 5A /r
        # VCVTPS2PD zmm1 {k1}{z}, ymm2/m256/m32bcst{sae}

        myEVEX = EVEX('EVEX.512.0F.W0')
        Buffer = bytes.fromhex('{}5a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2pd')
        assert_equal(myDisasm.repr(), 'vcvtps2pd zmm28, ymmword ptr [r8]')

        # 66 0F 5A /r
        # CVTPD2PS xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f5a209000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtpd2ps')
        assert_equal(myDisasm.repr(), 'cvtpd2ps xmm4, xmmword ptr [rax]')

        # VEX.128.66.0F.WIG 5A /r
        # VCVTPD2PS xmm1, xmm2/m128

        myVEX = VEX('VEX.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}5a20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2ps')
        assert_equal(myDisasm.repr(), 'vcvtpd2ps xmm12, xmmword ptr [r8]')

        # VEX.256.66.0F.WIG 5A /r
        # VCVTPD2PS xmm1, ymm2/m256

        myVEX = VEX('VEX.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}5a20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2ps')
        assert_equal(myDisasm.repr(), 'vcvtpd2ps ymm12, ymmword ptr [r8]')

        # EVEX.128.66.0F.W1 5A /r
        # VCVTPD2PS xmm1 {k1}{z}, xmm2/m128/m64bcst

        myEVEX = EVEX('EVEX.128.66.0F.W1')
        Buffer = bytes.fromhex('{}5a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2ps')
        assert_equal(myDisasm.repr(), 'vcvtpd2ps xmm28, xmmword ptr [r8]')

        # EVEX.256.66.0F.W1 5A /r
        # VCVTPD2PS xmm1 {k1}{z}, ymm2/m256/m64bcst

        myEVEX = EVEX('EVEX.256.66.0F.W1')
        Buffer = bytes.fromhex('{}5a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2ps')
        assert_equal(myDisasm.repr(), 'vcvtpd2ps ymm28, ymmword ptr [r8]')

        # EVEX.512.66.0F.W1 5A /r
        # VCVTPD2PS ymm1 {k1}{z}, zmm2/m512/m64bcst{er}

        myEVEX = EVEX('EVEX.512.66.0F.W1')
        Buffer = bytes.fromhex('{}5a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2ps')
        assert_equal(myDisasm.repr(), 'vcvtpd2ps zmm28, zmmword ptr [r8]')

        # F3 0F 5A /r
        # CVTSS2SD xmm1, xmm2/m32

        Buffer = bytes.fromhex('f30f5a209000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtss2sd')
        assert_equal(myDisasm.repr(), 'cvtss2sd xmm4, dword ptr [rax]')

        # VEX.NDS.LIG.F3.0F.WIG 5A /r
        # VCVTSS2SD xmm1, xmm2, xmm3/m32

        myVEX = VEX('VEX.NDS.LIG.F3.0F.WIG')
        Buffer = bytes.fromhex('{}5a20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtss2sd')
        assert_equal(myDisasm.repr(), 'vcvtss2sd xmm12, xmm15, dword ptr [r8]')

        # EVEX.NDS.LIG.F3.0F.W0 5A /r
        # VCVTSS2SD xmm1 {k1}{z}, xmm2, xmm3/m32{sae}

        myEVEX = EVEX('EVEX.NDS.LIG.F3.0F.W0')
        Buffer = bytes.fromhex('{}5a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtss2sd')
        assert_equal(myDisasm.repr(), 'vcvtss2sd xmm28, xmm31, dword ptr [r8]')

        # F2 0F 5A /r
        # CVTSD2SS xmm1, xmm2/m64

        Buffer = bytes.fromhex('f20f5a209000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtsd2ss')
        assert_equal(myDisasm.repr(), 'cvtsd2ss xmm4, qword ptr [rax]')

        # VEX.NDS.LIG.F2.0F.WIG 5A /r
        # VCVTSD2SS xmm1, xmm2, xmm3/m64

        myVEX = VEX('VEX.NDS.LIG.F2.0F.WIG')
        Buffer = bytes.fromhex('{}5a20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsd2ss')
        assert_equal(myDisasm.repr(), 'vcvtsd2ss xmm12, xmm15, qword ptr [r8]')

        # EVEX.NDS.LIG.F2.0F.W1 5A /r
        # VCVTSD2SS xmm1 {k1}{z}, xmm2, xmm3/m64{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F2.0F.W1')
        Buffer = bytes.fromhex('{}5a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsd2ss')
        assert_equal(myDisasm.repr(), 'vcvtsd2ss xmm28, xmm31, qword ptr [r8]')
