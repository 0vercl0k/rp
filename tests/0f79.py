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

        # NP 0F 79
        # VMWRITE r64, r/m64

        Buffer = bytes.fromhex('0f7920')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf79')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmwrite')
        assert_equal(myDisasm.repr(), 'vmwrite rsp, qword ptr [rax]')

        # EVEX.128.0F.W0 79 /r
        # VCVTPS2UDQ xmm1 {k1}{z}, xmm2/m128/m32bcst

        myEVEX = EVEX('EVEX.128.0F.W0')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2udq')
        assert_equal(myDisasm.repr(), 'vcvtps2udq xmm28, xmmword ptr [r8]')

        # EVEX.256.0F.W0 79 /r
        # VCVTPS2UDQ ymm1 {k1}{z}, ymm2/m256/m32bcst

        myEVEX = EVEX('EVEX.256.0F.W0')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2udq')
        assert_equal(myDisasm.repr(), 'vcvtps2udq ymm28, ymmword ptr [r8]')

        # EVEX.512.0F.W0 79 /r
        # VCVTPS2UDQ zmm1 {k1}{z}, zmm2/m512/m32bcst{er}

        myEVEX = EVEX('EVEX.512.0F.W0')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2udq')
        assert_equal(myDisasm.repr(), 'vcvtps2udq zmm28, zmmword ptr [r8]')

        # EVEX.128.0F.W1 79 /r
        # VCVTPD2UDQ xmm1 {k1}{z}, xmm2/m128/m64bcst

        myEVEX = EVEX('EVEX.128.0F.W1')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2udq')
        assert_equal(myDisasm.repr(), 'vcvtpd2udq xmm28, xmmword ptr [r8]')

        # EVEX.256.0F.W1 79 /r
        # VCVTPD2UDQ xmm1 {k1}{z}, ymm2/m256/m64bcst

        myEVEX = EVEX('EVEX.256.0F.W1')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2udq')
        assert_equal(myDisasm.repr(), 'vcvtpd2udq ymm28, ymmword ptr [r8]')

        # EVEX.512.0F.W1 79 /r
        # VCVTPD2UDQ ymm1 {k1}{z}, zmm2/m512/m64bcst{er}

        myEVEX = EVEX('EVEX.512.0F.W1')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2udq')
        assert_equal(myDisasm.repr(), 'vcvtpd2udq zmm28, zmmword ptr [r8]')

        # EVEX.128.66.0F.W0 79 /r
        # VCVTPS2UQQ xmm1 {k1}{z}, xmm2/m64/m32bcst

        myEVEX = EVEX('EVEX.128.66.0F.W0')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2uqq')
        assert_equal(myDisasm.repr(), 'vcvtps2uqq xmm28, qword ptr [r8]')

        # EVEX.256.66.0F.W0 79 /r
        # VCVTPS2UQQ ymm1 {k1}{z}, xmm2/m128/m32bcst

        myEVEX = EVEX('EVEX.256.66.0F.W0')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2uqq')
        assert_equal(myDisasm.repr(), 'vcvtps2uqq ymm28, xmmword ptr [r8]')

        # EVEX.512.66.0F.W0 79 /r
        # VCVTPS2UQQ zmm1 {k1}{z}, ymm2/m256/m32bcst{er}

        myEVEX = EVEX('EVEX.512.66.0F.W0')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtps2uqq')
        assert_equal(myDisasm.repr(), 'vcvtps2uqq zmm28, ymmword ptr [r8]')

        # EVEX.128.66.0F.W1 79 /r
        # VCVTPD2UQQ xmm1 {k1}{z}, xmm2/m128/m64bcst

        myEVEX = EVEX('EVEX.128.66.0F.W1')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2uqq')
        assert_equal(myDisasm.repr(), 'vcvtpd2uqq xmm28, xmmword ptr [r8]')

        # EVEX.256.66.0F.W1 79 /r
        # VCVTPD2UQQ ymm1 {k1}{z}, ymm2/m256/m64bcst

        myEVEX = EVEX('EVEX.256.66.0F.W1')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2uqq')
        assert_equal(myDisasm.repr(), 'vcvtpd2uqq ymm28, ymmword ptr [r8]')

        # EVEX.512.66.0F.W1 79 /r
        # VCVTPD2UQQ zmm1 {k1}{z}, zmm2/m512/m64bcst{er}

        myEVEX = EVEX('EVEX.512.66.0F.W1')
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtpd2uqq')
        assert_equal(myDisasm.repr(), 'vcvtpd2uqq zmm28, zmmword ptr [r8]')

        # EVEX.LIG.F3.0F.W0 79 /r
        # VCVTSS2USI r32, xmm1/m32{er}

        myEVEX = EVEX('EVEX.LIG.F3.0F.W0')
        myEVEX.Rprime = 1
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtss2usi')
        assert_equal(myDisasm.repr(), 'vcvtss2usi r12d, dword ptr [r8]')

        myEVEX = EVEX('EVEX.LIG.F3.0F.W0')
        myEVEX.Rprime = 1
        Buffer = bytes.fromhex('{}79c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtss2usi')
        assert_equal(myDisasm.repr(), 'vcvtss2usi r8d, xmm24')

        # EVEX.LIG.F3.0F.W1 79 /r
        # VCVTSS2USI r64, xmm1/m32{er}

        myEVEX = EVEX('EVEX.LIG.F3.0F.W1')
        myEVEX.Rprime = 1
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Reserved_.EVEX.W, 1)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtss2usi')
        assert_equal(myDisasm.repr(), 'vcvtss2usi r12, dword ptr [r8]')

        # EVEX.LIG.F2.0F.W0 79 /r
        # VCVTSD2USI r32, xmm1/m64{er}

        myEVEX = EVEX('EVEX.LIG.F2.0F.W0')
        myEVEX.Rprime = 1
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Reserved_.EVEX.W, 0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsd2usi')
        assert_equal(myDisasm.repr(), 'vcvtsd2usi r12d, dword ptr [r8]')

        # EVEX.LIG.F2.0F.W1 79 /r
        # VCVTSD2USI r64, xmm1/m64{er}

        myEVEX = EVEX('EVEX.LIG.F2.0F.W1')
        myEVEX.Rprime = 1
        Buffer = bytes.fromhex('{}7920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Reserved_.EVEX.W, 1)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsd2usi')
        assert_equal(myDisasm.repr(), 'vcvtsd2usi r12, qword ptr [r8]')

        myEVEX = EVEX('EVEX.LIG.F2.0F.W1')
        myEVEX.Rprime = 1
        Buffer = bytes.fromhex('{}79c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x79)
        assert_equal(myDisasm.infos.Reserved_.EVEX.W, 1)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsd2usi')
        assert_equal(myDisasm.repr(), 'vcvtsd2usi r8, xmm24')
