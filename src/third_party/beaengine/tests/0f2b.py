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


        # NP 0F 2B /r
        # MOVNTPS m128, xmm1

        Buffer = bytes.fromhex('0f2b20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movntps')
        assert_equal(myDisasm.repr(), 'movntps xmmword ptr [rax], xmm4')

        # VEX.128.0F.WIG 2B /r
        # VMOVNTPS m128, xmm1

        myVEX = VEX('VEX.128.0F.WIG')
        Buffer = bytes.fromhex('{}2b10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntps')
        assert_equal(myDisasm.repr(), 'vmovntps xmmword ptr [r8], xmm10')

        # VEX.256.0F.WIG 2B /r
        # VMOVNTPS m256, ymm1

        myVEX = VEX('VEX.256.0F.WIG')
        Buffer = bytes.fromhex('{}2b10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntps')
        assert_equal(myDisasm.repr(), 'vmovntps ymmword ptr [r8], ymm10')

        # EVEX.128.0F.W0 2B /r
        # VMOVNTPS m128, xmm1

        myEVEX = EVEX('EVEX.128.0F.W0')
        Buffer = bytes.fromhex('{}2b16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntps')
        assert_equal(myDisasm.repr(), 'vmovntps xmmword ptr [r14], xmm26')

        # EVEX.256.0F.W0 2B /r
        # VMOVNTPS m256, ymm1

        myEVEX = EVEX('EVEX.256.0F.W0')
        Buffer = bytes.fromhex('{}2b16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntps')
        assert_equal(myDisasm.repr(), 'vmovntps ymmword ptr [r14], ymm26')

        # EVEX.512.0F.W0 2B /r
        # VMOVNTPS m512, zmm1

        myEVEX = EVEX('EVEX.512.0F.W0')
        Buffer = bytes.fromhex('{}2b16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntps')
        assert_equal(myDisasm.repr(), 'vmovntps zmmword ptr [r14], zmm26')

        # 66 0F 2B /r
        # MOVNTPD m128, xmm1

        Buffer = bytes.fromhex('660f2b20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movntpd')
        assert_equal(myDisasm.repr(), 'movntpd xmmword ptr [rax], xmm4')

        # VEX.128.66.0F.WIG 2B /r
        # VMOVNTPD m128, xmm1

        myVEX = VEX('VEX.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}2b10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntpd')
        assert_equal(myDisasm.repr(), 'vmovntpd xmmword ptr [r8], xmm10')

        # VEX.256.66.0F.WIG 2B /r
        # VMOVNTPD m256, ymm1

        myVEX = VEX('VEX.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}2b10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntpd')
        assert_equal(myDisasm.repr(), 'vmovntpd ymmword ptr [r8], ymm10')

        # EVEX.128.66.0F.W1 2B /r
        # VMOVNTPD m128, xmm1

        myEVEX = EVEX('EVEX.128.66.0F.W1')
        Buffer = bytes.fromhex('{}2b16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntpd')
        assert_equal(myDisasm.repr(), 'vmovntpd xmmword ptr [r14], xmm26')

        # EVEX.256.66.0F.W1 2B /r
        # VMOVNTPD m256, ymm1

        myEVEX = EVEX('EVEX.256.66.0F.W1')
        Buffer = bytes.fromhex('{}2b16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntpd')
        assert_equal(myDisasm.repr(), 'vmovntpd ymmword ptr [r14], ymm26')

        # EVEX.512.66.0F.W1 2B /r
        # VMOVNTPD m512, zmm1

        myEVEX = EVEX('EVEX.512.66.0F.W1')
        Buffer = bytes.fromhex('{}2b16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntpd')
        assert_equal(myDisasm.repr(), 'vmovntpd zmmword ptr [r14], zmm26')
