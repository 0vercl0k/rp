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

        # 66 0F 38 2A /r
        # MOVNTDQA xmm1, m128

        Buffer = bytes.fromhex('660f382a20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf382a')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movntdqa')
        assert_equal(myDisasm.repr(), 'movntdqa xmm4, xmmword ptr [rax]')

        # VEX.128.66.0F38.WIG 2A /r
        # VMOVNTDQA xmm1, m128

        myVEX = VEX('VEX.128.66.0F38.WIG')
        Buffer = bytes.fromhex('{}2a20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntdqa')
        assert_equal(myDisasm.repr(), 'vmovntdqa xmm12, xmmword ptr [r8]')

        # VEX.256.66.0F38.WIG 2A /r
        # VMOVNTDQA ymm1, m256

        myVEX = VEX('VEX.256.66.0F38.WIG')
        Buffer = bytes.fromhex('{}2a20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntdqa')
        assert_equal(myDisasm.repr(), 'vmovntdqa ymm12, ymmword ptr [r8]')

        # EVEX.128.66.0F38.W0 2A /r
        # VMOVNTDQA xmm1, m128

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}2a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntdqa')
        assert_equal(myDisasm.repr(), 'vmovntdqa xmm28, xmmword ptr [r8]')

        # EVEX.256.66.0F38.W0 2A /r
        # VMOVNTDQA ymm1, m256

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}2a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntdqa')
        assert_equal(myDisasm.repr(), 'vmovntdqa ymm28, ymmword ptr [r8]')

        # EVEX.512.66.0F38.W0 2A /r
        # VMOVNTDQA zmm1, m512

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}2a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovntdqa')
        assert_equal(myDisasm.repr(), 'vmovntdqa zmm28, zmmword ptr [r8]')

        # EVEX.128.F3.0F38.W1 2A /r
        # VPBROADCASTMB2Q xmm1, k1

        myEVEX = EVEX('EVEX.128.F3.0F38.W1')
        Buffer = bytes.fromhex('{}2ac0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastmb2q')
        assert_equal(myDisasm.repr(), 'vpbroadcastmb2q xmm24, k0')


        # EVEX.256.F3.0F38.W1 2A /r
        # VPBROADCASTMB2Q ymm1, k1

        myEVEX = EVEX('EVEX.256.F3.0F38.W1')
        Buffer = bytes.fromhex('{}2ac0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastmb2q')
        assert_equal(myDisasm.repr(), 'vpbroadcastmb2q ymm24, k0')

        # EVEX.512.F3.0F38.W1 2A /r
        # VPBROADCASTMB2Q zmm1, k1

        myEVEX = EVEX('EVEX.512.F3.0F38.W1')
        Buffer = bytes.fromhex('{}2ac0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastmb2q')
        assert_equal(myDisasm.repr(), 'vpbroadcastmb2q zmm24, k0')
