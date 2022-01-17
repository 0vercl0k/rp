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

        # 66 0F 7d /r
        # hsubPD xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f7d9000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf7d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'hsubpd')
        assert_equal(myDisasm.repr(), 'hsubpd xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.66.0F.WIG 7d /r
        # VhsubPD xmm1,xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}7d9000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x7d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vhsubpd')
        assert_equal(myDisasm.repr(), 'vhsubpd xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.66.0F.WIG 7d /r
        # VhsubPD ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}7d9000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x7d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vhsubpd')
        assert_equal(myDisasm.repr(), 'vhsubpd ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # F2 0F 7d /r
        # hsubPS xmm1, xmm2/m128

        Buffer = bytes.fromhex('f20f7d9000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf7d')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'hsubps')
        assert_equal(myDisasm.repr(), 'hsubps xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.F2.0F.WIG 7d /r
        # VhsubPS xmm1, xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.F2.0F.WIG')
        Buffer = bytes.fromhex('{}7d9000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x7d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vhsubps')
        assert_equal(myDisasm.repr(), 'vhsubps xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.F2.0F.WIG 7d /r
        # VhsubPS ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.F2.0F.WIG')
        Buffer = bytes.fromhex('{}7d9000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x7d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vhsubps')
        assert_equal(myDisasm.repr(), 'vhsubps ymm10, ymm15, ymmword ptr [r8+00000000h]')
