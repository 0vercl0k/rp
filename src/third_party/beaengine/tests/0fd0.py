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


        # 66 0F D0 /r
        # ADDSUBPD xmm1, xmm2/m128

        Buffer = bytes.fromhex('660fd020')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfd0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addsubpd')
        assert_equal(myDisasm.repr(), 'addsubpd xmm4, xmmword ptr [rax]')

        # VEX.NDS.128.66.0F.WIG D0 /r
        # VADDSUBPD xmm1, xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}d020'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xd0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddsubpd')
        assert_equal(myDisasm.repr(), 'vaddsubpd xmm12, xmm15, xmmword ptr [r8]')

        # VEX.NDS.256.66.0F.WIG D0 /r
        # VADDSUBPD ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}d020'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xd0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddsubpd')
        assert_equal(myDisasm.repr(), 'vaddsubpd ymm12, ymm15, ymmword ptr [r8]')

        # F2 0F D0 /r
        # ADDSUBPS xmm1, xmm2/m128

        Buffer = bytes.fromhex('f20fd020')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfd0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addsubps')
        assert_equal(myDisasm.repr(), 'addsubps xmm4, xmmword ptr [rax]')

        # VEX.NDS.128.F2.0F.WIG D0 /r
        # VADDSUBPS xmm1, xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.F2.0F.WIG')
        Buffer = bytes.fromhex('{}d020'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xd0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddsubps')
        assert_equal(myDisasm.repr(), 'vaddsubps xmm12, xmm15, xmmword ptr [r8]')

        # VEX.NDS.256.F2.0F.WIG D0 /r
        # VADDSUBPS ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.F2.0F.WIG')
        Buffer = bytes.fromhex('{}d020'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xd0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddsubps')
        assert_equal(myDisasm.repr(), 'vaddsubps ymm12, ymm15, ymmword ptr [r8]')
