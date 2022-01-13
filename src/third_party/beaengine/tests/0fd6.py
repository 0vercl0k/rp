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


        # F3 0F D6 /r
        # MOVQ2DQ xmm, mm

        Buffer = bytes.fromhex('f30fd6c0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfd6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movq2dq')
        assert_equal(myDisasm.repr(), 'movq2dq xmm0, mm0')

        # F2 0F D6 /r
        # MOVDQ2Q mm, xmm

        Buffer = bytes.fromhex('f20fd6c0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfd6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movdq2q')
        assert_equal(myDisasm.repr(), 'movdq2q mm0, xmm0')

        # 66 0F D6 /r
        # MOVQ xmm2/m64, xmm1

        Buffer = bytes.fromhex('660fd620')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfd6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movq')
        assert_equal(myDisasm.repr(), 'movq qword ptr [rax], xmm4')

        # VEX.128.66.0F.WIG D6 /r
        # VMOVQ xmm1/m64, xmm2

        myVEX = VEX('VEX.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}d620'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xd6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovq')
        assert_equal(myDisasm.repr(), 'vmovq dword ptr [r8], xmm12')

        # EVEX.128.66.0F.W1 D6 /r
        # VMOVQ xmm1/m64, xmm2

        myEVEX = EVEX('EVEX.128.66.0F.W1')
        Buffer = bytes.fromhex('{}d620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xd6)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovq')
        assert_equal(myDisasm.repr(), 'vmovq dword ptr [r8], xmm28')
