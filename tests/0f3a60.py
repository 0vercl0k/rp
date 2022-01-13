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

        # 66 0F 3A 60 /r imm8
        # PCMPESTRM xmm1, xmm2/m128, imm8

        Buffer = bytes.fromhex('660f3a602001')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf3a60)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pcmpestrm')
        assert_equal(myDisasm.repr(), 'pcmpestrm xmm4, xmmword ptr [rax], 01h')

        # VEX.128.66.0F3A 60 /r ib
        # VPCMPESTRM xmm1, xmm2/m128, imm8

        myVEX = VEX('VEX.128.66.0F3A.')
        Buffer = bytes.fromhex('{}601033'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x60)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcmpestrm')
        assert_equal(myDisasm.repr(), 'vpcmpestrm xmm10, xmmword ptr [r8], 33h')
