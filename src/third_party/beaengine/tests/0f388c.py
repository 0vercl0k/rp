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



        # VEX.128.66.0F38.W0 8C /r
        # VPMASKMOVD xmm1, xmm2, m128

        myVEX = VEX('VEX.128.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}8c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaskmovd')
        assert_equal(myDisasm.repr(), 'vpmaskmovd xmm10, xmm0, xmmword ptr [r8]')

        # VEX.256.66.0F38.W0 8C /r
        # VPMASKMOVD ymm1, ymm2, m256

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}8c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaskmovd')
        assert_equal(myDisasm.repr(), 'vpmaskmovd ymm10, ymm0, ymmword ptr [r8]')

        # VEX.128.66.0F38.W1 8C /r
        # VPMASKMOVQ xmm1, xmm2, m128

        myVEX = VEX('VEX.128.66.0F38.W1')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}8c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaskmovq')
        assert_equal(myDisasm.repr(), 'vpmaskmovq xmm10, xmm0, xmmword ptr [r8]')

        # VEX.256.66.0F38.W1 8C /r
        # VPMASKMOVQ ymm1, ymm2, m256

        myVEX = VEX('VEX.256.66.0F38.W1')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}8c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaskmovq')
        assert_equal(myDisasm.repr(), 'vpmaskmovq ymm10, ymm0, ymmword ptr [r8]')
