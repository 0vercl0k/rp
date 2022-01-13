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


        # VEX.256.66.0F38.W0 16 /r
        # VPERMPS ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1620'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermps')
        assert_equal(myDisasm.repr(), 'vpermps ymm12, ymm0, ymmword ptr [r8]')

        # EVEX.NDS.256.66.0F38.W0 16 /r
        # VPERMPS ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermps')
        assert_equal(myDisasm.repr(), 'vpermps ymm28, ymm16, ymmword ptr [r8]')

        # EVEX.NDS.512.66.0F38.W0 16 /r
        # VPERMPS zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermps')
        assert_equal(myDisasm.repr(), 'vpermps zmm28, zmm16, zmmword ptr [r8]')

        # EVEX.NDS.256.66.0F38.W1 16 /r
        # VPERMPD ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermpd')
        assert_equal(myDisasm.repr(), 'vpermpd ymm28, ymm16, ymmword ptr [r8]')

        # EVEX.NDS.512.66.0F38.W1 16 /r
        # VPERMPD zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermpd')
        assert_equal(myDisasm.repr(), 'vpermpd zmm28, zmm16, zmmword ptr [r8]')
