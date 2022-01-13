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

        # VEX.NDS.256.66.0F38.W0 36 /r
        # VPERMD ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}3620'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x36)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermd')
        assert_equal(myDisasm.repr(), 'vpermd ymm12, ymm15, ymmword ptr [r8]')

        # EVEX.NDS.256.66.0F38.W0 36 /r
        # VPERMD ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}3620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x36)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermd')
        assert_equal(myDisasm.repr(), 'vpermd ymm28, ymm31, ymmword ptr [r8]')

        # EVEX.NDS.512.66.0F38.W0 36 /r
        # VPERMD zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}3620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x36)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermd')
        assert_equal(myDisasm.repr(), 'vpermd zmm28, zmm31, zmmword ptr [r8]')

        # EVEX.NDS.256.66.0F38.W1 36 /r
        # VPERMQ ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}3620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x36)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermq')
        assert_equal(myDisasm.repr(), 'vpermq ymm28, ymm31, ymmword ptr [r8]')

        # EVEX.NDS.512.66.0F38.W1 36 /r
        # VPERMQ zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}3620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x36)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermq')
        assert_equal(myDisasm.repr(), 'vpermq zmm28, zmm31, zmmword ptr [r8]')
