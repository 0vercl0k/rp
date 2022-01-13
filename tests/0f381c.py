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

        # NP 0F 38 1C /r1
        # PABSB mm1, mm2/m64

        Buffer = bytes.fromhex('0f381c6b11')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf381c')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pabsb')
        assert_equal(myDisasm.repr(), 'pabsb mm5, qword ptr [rbx+11h]')

        # 66 0F 38 1C /r
        # PABSB xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f381c6b11')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf381c')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pabsb')
        assert_equal(myDisasm.repr(), 'pabsb xmm5, xmmword ptr [rbx+11h]')

        # VEX.128.66.0F38.WIG 1C /r
        # VPABSB xmm1, xmm2/m128

        myVEX = VEX('VEX.128.66.0F38.WIG')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpabsb')
        assert_equal(myDisasm.repr(), 'vpabsb xmm10, xmmword ptr [r8]')

        # VEX.256.66.0F38.WIG 1C /r
        # VPABSB ymm1, ymm2/m256

        # EVEX.128.66.0F38.WIG 1C /r
        # VPABSB xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.66.0F38.WIG')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1c20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpabsb')
        assert_equal(myDisasm.repr(), 'vpabsb xmm28, xmmword ptr [r8]')

        # EVEX.256.66.0F38.WIG 1C /r
        # VPABSB ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.66.0F38.WIG')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1c20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpabsb')
        assert_equal(myDisasm.repr(), 'vpabsb ymm28, ymmword ptr [r8]')

        # EVEX.512.66.0F38.WIG 1C /r
        # VPABSB zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.66.0F38.WIG')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1c20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpabsb')
        assert_equal(myDisasm.repr(), 'vpabsb zmm28, zmmword ptr [r8]')
