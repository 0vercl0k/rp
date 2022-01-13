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


        # EVEX.NDS.128.66.0F38.W0 26 /r
        # VPTESTMB k2 {k1}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.NDS.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmb')
        assert_equal(myDisasm.repr(), 'vptestmb k?, xmm31, xmmword ptr [r8]')

        # EVEX.NDS.256.66.0F38.W0 26 /r
        # VPTESTMB k2 {k1}, ymm2, ymm3/m256

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmb')
        assert_equal(myDisasm.repr(), 'vptestmb k?, ymm31, ymmword ptr [r8]')

        # EVEX.NDS.512.66.0F38.W0 26 /r
        # VPTESTMB k2 {k1}, zmm2, zmm3/m512

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmb')
        assert_equal(myDisasm.repr(), 'vptestmb k?, zmm31, zmmword ptr [r8]')

        # EVEX.NDS.128.66.0F38.W1 26 /r
        # VPTESTMW k2 {k1}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.NDS.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmw')
        assert_equal(myDisasm.repr(), 'vptestmw k?, xmm31, xmmword ptr [r8]')

        # EVEX.NDS.256.66.0F38.W1 26 /r
        # VPTESTMW k2 {k1}, ymm2, ymm3/m256

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmw')
        assert_equal(myDisasm.repr(), 'vptestmw k?, ymm31, ymmword ptr [r8]')

        # EVEX.NDS.512.66.0F38.W1 26 /r
        # VPTESTMW k2 {k1}, zmm2, zmm3/m512

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmw')
        assert_equal(myDisasm.repr(), 'vptestmw k?, zmm31, zmmword ptr [r8]')

        # EVEX.NDS.128.F3.0F38.W0 26 /r
        # VPTESTNMB k2 {k1}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.NDS.128.F3.0F38.W0')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmb')
        assert_equal(myDisasm.repr(), 'vptestnmb k?, xmm31, xmmword ptr [r8]')

        # EVEX.NDS.256.F3.0F38.W0 26 /r
        # VPTESTNMB k2 {k1}, ymm2, ymm3/m256

        myEVEX = EVEX('EVEX.NDS.256.F3.0F38.W0')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmb')
        assert_equal(myDisasm.repr(), 'vptestnmb k?, ymm31, ymmword ptr [r8]')

        # EVEX.NDS.512.F3.0F38.W0 26 /r
        # VPTESTNMB k2 {k1}, zmm2, zmm3/m512

        myEVEX = EVEX('EVEX.NDS.512.F3.0F38.W0')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmb')
        assert_equal(myDisasm.repr(), 'vptestnmb k?, zmm31, zmmword ptr [r8]')

        # EVEX.NDS.128.F3.0F38.W1 26 /r
        # VPTESTNMW k2 {k1}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.NDS.128.F3.0F38.W1')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmw')
        assert_equal(myDisasm.repr(), 'vptestnmw k?, xmm31, xmmword ptr [r8]')

        # EVEX.NDS.256.F3.0F38.W1 26 /r
        # VPTESTNMW k2 {k1}, ymm2, ymm3/m256

        myEVEX = EVEX('EVEX.NDS.256.F3.0F38.W1')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmw')
        assert_equal(myDisasm.repr(), 'vptestnmw k?, ymm31, ymmword ptr [r8]')

        # EVEX.NDS.512.F3.0F38.W1 26 /r
        # VPTESTNMW k2 {k1}, zmm2, zmm3/m512

        myEVEX = EVEX('EVEX.NDS.512.F3.0F38.W1')
        Buffer = bytes.fromhex('{}2620'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x26)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmw')
        assert_equal(myDisasm.repr(), 'vptestnmw k?, zmm31, zmmword ptr [r8]')
