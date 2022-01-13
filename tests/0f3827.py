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


        # EVEX.NDS.128.66.0F38.W0 27 /r
        # vptestmd k2 {k1}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.NDS.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmd')
        assert_equal(myDisasm.repr(), 'vptestmd k?, xmm31, xmmword ptr [r8]')

        # EVEX.NDS.256.66.0F38.W0 27 /r
        # vptestmd k2 {k1}, ymm2, ymm3/m256

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmd')
        assert_equal(myDisasm.repr(), 'vptestmd k?, ymm31, ymmword ptr [r8]')

        # EVEX.NDS.512.66.0F38.W0 27 /r
        # vptestmd k2 {k1}, zmm2, zmm3/m512

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmd')
        assert_equal(myDisasm.repr(), 'vptestmd k?, zmm31, zmmword ptr [r8]')

        # EVEX.NDS.128.66.0F38.W1 27 /r
        # vptestmq k2 {k1}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.NDS.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmq')
        assert_equal(myDisasm.repr(), 'vptestmq k?, xmm31, xmmword ptr [r8]')

        # EVEX.NDS.256.66.0F38.W1 27 /r
        # vptestmq k2 {k1}, ymm2, ymm3/m256

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmq')
        assert_equal(myDisasm.repr(), 'vptestmq k?, ymm31, ymmword ptr [r8]')

        # EVEX.NDS.512.66.0F38.W1 27 /r
        # vptestmq k2 {k1}, zmm2, zmm3/m512

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestmq')
        assert_equal(myDisasm.repr(), 'vptestmq k?, zmm31, zmmword ptr [r8]')

        # EVEX.NDS.128.F3.0F38.W0 27 /r
        # vptestnmd k2 {k1}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.NDS.128.F3.0F38.W0')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmd')
        assert_equal(myDisasm.repr(), 'vptestnmd k?, xmm31, xmmword ptr [r8]')

        # EVEX.NDS.256.F3.0F38.W0 27 /r
        # vptestnmd k2 {k1}, ymm2, ymm3/m256

        myEVEX = EVEX('EVEX.NDS.256.F3.0F38.W0')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmd')
        assert_equal(myDisasm.repr(), 'vptestnmd k?, ymm31, ymmword ptr [r8]')

        # EVEX.NDS.512.F3.0F38.W0 27 /r
        # vptestnmd k2 {k1}, zmm2, zmm3/m512

        myEVEX = EVEX('EVEX.NDS.512.F3.0F38.W0')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmd')
        assert_equal(myDisasm.repr(), 'vptestnmd k?, zmm31, zmmword ptr [r8]')

        # EVEX.NDS.128.F3.0F38.W1 27 /r
        # vptestnmq k2 {k1}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.NDS.128.F3.0F38.W1')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmq')
        assert_equal(myDisasm.repr(), 'vptestnmq k?, xmm31, xmmword ptr [r8]')

        # EVEX.NDS.256.F3.0F38.W1 27 /r
        # vptestnmq k2 {k1}, ymm2, ymm3/m256

        myEVEX = EVEX('EVEX.NDS.256.F3.0F38.W1')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmq')
        assert_equal(myDisasm.repr(), 'vptestnmq k?, ymm31, ymmword ptr [r8]')

        # EVEX.NDS.512.F3.0F38.W1 27 /r
        # vptestnmq k2 {k1}, zmm2, zmm3/m512

        myEVEX = EVEX('EVEX.NDS.512.F3.0F38.W1')
        Buffer = bytes.fromhex('{}2720'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptestnmq')
        assert_equal(myDisasm.repr(), 'vptestnmq k?, zmm31, zmmword ptr [r8]')
