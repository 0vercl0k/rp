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

        # EVEX.NDS.128.66.0F38.W1 11 /r
        # VPSRAVW xmm1 {k1}{z}, xmm2,xmm3/m128

        myEVEX = EVEX('EVEX.NDS.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}1116'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x11)
        assert_equal(myDisasm.infos.Reserved_.VEX.pp, 1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.W, 1)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpsravw')
        assert_equal(myDisasm.repr(), 'vpsravw xmm26, xmm31, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F38.W1 11 /r
        # VPSRAVW ymm1 {k1}{z}, ymm2,ymm3/m256

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}1116'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x11)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpsravw')
        assert_equal(myDisasm.repr(), 'vpsravw ymm26, ymm31, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F38.W1 11 /r
        # VPSRAVW zmm1 {k1}{z}, zmm2,zmm3/m512

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}1116'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x11)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpsravw')
        assert_equal(myDisasm.repr(), 'vpsravw zmm26, zmm31, zmmword ptr [r14]')

        # EVEX.128.F3.0F38.W0 11 /r
        # VPMOVUSDB xmm1/m32 {k1}{z}, xmm2

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        Buffer = bytes.fromhex('{}1116'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x11)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdb')
        assert_equal(myDisasm.repr(), 'vpmovusdb dword ptr [r14], xmm26')

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        Buffer = bytes.fromhex('{}11c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x11)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdb')
        assert_equal(myDisasm.repr(), 'vpmovusdb xmm24, xmm24')

        # EVEX.256.F3.0F38.W0 11 /r
        # VPMOVUSDB xmm1/m64 {k1}{z}, ymm2

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        Buffer = bytes.fromhex('{}1116'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x11)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdb')
        assert_equal(myDisasm.repr(), 'vpmovusdb qword ptr [r14], ymm26')

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        Buffer = bytes.fromhex('{}11c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x11)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdb')
        assert_equal(myDisasm.repr(), 'vpmovusdb xmm24, ymm24')

        # EVEX.512.F3.0F38.W0 11 /r
        # VPMOVUSDB xmm1/m128 {k1}{z}, zmm2

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        Buffer = bytes.fromhex('{}1116'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x11)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdb')
        assert_equal(myDisasm.repr(), 'vpmovusdb xmmword ptr [r14], zmm26')

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        Buffer = bytes.fromhex('{}11c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x11)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdb')
        assert_equal(myDisasm.repr(), 'vpmovusdb xmm24, zmm24')
