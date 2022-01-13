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
        # 66 0F 38 29 /r
        # pcmpeqq mm1, mm2/m64
        Buffer = bytes.fromhex('660f38299011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf3829')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pcmpeqq')
        assert_equal(myDisasm.repr(), 'pcmpeqq xmm2, xmmword ptr [rax+44332211h]')

        # VEX.NDS.128.66.0F38.WIG 29 /r
        # vpcmpeqq xmm1, xmm2, xmm3/m128
        Buffer = bytes.fromhex('c40201290e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcmpeqq')
        assert_equal(myDisasm.repr(), 'vpcmpeqq xmm9, xmm15, xmmword ptr [r14]')

        # VEX.NDS.256.66.0F38.WIG 29 /r
        # vpcmpeqq ymm1, ymm2, ymm3/m256
        Buffer = bytes.fromhex('c40205290e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcmpeqq')
        assert_equal(myDisasm.repr(), 'vpcmpeqq ymm9, ymm15, ymmword ptr [r14]')

        # EVEX.NDS.128.66.0F38.WIG 29 /r
        # vpcmpeqq xmm1 {k1}{z}, xmm2, xmm3/m128
        Buffer = bytes.fromhex('62020506290e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x6)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x29')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcmpeqq')
        assert_equal(myDisasm.repr(), 'vpcmpeqq xmm25, xmm31, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F38.WIG 29 /r
        # vpcmpeqq ymm1 {k1}{z}, ymm2, ymm3/m256
        Buffer = bytes.fromhex('62020520290e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x20)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x29')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcmpeqq')
        assert_equal(myDisasm.repr(), 'vpcmpeqq ymm25, ymm31, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F38.WIG 29 /r
        # vpcmpeqq zmm1 {k1}{z}, zmm2, zmm3/m512
        Buffer = bytes.fromhex('62020540290e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x40)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x29')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcmpeqq')
        assert_equal(myDisasm.repr(), 'vpcmpeqq zmm25, zmm31, zmmword ptr [r14]')


        # EVEX.128.F3.0F38.W0 29 /r
        # VPMOVB2M k1, xmm1

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        Buffer = bytes.fromhex('{}29c1'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x29)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovb2m')
        assert_equal(myDisasm.repr(), 'vpmovb2m k?, xmm25')

        # EVEX.256.F3.0F38.W0 29 /r
        # VPMOVB2M k1, ymm1

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        Buffer = bytes.fromhex('{}29c1'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x29)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovb2m')
        assert_equal(myDisasm.repr(), 'vpmovb2m k?, ymm25')

        # EVEX.512.F3.0F38.W0 29 /r
        # VPMOVB2M k1, zmm1

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        Buffer = bytes.fromhex('{}29c1'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x29)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovb2m')
        assert_equal(myDisasm.repr(), 'vpmovb2m k?, zmm25')

        # EVEX.128.F3.0F38.W1 29 /r
        # VPMOVW2M k1, xmm1

        myEVEX = EVEX('EVEX.128.F3.0F38.W1')
        Buffer = bytes.fromhex('{}29c1'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x29)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovw2m')
        assert_equal(myDisasm.repr(), 'vpmovw2m k?, xmm25')

        # EVEX.256.F3.0F38.W1 29 /r
        # VPMOVW2M k1, ymm1

        myEVEX = EVEX('EVEX.256.F3.0F38.W1')
        Buffer = bytes.fromhex('{}29c1'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x29)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovw2m')
        assert_equal(myDisasm.repr(), 'vpmovw2m k?, ymm25')

        # EVEX.512.F3.0F38.W1 29 /r
        # VPMOVW2M k1, zmm1

        myEVEX = EVEX('EVEX.512.F3.0F38.W1')
        Buffer = bytes.fromhex('{}29c1'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x29)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovw2m')
        assert_equal(myDisasm.repr(), 'vpmovw2m k?, zmm25')
