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


        # EVEX.128.66.0F38.W0 c4 /r
        # vpconflictd xmm1{k1}{z}, m128

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c40e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictd')
        assert_equal(myDisasm.repr(), 'vpconflictd xmm25, xmmword ptr [r14]')

        # EVEX.128.66.0F38.W0 c4 /r
        # vpconflictd xmm1{k1}{z}, xmm2

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c4c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictd')
        assert_equal(myDisasm.repr(), 'vpconflictd xmm24, xmm24')

        # EVEX.256.66.0F38.W0 c4 /r
        # vpconflictd ymm1{k1}{z}, m256

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c40e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictd')
        assert_equal(myDisasm.repr(), 'vpconflictd ymm25, ymmword ptr [r14]')

        # EVEX.256.66.0F38.W0 c4 /r
        # vpconflictd ymm1{k1}{z}, ymm2

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c4c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictd')
        assert_equal(myDisasm.repr(), 'vpconflictd ymm24, ymm24')

        # EVEX.512.66.0F38.W0 c4 /r
        # vpconflictd zmm1{k1}{z}, m512

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c40e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictd')
        assert_equal(myDisasm.repr(), 'vpconflictd zmm25, zmmword ptr [r14]')

        # EVEX.512.66.0F38.W0 c4 /r
        # vpconflictd zmm1{k1}{z}, zmm2

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c4c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictd')
        assert_equal(myDisasm.repr(), 'vpconflictd zmm24, zmm24')

        # EVEX.128.66.0F38.W1 c4 /r
        # vpconflictq xmm1{k1}{z}, m128

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c40e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictq')
        assert_equal(myDisasm.repr(), 'vpconflictq xmm25, xmmword ptr [r14]')

        # EVEX.128.66.0F38.W1 c4 /r
        # vpconflictq xmm1{k1}{z}, xmm2

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c4c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictq')
        assert_equal(myDisasm.repr(), 'vpconflictq xmm24, xmm24')

        # EVEX.256.66.0F38.W1 c4 /r
        # vpconflictq ymm1{k1}{z}, m256

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c40e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictq')
        assert_equal(myDisasm.repr(), 'vpconflictq ymm25, ymmword ptr [r14]')

        # EVEX.256.66.0F38.W1 c4 /r
        # vpconflictq ymm1{k1}{z}, ymm2

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c4c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictq')
        assert_equal(myDisasm.repr(), 'vpconflictq ymm24, ymm24')

        # EVEX.512.66.0F38.W1 c4 /r
        # vpconflictq zmm1{k1}{z}, m512

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c40e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictq')
        assert_equal(myDisasm.repr(), 'vpconflictq zmm25, zmmword ptr [r14]')

        # EVEX.512.66.0F38.W1 c4 /r
        # vpconflictq zmm1{k1}{z}, zmm2

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}c4c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpconflictq')
        assert_equal(myDisasm.repr(), 'vpconflictq zmm24, zmm24')
