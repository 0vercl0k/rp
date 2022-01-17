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

        # EVEX.128.66.0F38.W0 63 /r
        # VPCOMPRESSB m128{k1}, xmm1

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}630e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressb')
        assert_equal(myDisasm.repr(), 'vpcompressb xmmword ptr [r14], xmm25')

        # EVEX.128.66.0F38.W0 63 /r
        # VPCOMPRESSB xmm1{k1}{z}, xmm2

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}63c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressb')
        assert_equal(myDisasm.repr(), 'vpcompressb xmm24, xmm24')

        # EVEX.256.66.0F38.W0 63 /r
        # VPCOMPRESSB m256{k1}, ymm1

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}630e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressb')
        assert_equal(myDisasm.repr(), 'vpcompressb ymmword ptr [r14], ymm25')

        # EVEX.256.66.0F38.W0 63 /r
        # VPCOMPRESSB ymm1{k1}{z}, ymm2

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}63c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressb')
        assert_equal(myDisasm.repr(), 'vpcompressb ymm24, ymm24')

        # EVEX.512.66.0F38.W0 63 /r
        # VPCOMPRESSB m512{k1}, zmm1

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}630e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressb')
        assert_equal(myDisasm.repr(), 'vpcompressb zmmword ptr [r14], zmm25')

        # EVEX.512.66.0F38.W0 63 /r
        # VPCOMPRESSB zmm1{k1}{z}, zmm2

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}63c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressb')
        assert_equal(myDisasm.repr(), 'vpcompressb zmm24, zmm24')

        # EVEX.128.66.0F38.W1 63 /r
        # VPCOMPRESSW m128{k1}, xmm1

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}630e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressw')
        assert_equal(myDisasm.repr(), 'vpcompressw xmmword ptr [r14], xmm25')

        # EVEX.128.66.0F38.W1 63 /r
        # VPCOMPRESSW xmm1{k1}{z}, xmm2

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}63c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressw')
        assert_equal(myDisasm.repr(), 'vpcompressw xmm24, xmm24')

        # EVEX.256.66.0F38.W1 63 /r
        # VPCOMPRESSW m256{k1}, ymm1

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}630e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressw')
        assert_equal(myDisasm.repr(), 'vpcompressw ymmword ptr [r14], ymm25')

        # EVEX.256.66.0F38.W1 63 /r
        # VPCOMPRESSW ymm1{k1}{z}, ymm2

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}63c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressw')
        assert_equal(myDisasm.repr(), 'vpcompressw ymm24, ymm24')

        # EVEX.512.66.0F38.W1 63 /r
        # VPCOMPRESSW m512{k1}, zmm1

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}630e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressw')
        assert_equal(myDisasm.repr(), 'vpcompressw zmmword ptr [r14], zmm25')

        # EVEX.512.66.0F38.W1 63 /r
        # VPCOMPRESSW zmm1{k1}{z}, zmm2

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}63c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x63)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressw')
        assert_equal(myDisasm.repr(), 'vpcompressw zmm24, zmm24')
