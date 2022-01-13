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

        # EVEX.128.66.0F38.W0 88 /r
        # VEXPANDPS xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}880e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x88)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vexpandps')
        assert_equal(myDisasm.repr(), 'vexpandps xmm25, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W0 88 /r
        # VEXPANDPS ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}880e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x88)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vexpandps')
        assert_equal(myDisasm.repr(), 'vexpandps ymm25, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W0 88 /r
        # VEXPANDPS zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}880e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x88)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vexpandps')
        assert_equal(myDisasm.repr(), 'vexpandps zmm25, zmmword ptr [r14]')

        # EVEX.128.66.0F38.W1 88 /r
        # VEXPANDPD xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}880e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x88)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vexpandpd')
        assert_equal(myDisasm.repr(), 'vexpandpd xmm25, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W1 88 /r
        # VEXPANDPD ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}880e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x88)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vexpandpd')
        assert_equal(myDisasm.repr(), 'vexpandpd ymm25, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W1 88 /r
        # VEXPANDPD zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}880e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x88)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vexpandpd')
        assert_equal(myDisasm.repr(), 'vexpandpd zmm25, zmmword ptr [r14]')
