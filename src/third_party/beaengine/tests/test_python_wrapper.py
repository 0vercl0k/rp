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
import struct
import yaml

class TestSuite:

    def test(self):

        #
        # Test json representation
        #

        myDisasm = Disasm(bytes.fromhex('6202054000443322'))
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'vpshufb zmm24, zmm31, zmmword ptr [r11+r14+0880h]')
        assert_equal(myDisasm.modifies("zmm24"), True)
        assert_equal(myDisasm.uses("r11 r14 zmm31"), True)
        json_output = myDisasm.structure()
        assert_equal(json_output.get('category'), "AVX512_INSTRUCTION")
        assert_equal(json_output['bytes'], "62 02 05 40 00 44 33 22")
        assert_equal(json_output['arch'], 64)
        assert_equal(json_output['mnemonic'], "vpshufb")
        assert_equal(json_output['operands'][1]['repr'], "zmm24")
        assert_equal(json_output['operands'][1]['type'], "register")
        assert_equal(json_output['operands'][1]['size'], 512)
        assert_equal(json_output['operands'][1]['mode'], "write")
        assert_equal(json_output['operands'][1]['register']['type'], "zmm")
        assert_equal(json_output.get('operands').get(1).get('type'), "register")

        #
        # Test used registers
        #

        buffer = bytes.fromhex('4831c0')
        myDisasm = Disasm(buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), "xor rax, rax")
        assert_equal(myDisasm.modifies("rax"), True)
        assert_equal(myDisasm.uses("rax gpr"), True)
        assert_equal(myDisasm.uses("gpr"), True)

        # Test used jumps
        #
        # e901000000    jmp $+1
        # cc            int3
        # 90            nop

        myDisasm = Disasm(bytes.fromhex('e901000000cc90'))
        # read first instruction
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'jmp')
        assert_equal(myDisasm.is_jump(), True)
        # change offset to point at jump target
        myDisasm.follow()
        # read next instruction
        myDisasm.read()
        assert_equal(myDisasm.repr(), "nop")

        #
        # Test segment registers
        #

        myDisasm = Disasm(bytes.fromhex('65488B042560000000'))
        myDisasm.read()
        assert_equal(myDisasm.repr(), "mov rax, qword ptr gs:[00000060h]")
        assert_equal(myDisasm.uses("gs"), True)
