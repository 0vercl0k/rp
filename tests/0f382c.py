
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

        # VEX.128.66.0F38.W0 2C /r
        # VMASKMOVPS xmm1, xmm2, m128

        myVEX = VEX('VEX.128.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaskmovps')
        assert_equal(myDisasm.repr(), 'vmaskmovps xmm10, xmm0, xmmword ptr [r8]')

        # VEX.256.66.0F38.W0 2C /r
        # VMASKMOVPS ymm1, ymm2, m256

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaskmovps')
        assert_equal(myDisasm.repr(), 'vmaskmovps ymm10, ymm0, ymmword ptr [r8]')

        # EVEX.128.66.0F38.W0 2C /r
        # VSCALEFPS xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2c20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vscalefps')
        assert_equal(myDisasm.repr(), 'vscalefps xmm28, xmm16, xmmword ptr [r8]')

        # EVEX.256.66.0F38.W0 2C /r
        # VSCALEFPS ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2c20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vscalefps')
        assert_equal(myDisasm.repr(), 'vscalefps ymm28, ymm16, ymmword ptr [r8]')

        # EVEX.512.66.0F38.W0 2C /r
        # VSCALEFPS zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst{er}

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2c20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vscalefps')
        assert_equal(myDisasm.repr(), 'vscalefps zmm28, zmm16, zmmword ptr [r8]')

        # EVEX.128.66.0F38.W1 2C /r
        # VSCALEFPD xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2c20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vscalefpd')
        assert_equal(myDisasm.repr(), 'vscalefpd xmm28, xmm16, xmmword ptr [r8]')

        # EVEX.256.66.0F38.W1 2C /r
        # VSCALEFPD ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2c20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vscalefpd')
        assert_equal(myDisasm.repr(), 'vscalefpd ymm28, ymm16, ymmword ptr [r8]')

        # EVEX.512.66.0F38.W1 2C /r
        # VSCALEFPD zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst{er}

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2c20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vscalefpd')
        assert_equal(myDisasm.repr(), 'vscalefpd zmm28, zmm16, zmmword ptr [r8]')
