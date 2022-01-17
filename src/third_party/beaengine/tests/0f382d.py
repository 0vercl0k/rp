
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

        # EVEX.LIG.66.0F38.W0 2D /r
        # VSCALEFSS xmm1 {k1}{z}, xmm2, xmm3/m32{er}

        myEVEX = EVEX('EVEX.LIG.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2d20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vscalefss')
        assert_equal(myDisasm.repr(), 'vscalefss xmm28, xmm16, xmmword ptr [r8]')

        # EVEX.LIG.66.0F38.W1 2D /r
        # VSCALEFSD xmm1 {k1}{z}, xmm2, xmm3/m64{er}

        myEVEX = EVEX('EVEX.LIG.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2d20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vscalefsd')
        assert_equal(myDisasm.repr(), 'vscalefsd xmm28, xmm16, xmmword ptr [r8]')

        # VEX.128.66.0F38.W0 2D /r
        # VMASKMOVPD xmm1, xmm2, m128

        myVEX = VEX('VEX.128.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2d10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaskmovpd')
        assert_equal(myDisasm.repr(), 'vmaskmovpd xmm10, xmm0, xmmword ptr [r8]')

        # VEX.256.66.0F38.W0 2D /r
        # VMASKMOVPD ymm1, ymm2, m256

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2d10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaskmovpd')
        assert_equal(myDisasm.repr(), 'vmaskmovpd ymm10, ymm0, ymmword ptr [r8]')
