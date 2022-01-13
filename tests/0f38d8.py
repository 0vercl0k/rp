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
    """
    Variable Blend Packed
    """

    def test(self):

        # F3 0F 38 D8 !(11):000:bbb
        # AESENCWIDE128KL m384, <XMM0-7>

        Buffer = bytes.fromhex('f30f38d800')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38d8)
        assert_equal(myDisasm.infos.Instruction.Category, KL_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'aesencwide128kl')

        assert_equal(myDisasm.infos.Operand1.OpType, MEMORY_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpSize, 384)
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ)

        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.xmm, REG0)
        assert_equal(myDisasm.infos.Operand2.OpSize, 128)
        assert_equal(myDisasm.infos.Operand2.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand3.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand3.Registers.xmm, REG1)
        assert_equal(myDisasm.infos.Operand3.OpSize, 128)
        assert_equal(myDisasm.infos.Operand3.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand4.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand4.Registers.xmm, REG2)
        assert_equal(myDisasm.infos.Operand4.OpSize, 128)
        assert_equal(myDisasm.infos.Operand4.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand5.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand5.Registers.xmm, REG3)
        assert_equal(myDisasm.infos.Operand5.OpSize, 128)
        assert_equal(myDisasm.infos.Operand5.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand6.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand6.Registers.xmm, REG4)
        assert_equal(myDisasm.infos.Operand6.OpSize, 128)
        assert_equal(myDisasm.infos.Operand6.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand7.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand7.Registers.xmm, REG5)
        assert_equal(myDisasm.infos.Operand7.OpSize, 128)
        assert_equal(myDisasm.infos.Operand7.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand8.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand8.Registers.xmm, REG6)
        assert_equal(myDisasm.infos.Operand8.OpSize, 128)
        assert_equal(myDisasm.infos.Operand8.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand9.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand9.Registers.xmm, REG7)
        assert_equal(myDisasm.infos.Operand9.OpSize, 128)
        assert_equal(myDisasm.infos.Operand9.AccessMode, WRITE)

        assert_equal(myDisasm.repr(), 'aesencwide128kl  [rax]')

        # F3 0F 38 D8 !(11):001:bbb
        # AESDECWIDE128KL m384, <XMM0-7>

        Buffer = bytes.fromhex('f30f38d808')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38d8)
        assert_equal(myDisasm.infos.Instruction.Category, KL_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'aesdecwide128kl')

        assert_equal(myDisasm.infos.Operand1.OpType, MEMORY_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpSize, 384)
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ)

        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.xmm, REG0)
        assert_equal(myDisasm.infos.Operand2.OpSize, 128)
        assert_equal(myDisasm.infos.Operand2.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand3.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand3.Registers.xmm, REG1)
        assert_equal(myDisasm.infos.Operand3.OpSize, 128)
        assert_equal(myDisasm.infos.Operand3.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand4.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand4.Registers.xmm, REG2)
        assert_equal(myDisasm.infos.Operand4.OpSize, 128)
        assert_equal(myDisasm.infos.Operand4.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand5.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand5.Registers.xmm, REG3)
        assert_equal(myDisasm.infos.Operand5.OpSize, 128)
        assert_equal(myDisasm.infos.Operand5.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand6.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand6.Registers.xmm, REG4)
        assert_equal(myDisasm.infos.Operand6.OpSize, 128)
        assert_equal(myDisasm.infos.Operand6.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand7.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand7.Registers.xmm, REG5)
        assert_equal(myDisasm.infos.Operand7.OpSize, 128)
        assert_equal(myDisasm.infos.Operand7.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand8.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand8.Registers.xmm, REG6)
        assert_equal(myDisasm.infos.Operand8.OpSize, 128)
        assert_equal(myDisasm.infos.Operand8.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand9.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand9.Registers.xmm, REG7)
        assert_equal(myDisasm.infos.Operand9.OpSize, 128)
        assert_equal(myDisasm.infos.Operand9.AccessMode, WRITE)

        assert_equal(myDisasm.repr(), 'aesdecwide128kl  [rax]')

        # F3 0F 38 D8 !(11):010:bbb
        # AESENCWIDE256KL m512, <XMM0-7>

        Buffer = bytes.fromhex('f30f38d810')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38d8)
        assert_equal(myDisasm.infos.Instruction.Category, KL_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'aesencwide256kl')

        assert_equal(myDisasm.infos.Operand1.OpType, MEMORY_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpSize, 512)
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ)

        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.xmm, REG0)
        assert_equal(myDisasm.infos.Operand2.OpSize, 128)
        assert_equal(myDisasm.infos.Operand2.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand3.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand3.Registers.xmm, REG1)
        assert_equal(myDisasm.infos.Operand3.OpSize, 128)
        assert_equal(myDisasm.infos.Operand3.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand4.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand4.Registers.xmm, REG2)
        assert_equal(myDisasm.infos.Operand4.OpSize, 128)
        assert_equal(myDisasm.infos.Operand4.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand5.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand5.Registers.xmm, REG3)
        assert_equal(myDisasm.infos.Operand5.OpSize, 128)
        assert_equal(myDisasm.infos.Operand5.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand6.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand6.Registers.xmm, REG4)
        assert_equal(myDisasm.infos.Operand6.OpSize, 128)
        assert_equal(myDisasm.infos.Operand6.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand7.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand7.Registers.xmm, REG5)
        assert_equal(myDisasm.infos.Operand7.OpSize, 128)
        assert_equal(myDisasm.infos.Operand7.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand8.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand8.Registers.xmm, REG6)
        assert_equal(myDisasm.infos.Operand8.OpSize, 128)
        assert_equal(myDisasm.infos.Operand8.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand9.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand9.Registers.xmm, REG7)
        assert_equal(myDisasm.infos.Operand9.OpSize, 128)
        assert_equal(myDisasm.infos.Operand9.AccessMode, WRITE)

        assert_equal(myDisasm.repr(), 'aesencwide256kl  [rax]')

        # F3 0F 38 D8 !(11):011:bbb
        # AESDECWIDE256KL m512, <XMM0-7>

        Buffer = bytes.fromhex('f30f38d818')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38d8)
        assert_equal(myDisasm.infos.Instruction.Category, KL_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'aesdecwide256kl')

        assert_equal(myDisasm.infos.Operand1.OpType, MEMORY_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpSize, 512)
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ)

        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.xmm, REG0)
        assert_equal(myDisasm.infos.Operand2.OpSize, 128)
        assert_equal(myDisasm.infos.Operand2.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand3.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand3.Registers.xmm, REG1)
        assert_equal(myDisasm.infos.Operand3.OpSize, 128)
        assert_equal(myDisasm.infos.Operand3.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand4.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand4.Registers.xmm, REG2)
        assert_equal(myDisasm.infos.Operand4.OpSize, 128)
        assert_equal(myDisasm.infos.Operand4.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand5.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand5.Registers.xmm, REG3)
        assert_equal(myDisasm.infos.Operand5.OpSize, 128)
        assert_equal(myDisasm.infos.Operand5.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand6.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand6.Registers.xmm, REG4)
        assert_equal(myDisasm.infos.Operand6.OpSize, 128)
        assert_equal(myDisasm.infos.Operand6.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand7.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand7.Registers.xmm, REG5)
        assert_equal(myDisasm.infos.Operand7.OpSize, 128)
        assert_equal(myDisasm.infos.Operand7.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand8.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand8.Registers.xmm, REG6)
        assert_equal(myDisasm.infos.Operand8.OpSize, 128)
        assert_equal(myDisasm.infos.Operand8.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand9.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand9.Registers.xmm, REG7)
        assert_equal(myDisasm.infos.Operand9.OpSize, 128)
        assert_equal(myDisasm.infos.Operand9.AccessMode, WRITE)

        assert_equal(myDisasm.repr(), 'aesdecwide256kl  [rax]')
