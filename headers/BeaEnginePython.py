# =====================================
#
#	BeaEngine 5.x header for Python
#	using ctypes
#
# =====================================

from ctypes import *
import re
import json

INSTRUCT_LENGTH = 80

class REX_Struct(Structure):
   _pack_= 1
   _fields_= [("W_",c_uint8),
              ("R_",c_uint8),
              ("X_",c_uint8),
              ("B_",c_uint8),
              ("state",c_uint8)]

class PREFIXINFO(Structure):
   _pack_= 1
   _fields_= [("Number",c_int),
              ("NbUndefined",c_int),
              ("LockPrefix",c_uint8),
              ("OperandSize",c_uint8),
              ("AddressSize",c_uint8),
              ("RepnePrefix",c_uint8),
              ("RepPrefix",c_uint8),
              ("FSPrefix",c_uint8),
              ("SSPrefix",c_uint8),
              ("GSPrefix",c_uint8),
              ("ESPrefix",c_uint8),
              ("CSPrefix",c_uint8),
              ("DSPrefix",c_uint8),
              ("BranchTaken",c_uint8),
              ("BranchNotTaken",c_uint8),
              ("REX",REX_Struct),
			  ("alignment1",c_uint8),
			  ("alignment2",c_uint8)]

class EFLStruct(Structure):
   _pack_= 1
   _fields_= [("OF_",c_uint8),
              ("SF_",c_uint8),
              ("ZF_",c_uint8),
              ("AF_",c_uint8),
              ("PF_",c_uint8),
              ("CF_",c_uint8),
              ("TF_",c_uint8),
              ("IF_",c_uint8),
              ("DF_",c_uint8),
              ("NT_",c_uint8),
              ("RF_",c_uint8),
              ("alignment",c_uint8)]

class REGISTERTYPE(Structure):
   _pack_= 4
   _fields_= [("type", c_int64),
              ("gpr",c_int64),
              ("mmx",c_int64),
              ("xmm",c_int64),
              ("ymm",c_int64),
              ("zmm",c_int64),
              ("special",c_int64),
              ("cr",c_int64),
              ("dr",c_int64),
              ("mem_management",c_int64),
              ("mpx",c_int64),
              ("opmask",c_int64),
              ("segment",c_int64),
              ("fpu",c_int64),
              ("tmm",c_int64)]

class MEMORYTYPE(Structure):
   _pack_= 4
   _fields_= [("BaseRegister", c_int64),
              ("IndexRegister",c_int64),
              ("Scale",c_int32),
              ("Displacement",c_int64)]


class INSTRTYPE(Structure):
   _pack_= 1
   _fields_= [("Category", c_int32),
              ("Opcode", c_int32),
              ("Mnemonic", c_char * 24),
              ("BranchType", c_int32),
              ("Flags", EFLStruct),
              ("AddrValue", c_uint64),
              ("Immediat", c_int64),
              ("ImplicitModifiedRegs", REGISTERTYPE),
              ("ImplicitUsedRegs", REGISTERTYPE)]

class OPTYPE(Structure):
   _pack_= 1
   _fields_= [("OpMnemonic", c_char * 24),
              ("OpType", c_int64),
              ("OpSize", c_int32),
              ("OpPosition", c_int32),
              ("AccessMode", c_uint32),
              ("Memory", MEMORYTYPE),
              ("Registers", REGISTERTYPE),
              ("SegmentReg", c_uint32)]

class VEX_Struct(Structure):
   _pack_= 1
   _fields_= [("L",c_uint8),
              ("vvvv",c_uint8),
              ("mmmmm",c_uint8),
              ("pp",c_uint8),
              ("state",c_uint8),
              ("opcode",c_uint8)]

class EVEX_Struct(Structure):
   _pack_= 1
   _fields_= [("P0",c_uint8),
              ("P1",c_uint8),
              ("P2",c_uint8),
              ("mm",c_uint8),
              ("pp",c_uint8),
              ("R",c_uint8),
              ("X",c_uint8),
              ("B",c_uint8),
              ("R1",c_uint8),
              ("vvvv",c_uint8),
              ("V",c_uint8),
              ("aaa",c_uint8),
              ("W",c_uint8),
              ("z",c_uint8),
              ("b",c_uint8),
              ("LL",c_uint8),
              ("state",c_uint8),
              ("masking",c_uint8),
              ("tupletype",c_uint8)]

class InternalDatas(Structure):
    _pack_ = 1
    _fields_ = [("EIP_", c_void_p),
                ('EIP_VA', c_uint64),
                ('EIP_REAL', c_void_p),
                ('OriginalOperandSize', c_uint32),
                ('OperandSize', c_uint32),
                ('MemDecoration', c_uint32),
                ('AddressSize', c_uint32),
                ('MOD_', c_uint32),
                ('RM_', c_uint32),
                ('INDEX_', c_uint32),
                ('SCALE_', c_uint32),
                ('BASE_', c_uint32),
                ('REGOPCODE', c_uint32),
                ('DECALAGE_EIP', c_uint32),
                ('FORMATNUMBER', c_uint32),
                ('SYNTAX_', c_uint32),
                ('EndOfBlock', c_uint64),
                ('RelativeAddress', c_uint32),
                ('Architecture', c_uint32),
                ('ImmediatSize', c_uint32),
                ('NB_PREFIX', c_uint32),
                ('PrefRepe', c_uint32),
                ('PrefRepne', c_uint32),
                ('SEGMENTREGS', c_uint32),
                ('SEGMENTFS', c_uint32),
                ('third_arg', c_uint32),
                ('OPTIONS', c_uint64),
                ('ERROR_OPCODE', c_uint32),
                ('REX', REX_Struct),
                ('OutOfBlock', c_uint32),
                ('VEX', VEX_Struct),
                ('EVEX', EVEX_Struct),
                ('VSIB_', c_uint32),
                ('Register_', c_uint32),
                ]

class INSTRUCTION(Structure):
    _pack_= 1
    _fields_= [("offset", c_void_p),                # EIP
               ("VirtualAddr", c_uint64),
               ("SecurityBlock", c_uint32),
               ("repr", c_char * INSTRUCT_LENGTH),  # CompleteInstr
               ("Archi", c_uint32),
               ("Options", c_uint64),
               ("Instruction", INSTRTYPE),
               ("Operand1", OPTYPE),
               ("Operand2", OPTYPE),
               ("Operand3", OPTYPE),
               ("Operand4", OPTYPE),
               ("Operand5", OPTYPE),
               ("Operand6", OPTYPE),
               ("Operand7", OPTYPE),
               ("Operand8", OPTYPE),
               ("Operand9", OPTYPE),
               ("Prefix", PREFIXINFO),
               ("Error", c_int32),
               ("Reserved_", InternalDatas)]

# ======================= PREFIXES

NotUsedPrefix = 0
InUsePrefix = 1
SuperfluousPrefix = 2
InvalidPrefix = 4
MandatoryPrefix = 8

UNKNOWN_OPCODE = -1
OUT_OF_BLOCK = -2

# ======================= OPTIONS
NoTabulation = 0
Tabulation = 1
MasmSyntax = 0
GoAsmSyntax = 0x100
NasmSyntax = 0x200
ATSyntax = 0x400
IntrinsicMemSyntax= 0x800
PrefixedNumeral = 0x10000
SuffixedNumeral = 0x20000
ShowSegmentRegs = 0x01000000
ShowEVEXMasking = 0x02000000

LowPosition = 0
HighPosition = 1

# EVEX tupletypes

FULL = 1
HALF = 2
FULL_MEM =         3
TUPLE1_SCALAR__8 = 4
TUPLE1_SCALAR__16 =5
TUPLE1_SCALAR =    6
TUPLE1_FIXED__32 = 7
TUPLE1_FIXED__64 = 8
TUPLE2 =           9
TUPLE4 =           10
TUPLE8 =           11
HALF_MEM =         12
QUARTER_MEM =      13
EIGHTH_MEM =       14
MEM128   =         15
MOVDDUP =          16

# ======================= EFLAGS states

TE_ = 1
MO_ = 2
RE_ = 4
SE_ = 8
UN_ = 0x10
PR_ = 0x20

instrRflags = {
    TE_: "tested",
    MO_: "modified",
    RE_: "reset",
    SE_: "set",
    UN_: "undef",
    PR_: "prior state"
}

GENERAL_PURPOSE_INSTRUCTION   =     0x10000
FPU_INSTRUCTION               =     0x20000
MMX_INSTRUCTION               =     0x30000
SSE_INSTRUCTION               =     0x40000
SSE2_INSTRUCTION              =     0x50000
SSE3_INSTRUCTION              =     0x60000
SSSE3_INSTRUCTION             =     0x70000
SSE41_INSTRUCTION             =     0x80000
SSE42_INSTRUCTION             =     0x90000
SYSTEM_INSTRUCTION            =     0xa0000
VM_INSTRUCTION                =     0xb0000
UNDOCUMENTED_INSTRUCTION      =     0xc0000
AMD_INSTRUCTION               =     0xd0000
ILLEGAL_INSTRUCTION           =     0xe0000
AES_INSTRUCTION               =     0xf0000
CLMUL_INSTRUCTION             =    0x100000
AVX_INSTRUCTION               =    0x110000
AVX2_INSTRUCTION              =    0x120000
MPX_INSTRUCTION               =    0x130000
AVX512_INSTRUCTION            =    0x140000
SHA_INSTRUCTION               =    0x150000
BMI2_INSTRUCTION              =    0x160000
CET_INSTRUCTION               =    0x170000
BMI1_INSTRUCTION              =    0x180000
XSAVEOPT_INSTRUCTION          =    0x190000
FSGSBASE_INSTRUCTION          =    0x1a0000
CLWB_INSTRUCTION              =    0x1b0000
CLFLUSHOPT_INSTRUCTION        =    0x1c0000
FXSR_INSTRUCTION              =    0x1d0000
XSAVE_INSTRUCTION             =    0x1e0000
SGX_INSTRUCTION               =    0x1f0000
PCONFIG_INSTRUCTION           =    0x200000
UINTR_INSTRUCTION             =    0x210000
KL_INSTRUCTION                =    0x220000
AMX_INSTRUCTION               =    0x230000

instrCateg = {}
instrCateg[0] = ""
instrCateg[GENERAL_PURPOSE_INSTRUCTION]   = "GENERAL_PURPOSE_INSTRUCTION"
instrCateg[FPU_INSTRUCTION]               = "FPU_INSTRUCTION"
instrCateg[MMX_INSTRUCTION]               = "MMX_INSTRUCTION"
instrCateg[SSE_INSTRUCTION]               = "SSE_INSTRUCTION"
instrCateg[SSE2_INSTRUCTION]              = "SSE2_INSTRUCTION"
instrCateg[SSE3_INSTRUCTION]              = "SSE3_INSTRUCTION"
instrCateg[SSSE3_INSTRUCTION]             = "SSSE3_INSTRUCTION"
instrCateg[SSE41_INSTRUCTION]             = "SSE41_INSTRUCTION"
instrCateg[SSE42_INSTRUCTION]             = "SSE42_INSTRUCTION"
instrCateg[SYSTEM_INSTRUCTION]            = "SYSTEM_INSTRUCTION"
instrCateg[VM_INSTRUCTION]                = "VM_INSTRUCTION"
instrCateg[UNDOCUMENTED_INSTRUCTION]      = "UNDOCUMENTED_INSTRUCTION"
instrCateg[AMD_INSTRUCTION]               = "AMD_INSTRUCTION"
instrCateg[ILLEGAL_INSTRUCTION]           = "ILLEGAL_INSTRUCTION"
instrCateg[AES_INSTRUCTION]               = "AES_INSTRUCTION"
instrCateg[CLMUL_INSTRUCTION]             = "CLMUL_INSTRUCTION"
instrCateg[AVX_INSTRUCTION]               = "AVX_INSTRUCTION"
instrCateg[AVX2_INSTRUCTION]              = "AVX2_INSTRUCTION"
instrCateg[MPX_INSTRUCTION]               = "MPX_INSTRUCTION"
instrCateg[AVX512_INSTRUCTION]            = "AVX512_INSTRUCTION"
instrCateg[SHA_INSTRUCTION]               = "SHA_INSTRUCTION"
instrCateg[BMI2_INSTRUCTION]              = "BMI2_INSTRUCTION"
instrCateg[CET_INSTRUCTION]               = "CET_INSTRUCTION"
instrCateg[BMI1_INSTRUCTION]              = "BMI1_INSTRUCTION"
instrCateg[XSAVEOPT_INSTRUCTION]          = "XSAVEOPT_INSTRUCTION"
instrCateg[FSGSBASE_INSTRUCTION]          = "FSGSBASE_INSTRUCTION"
instrCateg[CLWB_INSTRUCTION]              = "CLWB_INSTRUCTION"
instrCateg[CLFLUSHOPT_INSTRUCTION]        = "CLFLUSHOPT_INSTRUCTION"
instrCateg[FXSR_INSTRUCTION]              = "FXSR_INSTRUCTION"
instrCateg[XSAVE_INSTRUCTION]             = "XSAVE_INSTRUCTION"
instrCateg[SGX_INSTRUCTION]               = "SGX_INSTRUCTION"
instrCateg[KL_INSTRUCTION]                = "KL_INSTRUCTION"
instrCateg[UINTR_INSTRUCTION]             = "UINTR_INSTRUCTION"
instrCateg[AMX_INSTRUCTION]               = "AMX_INSTRUCTION"
instrCateg[PCONFIG_INSTRUCTION]           = "PCONFIG_INSTRUCTION"

DATA_TRANSFER = 0x1
ARITHMETIC_INSTRUCTION = 2
LOGICAL_INSTRUCTION = 3
SHIFT_ROTATE = 4
BIT_BYTE = 5
CONTROL_TRANSFER = 6
STRING_INSTRUCTION = 7
InOutINSTRUCTION = 8
ENTER_LEAVE_INSTRUCTION = 9
FLAG_CONTROL_INSTRUCTION = 10
SEGMENT_REGISTER = 11
MISCELLANEOUS_INSTRUCTION = 12
COMPARISON_INSTRUCTION = 13
LOGARITHMIC_INSTRUCTION = 14
TRIGONOMETRIC_INSTRUCTION = 15
UNSUPPORTED_INSTRUCTION = 16
LOAD_CONSTANTS = 17
FPUCONTROL = 18
STATE_MANAGEMENT = 19
CONVERSION_INSTRUCTION = 20
SHUFFLE_UNPACK = 21
PACKED_SINGLE_PRECISION = 22
SIMD128bits = 23
SIMD64bits = 24
CACHEABILITY_CONTROL = 25
FP_INTEGER_CONVERSION = 26
SPECIALIZED_128bits = 27
SIMD_FP_PACKED = 28
SIMD_FP_HORIZONTAL = 29
AGENT_SYNCHRONISATION = 30
PACKED_ALIGN_RIGHT = 31
PACKED_SIGN = 32
PACKED_BLENDING_INSTRUCTION = 33
PACKED_TEST = 34
PACKED_MINMAX = 35
HORIZONTAL_SEARCH = 36
PACKED_EQUALITY = 37
STREAMING_LOAD = 38
INSERTION_EXTRACTION = 39
DOT_PRODUCT = 40
SAD_INSTRUCTION = 41
ACCELERATOR_INSTRUCTION = 42
ROUND_INSTRUCTION = 43

JO = 1
JC = 2
JE = 3
JA = 4
JS = 5
JP = 6
JL = 7
JG = 8
JB = 2
JECXZ = 10
JmpType = 11
CallType = 12
RetType = 13
JNO = -1
JNC = -2
JNE = -3
JNA = -4
JNS = -5
JNP = -6
JNL = -7
JNG = -8
JNB = -2

NO_ARGUMENT = 0x10000
REGISTER_TYPE = 0x20000
MEMORY_TYPE = 0x30000
CONSTANT_TYPE = 0x40000

GENERAL_REG = 0x1
MMX_REG = 0x2
SSE_REG = 0x4
AVX_REG = 0x8
AVX512_REG = 0x10
SPECIAL_REG = 0x20
CR_REG = 0x40
DR_REG = 0x80
MEMORY_MANAGEMENT_REG = 0x100
MPX_REG = 0x200
OPMASK_REG = 0x400
SEGMENT_REG = 0x800
FPU_REG = 0x1000
TMM_REG = 0x2000

instrRegisters = {
    GENERAL_REG: 'gpr',
    MMX_REG: 'mmx',
    SSE_REG: 'xmm',
    AVX_REG: 'ymm',
    AVX512_REG: 'zmm',
    SPECIAL_REG: 'special',
    CR_REG: 'cr',
    DR_REG: 'dr',
    MEMORY_MANAGEMENT_REG: 'mem_management',
    MPX_REG: 'mpx',
    OPMASK_REG: 'opmask',
    SEGMENT_REG: 'segment',
    FPU_REG: 'fpu',
    TMM_REG: 'tmm'
}

RELATIVE_ = 0x4000000
ABSOLUTE_ = 0x8000000

instr_Types = {
    NO_ARGUMENT: 'no argument',
    REGISTER_TYPE: 'register',
    MEMORY_TYPE: 'memory',
    CONSTANT_TYPE+ABSOLUTE_: 'constant',
    CONSTANT_TYPE+RELATIVE_: 'constant+relative',
}

READ = 0x1
WRITE = 0x2

REG0 = 0x1
REG1 = 0x2
REG2 = 0x4
REG3 = 0x8
REG4 = 0x10
REG5 = 0x20
REG6 = 0x40
REG7 = 0x80
REG8 = 0x100
REG9 = 0x200
REG10 = 0x400
REG11 = 0x800
REG12 = 0x1000
REG13 = 0x2000
REG14 = 0x4000
REG15 = 0x8000
REG16 = 0x10000
REG17 = 0x20000
REG18 = 0x40000
REG19 = 0x80000
REG20 = 0x100000
REG21 = 0x200000
REG22 = 0x400000
REG23 = 0x800000
REG24 = 0x1000000
REG25 = 0x2000000
REG26 = 0x4000000
REG27 = 0x8000000
REG28 = 0x10000000
REG29 = 0x20000000
REG30 = 0x40000000
REG31 = 0x80000000

# Exceptions codes
UD_ = 2

NoTabulation      = 0x00000000
Tabulation        = 0x00000001

MasmSyntax        = 0x00000000
GoAsmSyntax       = 0x00000100
NasmSyntax        = 0x00000200
ATSyntax          = 0x00000400

PrefixedNumeral   = 0x00010000
SuffixedNumeral   = 0x00000000

ShowSegmentRegs   = 0x01000000

MAX_OPERANDS = 9

REGSTYPE = {
    # es ds fs gs cs ss                                   Registers.segment
    'es': {'type': 'segment','reg': REG0,'size': 16},
    'ds': {'type': 'segment','reg': REG1,'size': 16},
    'fs': {'type': 'segment','reg': REG2,'size': 16},
    'gs': {'type': 'segment','reg': REG3,'size': 16},
    'cs': {'type': 'segment','reg': REG4,'size': 16},
    'ss': {'type': 'segment','reg': REG5,'size': 16},
    'seg': {'type': 'segment','reg': REG0 | REG1 | REG2 | REG3 | REG4 | \
        REG5,'size': 16},

    # bnd0-bnd3                                           Registers.mpx
    'bnd0': {'type': 'mpx','reg': REG0,'size': 128},
    'bnd1': {'type': 'mpx','reg': REG1,'size': 128},
    'bnd2': {'type': 'mpx','reg': REG2,'size': 128},
    'bnd3': {'type': 'mpx','reg': REG3,'size': 128},
    'bnd': {'type': 'mpx','reg': REG0 | REG1 | REG2 | REG3,'size': 128},

    # st0-st7                                             Registers.fpu
    'st0': {'type': 'fpu','reg': REG0,'size': 80},
    'st1': {'type': 'fpu','reg': REG1,'size': 80},
    'st2': {'type': 'fpu','reg': REG2,'size': 80},
    'st3': {'type': 'fpu','reg': REG3,'size': 80},
    'st4': {'type': 'fpu','reg': REG4,'size': 80},
    'st5': {'type': 'fpu','reg': REG5,'size': 80},
    'st6': {'type': 'fpu','reg': REG6,'size': 80},
    'st7': {'type': 'fpu','reg': REG7,'size': 80},
    'fpu': {'type': 'fpu','reg': REG0 | REG1 | REG2 | \
        REG3 | REG4 | REG5 | REG6 | REG7,'size': 80},

    # dr0-dr15                                            Registers.dr
    'dr0': {'type': 'dr','reg': REG0,'size': 32},
    'dr1': {'type': 'dr','reg': REG1,'size': 32},
    'dr2': {'type': 'dr','reg': REG2,'size': 32},
    'dr3': {'type': 'dr','reg': REG3,'size': 32},
    'dr4': {'type': 'dr','reg': REG4,'size': 32},
    'dr5': {'type': 'dr','reg': REG5,'size': 32},
    'dr6': {'type': 'dr','reg': REG6,'size': 32},
    'dr7': {'type': 'dr','reg': REG7,'size': 32},
    'dr8': {'type': 'dr','reg': REG8,'size': 32},
    'dr9': {'type': 'dr','reg': REG9,'size': 32},
    'dr10': {'type': 'dr','reg': REG10,'size': 32},
    'dr11': {'type': 'dr','reg': REG11,'size': 32},
    'dr12': {'type': 'dr','reg': REG12,'size': 32},
    'dr13': {'type': 'dr','reg': REG13,'size': 32},
    'dr14': {'type': 'dr','reg': REG14,'size': 32},
    'dr15': {'type': 'dr','reg': REG15,'size': 32},
    'dr': {'type': 'dr','reg': REG0 | REG1 | REG2 | REG3 | REG4 | REG5 |    \
        REG6 | REG7 | REG8 | REG9 | REG10 | REG11 | REG12 | REG13 | REG14 | \
        REG15,'size': 32},

    # cr0-cr15                                            Registers.cr
    'cr0': {'type': 'cr','reg': REG0,'size': 32},
    'cr1': {'type': 'cr','reg': REG1,'size': 32},
    'cr2': {'type': 'cr','reg': REG2,'size': 32},
    'cr3': {'type': 'cr','reg': REG3,'size': 32},
    'cr4': {'type': 'cr','reg': REG4,'size': 32},
    'cr5': {'type': 'cr','reg': REG5,'size': 32},
    'cr6': {'type': 'cr','reg': REG6,'size': 32},
    'cr7': {'type': 'cr','reg': REG7,'size': 32},
    'cr8': {'type': 'cr','reg': REG8,'size': 32},
    'cr9': {'type': 'cr','reg': REG9,'size': 32},
    'cr10': {'type': 'cr','reg': REG10,'size': 32},
    'cr11': {'type': 'cr','reg': REG11,'size': 32},
    'cr12': {'type': 'cr','reg': REG12,'size': 32},
    'cr13': {'type': 'cr','reg': REG13,'size': 32},
    'cr14': {'type': 'cr','reg': REG14,'size': 32},
    'cr15': {'type': 'cr','reg': REG15,'size': 32},
    'cr': {'type': 'dr','reg': REG0 | REG1 | REG2 | REG3 | REG4 | REG5 |    \
        REG6 | REG7 | REG8 | REG9 | REG10 | REG11 | REG12 | REG13 | REG14 | \
        REG15,'size': 32},

    # rax rcx rdx rbx rsp rbp rsi rdi r8-r15              Registers.gpr
    'gpr': {'type': 'gpr','reg': REG0 | REG1 | REG2 | REG3 | REG4 | REG5 |  \
        REG6 | REG7 | REG8 | REG9 | REG10 | REG11 | REG12 | REG13 | REG14 | \
        REG15,'size': 64},
    'rax': {'type': 'gpr','reg': REG0,'size': 64},
    'rcx': {'type': 'gpr','reg': REG1,'size': 64},
    'rdx': {'type': 'gpr','reg': REG2,'size': 64},
    'rbx': {'type': 'gpr','reg': REG3,'size': 64},
    'rsp': {'type': 'gpr','reg': REG4,'size': 64},
    'rbp': {'type': 'gpr','reg': REG5,'size': 64},
    'rsi': {'type': 'gpr','reg': REG6,'size': 64},
    'rdi': {'type': 'gpr','reg': REG7,'size': 64},
    'r8': {'type': 'gpr','reg': REG8,'size': 64},
    'r9': {'type': 'gpr','reg': REG9,'size': 64},
    'r10': {'type': 'gpr','reg': REG10,'size': 64},
    'r11': {'type': 'gpr','reg': REG11,'size': 64},
    'r12': {'type': 'gpr','reg': REG12,'size': 64},
    'r13': {'type': 'gpr','reg': REG13,'size': 64},
    'r14': {'type': 'gpr','reg': REG14,'size': 64},
    'r15': {'type': 'gpr','reg': REG15,'size': 64},

    # eax ecx edx ebx esp ebp esi edi r8d-r15d            Registers.gpr
    'eax': {'type': 'gpr','reg': REG0,'size': 32},
    'ecx': {'type': 'gpr','reg': REG1,'size': 32},
    'edx': {'type': 'gpr','reg': REG2,'size': 32},
    'ebx': {'type': 'gpr','reg': REG3,'size': 32},
    'esp': {'type': 'gpr','reg': REG4,'size': 32},
    'ebp': {'type': 'gpr','reg': REG5,'size': 32},
    'esi': {'type': 'gpr','reg': REG6,'size': 32},
    'edi': {'type': 'gpr','reg': REG7,'size': 32},
    'r8d': {'type': 'gpr','reg': REG8,'size': 32},
    'r9d': {'type': 'gpr','reg': REG9,'size': 32},
    'r10d': {'type': 'gpr','reg': REG10,'size': 32},
    'r11d': {'type': 'gpr','reg': REG11,'size': 32},
    'r12d': {'type': 'gpr','reg': REG12,'size': 32},
    'r13d': {'type': 'gpr','reg': REG13,'size': 32},
    'r14d': {'type': 'gpr','reg': REG14,'size': 32},
    'r15d': {'type': 'gpr','reg': REG15,'size': 32},

    # ax cx dx bx sp bp si di r8w-r15w                    Registers.gpr
    'ax': {'type': 'gpr','reg': REG0,'size': 16},
    'cx': {'type': 'gpr','reg': REG1,'size': 16},
    'dx': {'type': 'gpr','reg': REG2,'size': 16},
    'bx': {'type': 'gpr','reg': REG3,'size': 16},
    'sp': {'type': 'gpr','reg': REG4,'size': 16},
    'bp': {'type': 'gpr','reg': REG5,'size': 16},
    'si': {'type': 'gpr','reg': REG6,'size': 16},
    'di': {'type': 'gpr','reg': REG7,'size': 16},
    'r8w': {'type': 'gpr','reg': REG8,'size': 16},
    'r9w': {'type': 'gpr','reg': REG9,'size': 16},
    'r10w': {'type': 'gpr','reg': REG10,'size': 16},
    'r11w': {'type': 'gpr','reg': REG11,'size': 16},
    'r12w': {'type': 'gpr','reg': REG12,'size': 16},
    'r13w': {'type': 'gpr','reg': REG13,'size': 16},
    'r14w': {'type': 'gpr','reg': REG14,'size': 16},
    'r15w': {'type': 'gpr','reg': REG15,'size': 16},

    # al cl dl bl ah ch dh bh spl bpl sil dil r8L-r15L    Registers.gpr
    'al': {'type': 'gpr','reg': REG0,'size': 8},
    'cl': {'type': 'gpr','reg': REG1,'size': 8},
    'dl': {'type': 'gpr','reg': REG2,'size': 8},
    'bl': {'type': 'gpr','reg': REG3,'size': 8},
    'ah': {'type': 'gpr','reg': REG0,'size': 8},
    'ch': {'type': 'gpr','reg': REG1,'size': 8},
    'dh': {'type': 'gpr','reg': REG2,'size': 8},
    'bh': {'type': 'gpr','reg': REG3,'size': 8},
    'spl': {'type': 'gpr','reg': REG4,'size': 8},
    'bpl': {'type': 'gpr','reg': REG5,'size': 8},
    'sil': {'type': 'gpr','reg': REG6,'size': 8},
    'dil': {'type': 'gpr','reg': REG7,'size': 8},
    'r8l': {'type': 'gpr','reg': REG8,'size': 8},
    'r9l': {'type': 'gpr','reg': REG9,'size': 8},
    'r10l': {'type': 'gpr','reg': REG10,'size': 8},
    'r11l': {'type': 'gpr','reg': REG11,'size': 8},
    'r12l': {'type': 'gpr','reg': REG12,'size': 8},
    'r13l': {'type': 'gpr','reg': REG13,'size': 8},
    'r14l': {'type': 'gpr','reg': REG14,'size': 8},
    'r15l': {'type': 'gpr','reg': REG12,'size': 8},

    # mm0-mm7                                             Registers.mmx
    'mm0': {'type': 'mmx','reg': REG0,'size': 64},
    'mm1': {'type': 'mmx','reg': REG1,'size': 64},
    'mm2': {'type': 'mmx','reg': REG2,'size': 64},
    'mm3': {'type': 'mmx','reg': REG3,'size': 64},
    'mm4': {'type': 'mmx','reg': REG4,'size': 64},
    'mm5': {'type': 'mmx','reg': REG5,'size': 64},
    'mm6': {'type': 'mmx','reg': REG6,'size': 64},
    'mm7': {'type': 'mmx','reg': REG7,'size': 64},
    'mmx': {'type': 'mmx','reg': REG0 | REG1 | REG2 | REG3 | REG4 | REG5 |  \
        REG6 | REG7,'size': 64},

    # xmm0-xmm31                                          Registers.xmm
    'xmm0': {'type': 'xmm','reg': REG0,'size': 128},
    'xmm1': {'type': 'xmm','reg': REG1,'size': 128},
    'xmm2': {'type': 'xmm','reg': REG2,'size': 128},
    'xmm3': {'type': 'xmm','reg': REG3,'size': 128},
    'xmm4': {'type': 'xmm','reg': REG4,'size': 128},
    'xmm5': {'type': 'xmm','reg': REG5,'size': 128},
    'xmm6': {'type': 'xmm','reg': REG6,'size': 128},
    'xmm7': {'type': 'xmm','reg': REG7,'size': 128},
    'xmm8': {'type': 'xmm','reg': REG8,'size': 128},
    'xmm9': {'type': 'xmm','reg': REG9,'size': 128},
    'xmm10': {'type': 'xmm','reg': REG10,'size': 128},
    'xmm11': {'type': 'xmm','reg': REG11,'size': 128},
    'xmm12': {'type': 'xmm','reg': REG12,'size': 128},
    'xmm13': {'type': 'xmm','reg': REG13,'size': 128},
    'xmm14': {'type': 'xmm','reg': REG14,'size': 128},
    'xmm15': {'type': 'xmm','reg': REG15,'size': 128},
    'xmm16': {'type': 'xmm','reg': REG16,'size': 128},
    'xmm17': {'type': 'xmm','reg': REG17,'size': 128},
    'xmm18': {'type': 'xmm','reg': REG18,'size': 128},
    'xmm19': {'type': 'xmm','reg': REG19,'size': 128},
    'xmm20': {'type': 'xmm','reg': REG20,'size': 128},
    'xmm21': {'type': 'xmm','reg': REG21,'size': 128},
    'xmm22': {'type': 'xmm','reg': REG22,'size': 128},
    'xmm23': {'type': 'xmm','reg': REG23,'size': 128},
    'xmm24': {'type': 'xmm','reg': REG24,'size': 128},
    'xmm25': {'type': 'xmm','reg': REG25,'size': 128},
    'xmm26': {'type': 'xmm','reg': REG26,'size': 128},
    'xmm27': {'type': 'xmm','reg': REG27,'size': 128},
    'xmm28': {'type': 'xmm','reg': REG28,'size': 128},
    'xmm29': {'type': 'xmm','reg': REG29,'size': 128},
    'xmm30': {'type': 'xmm','reg': REG30,'size': 128},
    'xmm31': {'type': 'xmm','reg': REG31,'size': 128},
    'xmm': {'type': 'xmm','reg': REG0 | REG1 | REG2 | REG3 | REG4 | REG5 |  \
        REG6 | REG7 | REG8 | REG9 | REG10 | REG11 | REG12 | REG13 | REG14 | \
        REG15 | REG16 | REG17 | REG18 | REG19 | REG20 | REG21 | REG22 |     \
        REG23 | REG24 | REG25 | REG26 | REG27 | REG28 | REG29 | REG30 |     \
        REG31,'size': 128},

    # ymm0-ymm31                                          Registers.ymm
    'ymm0': {'type': 'ymm','reg': REG0,'size': 256},
    'ymm1': {'type': 'ymm','reg': REG1,'size': 256},
    'ymm2': {'type': 'ymm','reg': REG2,'size': 256},
    'ymm3': {'type': 'ymm','reg': REG3,'size': 256},
    'ymm4': {'type': 'ymm','reg': REG4,'size': 256},
    'ymm5': {'type': 'ymm','reg': REG5,'size': 256},
    'ymm6': {'type': 'ymm','reg': REG6,'size': 256},
    'ymm7': {'type': 'ymm','reg': REG7,'size': 256},
    'ymm8': {'type': 'ymm','reg': REG8,'size': 256},
    'ymm9': {'type': 'ymm','reg': REG9,'size': 256},
    'ymm10': {'type': 'ymm','reg': REG10,'size': 256},
    'ymm11': {'type': 'ymm','reg': REG11,'size': 256},
    'ymm12': {'type': 'ymm','reg': REG12,'size': 256},
    'ymm13': {'type': 'ymm','reg': REG13,'size': 256},
    'ymm14': {'type': 'ymm','reg': REG14,'size': 256},
    'ymm15': {'type': 'ymm','reg': REG15,'size': 256},
    'ymm16': {'type': 'ymm','reg': REG16,'size': 256},
    'ymm17': {'type': 'ymm','reg': REG17,'size': 256},
    'ymm18': {'type': 'ymm','reg': REG18,'size': 256},
    'ymm19': {'type': 'ymm','reg': REG19,'size': 256},
    'ymm20': {'type': 'ymm','reg': REG20,'size': 256},
    'ymm21': {'type': 'ymm','reg': REG21,'size': 256},
    'ymm22': {'type': 'ymm','reg': REG22,'size': 256},
    'ymm23': {'type': 'ymm','reg': REG23,'size': 256},
    'ymm24': {'type': 'ymm','reg': REG24,'size': 256},
    'ymm25': {'type': 'ymm','reg': REG25,'size': 256},
    'ymm26': {'type': 'ymm','reg': REG26,'size': 256},
    'ymm27': {'type': 'ymm','reg': REG27,'size': 256},
    'ymm28': {'type': 'ymm','reg': REG28,'size': 256},
    'ymm29': {'type': 'ymm','reg': REG29,'size': 256},
    'ymm30': {'type': 'ymm','reg': REG30,'size': 256},
    'ymm31': {'type': 'ymm','reg': REG31,'size': 256},
    'ymm': {'type': 'ymm','reg': REG0 | REG1 | REG2 | REG3 | REG4 | REG5 |  \
        REG6 | REG7 | REG8 | REG9 | REG10 | REG11 | REG12 | REG13 | REG14 | \
        REG15 | REG16 | REG17 | REG18 | REG19 | REG20 | REG21 | REG22 |     \
        REG23 | REG24 | REG25 | REG26 | REG27 | REG28 | REG29 | REG30 |     \
        REG31,'size': 256},
    # zmm0-zmm31                                          Registers.zmm
    'zmm0': {'type': 'zmm','reg': REG0,'size': 512},
    'zmm1': {'type': 'zmm','reg': REG1,'size': 512},
    'zmm2': {'type': 'zmm','reg': REG2,'size': 512},
    'zmm3': {'type': 'zmm','reg': REG3,'size': 512},
    'zmm4': {'type': 'zmm','reg': REG4,'size': 512},
    'zmm5': {'type': 'zmm','reg': REG5,'size': 512},
    'zmm6': {'type': 'zmm','reg': REG6,'size': 512},
    'zmm7': {'type': 'zmm','reg': REG7,'size': 512},
    'zmm8': {'type': 'zmm','reg': REG8,'size': 512},
    'zmm9': {'type': 'zmm','reg': REG9,'size': 512},
    'zmm10': {'type': 'zmm','reg': REG10,'size': 512},
    'zmm11': {'type': 'zmm','reg': REG11,'size': 512},
    'zmm12': {'type': 'zmm','reg': REG12,'size': 512},
    'zmm13': {'type': 'zmm','reg': REG13,'size': 512},
    'zmm14': {'type': 'zmm','reg': REG14,'size': 512},
    'zmm15': {'type': 'zmm','reg': REG15,'size': 512},
    'zmm16': {'type': 'zmm','reg': REG16,'size': 512},
    'zmm17': {'type': 'zmm','reg': REG17,'size': 512},
    'zmm18': {'type': 'zmm','reg': REG18,'size': 512},
    'zmm19': {'type': 'zmm','reg': REG19,'size': 512},
    'zmm20': {'type': 'zmm','reg': REG20,'size': 512},
    'zmm21': {'type': 'zmm','reg': REG21,'size': 512},
    'zmm22': {'type': 'zmm','reg': REG22,'size': 512},
    'zmm23': {'type': 'zmm','reg': REG23,'size': 512},
    'zmm24': {'type': 'zmm','reg': REG24,'size': 512},
    'zmm25': {'type': 'zmm','reg': REG25,'size': 512},
    'zmm26': {'type': 'zmm','reg': REG26,'size': 512},
    'zmm27': {'type': 'zmm','reg': REG27,'size': 512},
    'zmm28': {'type': 'zmm','reg': REG28,'size': 512},
    'zmm29': {'type': 'zmm','reg': REG29,'size': 512},
    'zmm30': {'type': 'zmm','reg': REG30,'size': 512},
    'zmm31': {'type': 'zmm','reg': REG31,'size': 512},
    'zmm': {'type': 'zmm','reg': REG0 | REG1 | REG2 | REG3 | REG4 | REG5 |  \
        REG6 | REG7 | REG8 | REG9 | REG10 | REG11 | REG12 | REG13 | REG14 | \
        REG15 | REG16 | REG17 | REG18 | REG19 | REG20 | REG21 | REG22 |     \
        REG23 | REG24 | REG25 | REG26 | REG27 | REG28 | REG29 | REG30 |     \
        REG31,'size': 512},
    # k0-k7                                               Registers.opmask
    'k0': {'type': 'opmask','reg': REG0,'size': 16},
    'k1': {'type': 'opmask','reg': REG1,'size': 16},
    'k2': {'type': 'opmask','reg': REG2,'size': 16},
    'k3': {'type': 'opmask','reg': REG3,'size': 16},
    'k4': {'type': 'opmask','reg': REG4,'size': 16},
    'k5': {'type': 'opmask','reg': REG5,'size': 16},
    'k6': {'type': 'opmask','reg': REG6,'size': 16},
    'k7': {'type': 'opmask','reg': REG7,'size': 16},
    'opmask': {'type': 'opmask','reg': REG0 | REG1 | REG2 | REG3 | REG4 | \
        REG5 |  REG6 | REG7,'size': 16},
    # tmm0-tmm7                                          Registers.tmm
    'tmm0': {'type': 'tmm','reg': REG0,'size': 8192},
    'tmm1': {'type': 'tmm','reg': REG1,'size': 8192},
    'tmm2': {'type': 'tmm','reg': REG2,'size': 8192},
    'tmm3': {'type': 'tmm','reg': REG3,'size': 8192},
    'tmm4': {'type': 'tmm','reg': REG4,'size': 8192},
    'tmm5': {'type': 'tmm','reg': REG5,'size': 8192},
    'tmm6': {'type': 'tmm','reg': REG6,'size': 8192},
    'tmm7': {'type': 'tmm','reg': REG7,'size': 8192},
    'tmm': {'type': 'tmm','reg': REG0 | REG1 | REG2 | REG3 | REG4 | REG5 |  \
        REG6 | REG7,'size': 8192},
    # EFLAGS  MXCSR  SSP  PKRU                            Registers.special
    'rflags': {'type': 'special','reg': REG0,'size': 64},
    'eflags': {'type': 'special','reg': REG0,'size': 32},
    'mxcsr': {'type': 'special','reg': REG1,'size': 32},
    'ssp': {'type': 'special','reg': REG2,'size': 64},
    'pkru': {'type': 'special','reg': REG3,'size': 32},
    'uif': {'type': 'special','reg': REG4,'size': 1},
    'ia32_time_stamp_counter': {'type': 'special','reg': REG5,'size': 64},
    'ia32_tsc_aux': {'type': 'special','reg': REG6,'size': 64},

    # GDTR LDTR IDTR TR                                   Registers.mem_management
    'gdtr': {'type': 'mem_management','reg': REG0,'size': 48},
    'ldtr': {'type': 'mem_management','reg': REG0,'size': 16},
    'idtr': {'type': 'mem_management','reg': REG1,'size': 64},
    'tr': {'type': 'mem_management','reg': REG2,'size': 16},

}

# ====================================== Import Disasm function
import os

if os.name == 'nt':
  __module = WinDLL('BeaEngine')
elif os.name == 'posix':
  linuxso = os.path.abspath(os.path.join(os.path.dirname(__file__), 'libBeaEngine.so'))
  __module = CDLL(linuxso)

BeaEngineVersion = __module.BeaEngineVersion
BeaEngineRevision = __module.BeaEngineRevision
BeaEngineVersion.restype = c_char_p
BeaEngineRevision.restype = c_char_p
BeaDisasm = __module.Disasm

#
# BeaEngine helpers
#

class EVEX:
    def __init__(self, params = ""):
        self.reset()
        # NDS = Non destructive source
        # NDD = Non destructive destination
        # DDS = Destructive Destination and source
        if re.match(r"(.*)\.(NDS|NDD|DDS)\.(.*)", params):
            self.vvvv = 0b0

        if re.match(r"(.*)\.512\.(.*)", params):
            self.LL = 0b10
        elif re.match(r"(.*)\.256\.(.*)", params):
            self.LL = 0b1

        if re.match(r"(.*)\.66\.(.*)", params):
            self.pp = 0b1
        elif re.match(r"(.*)\.F3\.(.*)", params):
            self.pp = 0b10
        elif re.match(r"(.*)\.F2\.(.*)", params):
            self.pp = 0b11

        if re.match(r"(.*)\.0F\.(.*)", params):
            self.mm = 0b1
        elif re.match(r"(.*)\.0F38\.(.*)", params):
            self.mm = 0b10
        elif re.match(r"(.*)\.0F3A\.(.*)", params):
            self.mm = 0b11

        if re.match(r"(.*)\.W1(.*)", params):
            self.W = 0b1

    def reset(self):
        self.mm = 0
        self.pp = 0
        self.R = 0
        self.B = 0
        self.Rprime = 0
        self.X = 0
        self.vvvv = 0b1111  # default value to tell it is unused
        self.V = 0
        self.aaa = 0
        self.W = 0
        self.z = 0
        self.b = 0
        self.LL = 0

    def prefix(self):
        return '62{:02x}{:02x}{:02x}'.format(self.p0(),self.p1(),self.p2())

    def p0(self):
        return self.mm + (self.Rprime << 4) + (self.B << 5) + (self.X << 6)+ (self.R << 7)

    def p1(self):
        return self.pp + 0b100 + (self.vvvv << 3) + (self.W << 7)

    def p2(self):
        return self.aaa + (self.V << 3) + (self.b << 4) + (self.LL << 5) + (self.z << 7)

class VEX:
    def __init__(self, params = ""):
        self.reset()
        # NDS = Non destructive source
        # NDD = Non destructive destination
        # DDS = Destructive Destination and source
        if re.match(r"(.*)\.(NDS|NDD|DDS)\.(.*)", params):
            self.vvvv = 0b0

        if re.match(r"(.*)\.256\.(.*)", params):
            self.L = 0b1

        if re.match(r"(.*)\.66\.(.*)", params):
            self.pp = 0b1
        elif re.match(r"(.*)\.F3\.(.*)", params):
            self.pp = 0b10
        elif re.match(r"(.*)\.F2\.(.*)", params):
            self.pp = 0b11

        if re.match(r"(.*)\.0F38\.(.*)", params):
            self.mmmm = 0b10
        elif re.match(r"(.*)\.0F3A\.(.*)", params):
            self.mmmm = 0b11
        elif re.match(r"(.*)\.(0F\.(.*)|0F)", params):
            self.mmmm = 0b1

        if re.match(r"(.*)\.W1(.*)", params):
            self.W = 0b1

        if re.match(r"(.*)\.L1(.*)", params):
            self.L = 0b1

    def reset(self):
        self.L = 0
        self.pp = 0
        self.mmmm = 0
        self.W = 0
        self.vvvv = 0b1111
        self.R = 0
        self.X = 0
        self.B = 0

    def c4(self):
        return 'c4{:02x}{:02x}'.format(self.byte1(), self.byte2())

    def c5(self):
        return 'c5{:02x}'.format(self.byte3())

    def byte1(self):
        return self.mmmm + (self.B << 5) + (self.X << 6) + (self.R << 7)

    def byte2(self):
        return self.pp + (self.L << 2) + (self.vvvv << 3) + (self.W << 7)

    def byte3(self):
        return self.pp + (self.L << 2) + (self.vvvv << 3) + (self.R << 7)

class REX:
    def __init__(self):
        self.reset()

    def reset(self):
        self.W = 0
        self.R = 0
        self.X = 0
        self.B = 0

    def byte(self):
        return self.B + (self.X << 1) + (self.R << 2) + (self.W << 3) + 0b01000000


#
# BeaEngine Wrapper
# to hide ctypes complexity
#
class Disasm():
    def __init__(self, buffer, offset=0, virtualAddr=0):
        """
        Initialize Disasm object
        Example :
            # instantiate BeaEngine on a buffer
            disasm = Disasm(b'\x90\x90\x6a\x00\xe8\xa5\xc7\x02\x00')
        """
        self.buffer = buffer
        self.target = create_string_buffer(buffer,len(buffer))
        self.infos = INSTRUCTION()
        #self.infos.Options = PrefixedNumeral
        self.infos.offset = addressof(self.target) + offset
        self.end_block = self.infos.offset + len(buffer)
        self.infos.VirtualAddr = virtualAddr
        self.infos.Archi = 64
        self.length = 0
        self.bytes = bytearray()

    def register_repr(self, registers):
        regs = []
        for i in range(0,32):
            if registers & (1 << i):
                regs.append(i)
        return "+".join(f'REG{b}' for b in regs)

    def merge_registers(self, dest, source):

        for entry in source._fields_:
            value = getattr(dest, entry[0]) | getattr(source, entry[0])
            setattr(dest, entry[0], value)

    def get_modified_regs(self):
        regs = REGISTERTYPE()
        result = {}
        for i in range(1,MAX_OPERANDS + 1):
            operand = getattr(self.infos, f'Operand{i}')
            if operand.OpType == REGISTER_TYPE and operand.AccessMode & WRITE:
                self.merge_registers(regs, operand.Registers)
        self.merge_registers(regs, self.infos.Instruction.ImplicitModifiedRegs)
        for entry in regs._fields_:
            if entry[0] != 'type':
                result[entry[0]] = self.register_repr(getattr(regs, entry[0]))
            else:
                result[entry[0]] = getattr(regs, entry[0])
        return result

    def get_read_regs(self):
        regs = REGISTERTYPE()
        result = {}
        for i in range(1,MAX_OPERANDS + 1):
            operand = getattr(self.infos, f'Operand{i}')
            if operand.OpType == REGISTER_TYPE and operand.AccessMode & READ:
                self.merge_registers(regs, operand.Registers)
            elif operand.OpType == MEMORY_TYPE:
                regs.type |= GENERAL_REG
                regs.gpr |= operand.Memory.BaseRegister
                if self.infos.Reserved_.VSIB_ == SSE_REG:
                    regs.type |= SSE_REG
                    regs.xmm |= operand.Memory.IndexRegister
                elif self.infos.Reserved_.VSIB_ == AVX_REG:
                    regs.type |= AVX_REG
                    regs.ymm |= operand.Memory.IndexRegister
                elif self.infos.Reserved_.VSIB_ == AVX512_REG:
                    regs.type |= AVX512_REG
                    regs.zmm |= operand.Memory.IndexRegister
                else:
                    regs.gpr |= operand.Memory.IndexRegister

                if operand.SegmentReg != 0:
                    regs.type |= SEGMENT_REG
                    regs.segment |= operand.SegmentReg
        self.merge_registers(regs, self.infos.Instruction.ImplicitUsedRegs)
        for entry in regs._fields_:
            if entry[0] != 'type':
                result[entry[0]] = self.register_repr(getattr(regs, entry[0]))
            else:
                result[entry[0]] = getattr(regs, entry[0])

        return result

    def json(self):
        """
        json dump of instruction structure
        Example:
            instr = Disasm(bytes.fromhex('0f2e20'))
            instr.read()
            print(instr.json())
        """
        instr_struct = self.structure()
        return json.dumps(instr_struct, indent=4)

    def structure(self):
        """
            Dictionary to extract
            used registers, modified registers, errors...
        """
        instr = {}
        instr['repr'] = self.repr()
        instr['category'] = instrCateg[self.infos.Instruction.Category & 0x0FFFF0000]
        instr['mnemonic'] = self.infos.Instruction.Mnemonic.decode()
        instr['bytes'] = " ".join("{:02x}".format(b if type(b) == int else ord(b)) for b in self.bytes)
        instr['error'] = self.infos.Error
        instr['arch'] = self.infos.Archi
        instr['operands'] = {}
        instr['registers'] = {
            'modified': self.get_modified_regs(),
            'read': self.get_read_regs()
        }
        #instr['opcode'] = hex(self.infos.Instruction.Opcode)
        rflags = self.infos.Instruction.Flags
        instr['rflags'] = {
            'of': instrRflags.get(rflags.OF_),
            'sf': instrRflags.get(rflags.SF_),
            'zf': instrRflags.get(rflags.ZF_),
            'af': instrRflags.get(rflags.AF_),
            'pf': instrRflags.get(rflags.PF_),
            'cf': instrRflags.get(rflags.CF_),
            'tf': instrRflags.get(rflags.TF_),
            'if': instrRflags.get(rflags.IF_),
            'df': instrRflags.get(rflags.DF_),
            'nt': instrRflags.get(rflags.NT_),
            'rf': instrRflags.get(rflags.RF_),
        }
        for i in range(1,MAX_OPERANDS + 1):
            operand = getattr(self.infos, f'Operand{i}')
            if operand.OpType != NO_ARGUMENT:
                instr['operands'][i] = {
                    'repr': operand.OpMnemonic.decode(),
                    'type': instr_Types.get(operand.OpType),
                    'size': operand.OpSize,
                    'mode': {READ: 'read', WRITE: 'write', READ+WRITE: 'read+write'}.get(operand.AccessMode)
                }
                if operand.OpType == REGISTER_TYPE:
                    instr['operands'][i]['register'] = {
                        'type': instrRegisters.get(operand.Registers.type)
                    }
                    registers = getattr(operand.Registers, instr['operands'][i]['register']['type'])
                    instr['operands'][i]['register']['value'] = self.register_repr(registers)
                elif operand.OpType & 0xFFFFF == CONSTANT_TYPE:
                    instr['immediat'] = hex(self.infos.Instruction.Immediat)
                elif operand.OpType == MEMORY_TYPE:
                    instr['operands'][i]['memory'] = {
                        'base': self.register_repr(operand.Memory.BaseRegister),
                        'index': self.register_repr(operand.Memory.IndexRegister),
                        'scale': operand.Memory.Scale,
                        'displacement': hex(operand.Memory.Displacement)
                    }

        return instr

    def analyze(self, registers: str)->REGISTERTYPE():
        result = REGISTERTYPE()
        regs = re.sub(' +', ' ', registers.strip().lower()).split(" ")
        for reg in regs:
            current_reg = REGSTYPE.get(reg)
            if current_reg:
                val = getattr(result, current_reg.get('type'))
                val = val | current_reg.get('reg')
                setattr(result, current_reg.get('type'), val)
        return result

    def match_registers(self, registers1, registers2):
        status = 0

        for entry in registers1._fields_:
            if getattr(registers1, entry[0]) & getattr(registers2, entry[0]):
                status = 1
                break

        return status

    def uses(self, registers):
        """
        Check used registers
        Example: ucomiss xmm4, dword ptr [rax]
            instr = Disasm(bytes.fromhex('0f2e20'))
            instr.read()
            if instr.uses("gpr"):
                print("one or more general purpose registers are used")
        """
        status = 0
        registers_type = self.analyze(registers)
        for i in range(1,MAX_OPERANDS + 1):
            operand = getattr(self.infos, f'Operand{i}')
            if operand.AccessMode & READ:
                if operand.OpType == REGISTER_TYPE:
                    status += self.match_registers(operand.Registers, registers_type)
                elif operand.OpType == MEMORY_TYPE:
                    regs = REGISTERTYPE()
                    regs.type |= GENERAL_REG
                    regs.gpr |= operand.Memory.BaseRegister
                    if self.infos.Reserved_.VSIB_ == SSE_REG:
                        regs.type |= SSE_REG
                        regs.xmm |= operand.Memory.IndexRegister
                    elif self.infos.Reserved_.VSIB_ == AVX_REG:
                        regs.type |= AVX_REG
                        regs.ymm |= operand.Memory.IndexRegister
                    elif self.infos.Reserved_.VSIB_ == AVX512_REG:
                        regs.type |= AVX512_REG
                        regs.zmm |= operand.Memory.IndexRegister
                    else:
                        regs.gpr |= operand.Memory.IndexRegister

                    if operand.SegmentReg != 0:
                        regs.type |= SEGMENT_REG
                        regs.segment |= operand.SegmentReg
                    status += self.match_registers(regs, registers_type)

        status += self.match_registers(self.infos.Instruction.ImplicitUsedRegs, registers_type)
        return True if status > 0 else False

    def modifies(self, registers):
        """
        Check modified registers
        Example: ucomiss xmm4, dword ptr [rax]
            instr = Disasm(bytes.fromhex('0f2e20'))
            instr.read()
            if instr.modifies("xmm4"):
                print("xmm4 register is modified")
        """
        status = 0
        registers_type = self.analyze(registers)

        for i in range(1,MAX_OPERANDS + 1):
            operand = getattr(self.infos, f'Operand{i}')
            if operand.AccessMode & WRITE:
                status += self.match_registers(operand.Registers, registers_type)
        status += self.match_registers(self.infos.Instruction.ImplicitModifiedRegs, registers_type)

        return True if status > 0 else False

    def seek(self, offset = -1):
        """
        getter/setter for offset
        Example :
            disasm.seek(0x400)  # define offset where disasm engine must work
            print("%08x" % disasm.seek())   # get offset position
        """
        if offset == -1:
            return self.infos.offset - addressof(self.target)
        else:
            self.infos.offset = addressof(self.target) + offset
            return offset

    def getBytes(self):
        """
        getter to get bytes sequence of disassembled instruction
        Example:
            print(" ".join("{:02x}".format(b if type(b) == int else ord(b)) for b in self.bytes))
        """
        offset = self.infos.offset - addressof(self.target)
        if self.length == -1:
            self.bytes = self.buffer[offset : offset + 1]
        else:
            self.bytes = self.buffer[offset : offset + self.length]

    def getNextOffset(self):
        """
        setter to define next instruction offset
        """
        if self.infos.Error < 0:
            self.infos.offset += 1
            if self.infos.VirtualAddr != 0:
                self.infos.VirtualAddr += 1
        else:
            self.infos.offset = self.infos.offset + self.length
            if self.infos.VirtualAddr != 0:
                self.infos.VirtualAddr= self.infos.VirtualAddr+ self.length
        self.length = 0

    def next(self):
        """
        Disassemble next instruction
        Example:
            instr = Disasm(b'\x90\x90\x6a\x00\xe8\xa5\xc7\x02\x00')
            instr.read()
            print(instr.repr())

            instr.next()
            print(instr.repr())
        """
        return self.read()

    def read(self):
        """
        Disassemble next instruction
        Example:
            instr = Disasm(b'\x90\x90\x6a\x00\xe8\xa5\xc7\x02\x00')
            instr.read()
            print(instr.repr())

            instr.read()
            print(instr.repr())
        """
        self.getNextOffset()
        if self.infos.offset < self.end_block:
            self.infos.SecurityBlock = self.end_block - self.infos.offset
            self.length = BeaDisasm(c_void_p(addressof(self.infos)))
            self.getBytes()
        else:
            self.length = OUT_OF_BLOCK
            self.infos.Error = OUT_OF_BLOCK

        return self.length

    def error(self):
        return self.infos.Error

    def is_jump(self):
        """
        Check if it is a jump
        Example:
            instr = Disasm(bytes.fromhex('e9010000CC90'))
            instr.read()
            while not intr.error():
                if instr.is_jump():
                    instr.follow()
                else
                    instr.next()
        """
        if self.infos.Instruction.BranchType == JmpType and \
            self.infos.Instruction.AddrValue != 0:
            return True
        else:
            return False

    def is_call(self):
        """
        Check if it is a call
        Example:
            instr = Disasm(bytes.fromhex('e801000000CC90'))
            instr.read()
            while not intr.error():
                if instr.is_call():
                    instr.follow()
                else
                    instr.next()
        """
        if self.infos.Instruction.BranchType == CallType and \
            self.infos.Instruction.AddrValue != 0:
            return True
        else:
            return False

    def follow(self):
        """
        Example:
            instr = Disasm(bytes.fromhex('e90000000090'))
            instr.read()
            while not intr.error():
                if instr.is_jump():
                    instr.follow()
                else
                    instr.next()
        """
        if self.infos.Instruction.AddrValue != 0:
            self.infos.offset = self.infos.Instruction.AddrValue
            self.length = 0

    def repr(self):
        """
        Complete instruction representation for quick analysis
        Example:
            instr = Disasm(b'\x90\x90\x6a\x00\xe8\xa5\xc7\x02\x00')
            while instr.read() > 0:
                print(instr.repr())
        """
        return f"{self.infos.repr.decode()}"

        # return "{} {:<30} {}".format(
        #    "0x%08x" %(self.seek()),
        #    " ".join("{:02x}".format(b if type(b) == int else ord(b)) for b in self.bytes),
        #    self.infos.repr.decode("utf-8")
        # )
