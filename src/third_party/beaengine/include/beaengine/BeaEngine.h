#ifndef _BEA_ENGINE_
#define _BEA_ENGINE_
#if  defined(__cplusplus) && defined(__BORLANDC__)
namespace BeaEngine {
#endif


#include <beaengine/macros.h>
#include <beaengine/export.h>
#include <beaengine/basic_types.h>

#if !defined(BEA_ENGINE_STATIC)
	#if defined(BUILD_BEA_ENGINE_DLL)
		#define BEA_API bea__api_export__
	#else
		#define BEA_API bea__api_import__
	#endif
#else
	#define BEA_API
#endif


#define INSTRUCT_LENGTH 80

#pragma pack(1)
typedef struct {
   UInt8 P0;
   UInt8 P1;
   UInt8 P2;
   UInt8 mm;
   UInt8 pp;
   UInt8 R;
   UInt8 X;
   UInt8 B;
   UInt8 R1;
   UInt8 vvvv;
   UInt8 V;
   UInt8 aaa;
   UInt8 W;
   UInt8 z;
   UInt8 b;
   UInt8 LL;
   UInt8 state;
   UInt8 masking;
   UInt8 tupletype;
} EVEX_Struct  ;
#pragma pack()

#pragma pack(1)
typedef struct {
   UInt8 L;
   UInt8 vvvv;
   UInt8 mmmmm;
   UInt8 pp;
   UInt8 state;
   UInt8 opcode;
} VEX_Struct  ;
#pragma pack()

#pragma pack(1)
typedef struct {
   UInt8 W_;
   UInt8 R_;
   UInt8 X_;
   UInt8 B_;
   UInt8 state;
} REX_Struct  ;
#pragma pack()

#pragma pack(1)
typedef struct {
   int Number;
   int NbUndefined;
   UInt8 LockPrefix;
   UInt8 OperandSize;
   UInt8 AddressSize;
   UInt8 RepnePrefix;
   UInt8 RepPrefix;
   UInt8 FSPrefix;
   UInt8 SSPrefix;
   UInt8 GSPrefix;
   UInt8 ESPrefix;
   UInt8 CSPrefix;
   UInt8 DSPrefix;
   UInt8 BranchTaken;
   UInt8 BranchNotTaken;
   REX_Struct REX;
   char alignment[2];
} PREFIXINFO  ;
#pragma pack()

#pragma pack(1)
typedef struct {
   UInt8 OF_;
   UInt8 SF_;
   UInt8 ZF_;
   UInt8 AF_;
   UInt8 PF_;
   UInt8 CF_;
   UInt8 TF_;
   UInt8 IF_;
   UInt8 DF_;
   UInt8 NT_;
   UInt8 RF_;
   UInt8 alignment;
} EFLStruct  ;
#pragma pack()

#pragma pack(4)
typedef struct {
   Int64 BaseRegister;
   Int64 IndexRegister;
   Int32 Scale;
   Int64 Displacement;
} MEMORYTYPE ;
#pragma pack()

#pragma pack(4)
typedef struct {
   Int64 type;
   Int64 gpr;
   Int64 mmx;
   Int64 xmm;
   Int64 ymm;
   Int64 zmm;
   Int64 special;
   Int64 cr;
   Int64 dr;
   Int64 mem_management;
   Int64 mpx;
   Int64 opmask;
   Int64 segment;
   Int64 fpu;
   Int64 tmm;
} REGISTERTYPE ;
#pragma pack()

#pragma pack(1)
typedef struct  {
   Int32 Category;
   Int32 Opcode;
   char Mnemonic[24];
   Int32 BranchType;
   EFLStruct Flags;
   UInt64 AddrValue;
   Int64 Immediat;
   REGISTERTYPE ImplicitModifiedRegs;
	 REGISTERTYPE ImplicitUsedRegs;
} INSTRTYPE;
#pragma pack()

#pragma pack(1)
typedef struct  {
   char OpMnemonic[24];
   Int64 OpType;
   Int32 OpSize;
   Int32 OpPosition;
   UInt32 AccessMode;
   MEMORYTYPE Memory;
   REGISTERTYPE Registers;
   UInt32 SegmentReg;
} OPTYPE;
#pragma pack()

/* reserved structure used for thread-safety */
/* unusable by customer */
#pragma pack(1)
typedef struct {
   UIntPtr EIP_;
   UInt64 EIP_VA;
   UIntPtr EIP_REAL;
   Int32 OriginalOperandSize;
   Int32 OperandSize;
   Int32 MemDecoration;
   Int32 AddressSize;
   Int32 MOD_;
   Int32 RM_;
   Int32 INDEX_;
   Int32 SCALE_;
   Int32 BASE_;
   Int32 REGOPCODE;
   UInt32 DECALAGE_EIP;
   Int32 FORMATNUMBER;
   Int32 SYNTAX_;
   UInt64 EndOfBlock;
   Int32 RelativeAddress;
   UInt32 Architecture;
   Int32 ImmediatSize;
   Int32 NB_PREFIX;
   Int32 PrefRepe;
   Int32 PrefRepne;
   UInt32 SEGMENTREGS;
   UInt32 SEGMENTFS;
   Int32 third_arg;
   UInt64 OPTIONS;
   Int32 ERROR_OPCODE;
   REX_Struct REX;
   Int32 OutOfBlock;
   VEX_Struct VEX;
   EVEX_Struct EVEX;
   Int32 VSIB_;
   Int32 Register_;
} InternalDatas;
#pragma pack()

/* ************** main structure ************ */
#pragma pack(1)
typedef struct _Disasm {
   UIntPtr EIP;
   UInt64 VirtualAddr;
   UInt32 SecurityBlock;
   char CompleteInstr[INSTRUCT_LENGTH];
   UInt32 Archi;
   UInt64 Options;
   INSTRTYPE Instruction;
   OPTYPE Operand1;
   OPTYPE Operand2;
   OPTYPE Operand3;
   OPTYPE Operand4;
   OPTYPE Operand5;
   OPTYPE Operand6;
   OPTYPE Operand7;
   OPTYPE Operand8;
   OPTYPE Operand9;
   PREFIXINFO Prefix;
   Int32 Error;
   InternalDatas Reserved_;
} DISASM, *PDISASM, *LPDISASM;
#pragma pack()

/* #UD exception */
#define UD_   2
#define DE__  3

#define ESReg 0x1
#define DSReg 0x2
#define FSReg 0x4
#define GSReg 0x8
#define CSReg 0x10
#define SSReg 0x20

#define InvalidPrefix 4
#define SuperfluousPrefix 2
#define NotUsedPrefix 0
#define MandatoryPrefix 8
#define InUsePrefix 1

#define LowPosition 0
#define HighPosition 1

/* EVEX Masking */

#define NO_MASK 0
#define MERGING 1
#define MERGING_ZEROING 2

/* EVEX Compressed Displacement */

#define FULL              1
#define HALF              2
#define FULL_MEM          3
#define TUPLE1_SCALAR__8  4
#define TUPLE1_SCALAR__16 5
#define TUPLE1_SCALAR     6
#define TUPLE1_FIXED__32  7
#define TUPLE1_FIXED__64  8
#define TUPLE2            9
#define TUPLE4            10
#define TUPLE8            11
#define HALF_MEM          12
#define QUARTER_MEM       13
#define EIGHTH_MEM        14
#define MEM128            15
#define MOVDDUP           16

enum INSTRUCTION_TYPE
{
  GENERAL_PURPOSE_INSTRUCTION   =           0x10000,
  FPU_INSTRUCTION               =           0x20000,
  MMX_INSTRUCTION               =           0x30000,
  SSE_INSTRUCTION               =           0x40000,
  SSE2_INSTRUCTION              =           0x50000,
  SSE3_INSTRUCTION              =           0x60000,
  SSSE3_INSTRUCTION             =           0x70000,
  SSE41_INSTRUCTION             =           0x80000,
  SSE42_INSTRUCTION             =           0x90000,
  SYSTEM_INSTRUCTION            =           0xa0000,
  VM_INSTRUCTION                =           0xb0000,
  UNDOCUMENTED_INSTRUCTION      =           0xc0000,
  AMD_INSTRUCTION               =           0xd0000,
  ILLEGAL_INSTRUCTION           =           0xe0000,
  AES_INSTRUCTION               =           0xf0000,
  CLMUL_INSTRUCTION             =          0x100000,
  AVX_INSTRUCTION               =          0x110000,
  AVX2_INSTRUCTION              =          0x120000,
  MPX_INSTRUCTION               =          0x130000,
  AVX512_INSTRUCTION            =          0x140000,
  SHA_INSTRUCTION               =          0x150000,
  BMI2_INSTRUCTION              =          0x160000,
  CET_INSTRUCTION               =          0x170000,
  BMI1_INSTRUCTION              =          0x180000,
  XSAVEOPT_INSTRUCTION          =          0x190000,
  FSGSBASE_INSTRUCTION          =          0x1a0000,
  CLWB_INSTRUCTION              =          0x1b0000,
  CLFLUSHOPT_INSTRUCTION        =          0x1c0000,
  FXSR_INSTRUCTION              =          0x1d0000,
  XSAVE_INSTRUCTION             =          0x1e0000,
  SGX_INSTRUCTION               =          0x1f0000,
  PCONFIG_INSTRUCTION           =          0x200000,
  UINTR_INSTRUCTION             =          0x210000,
  KL_INSTRUCTION                =          0x220000,
  AMX_INSTRUCTION               =          0x230000,

  DATA_TRANSFER = 0x1,
  ARITHMETIC_INSTRUCTION,
  LOGICAL_INSTRUCTION,
  SHIFT_ROTATE,
  BIT_UInt8,
  CONTROL_TRANSFER,
  STRING_INSTRUCTION,
  InOutINSTRUCTION,
  ENTER_LEAVE_INSTRUCTION,
  FLAG_CONTROL_INSTRUCTION,
  SEGMENT_REGISTER,
  MISCELLANEOUS_INSTRUCTION,
  COMPARISON_INSTRUCTION,
  LOGARITHMIC_INSTRUCTION,
  TRIGONOMETRIC_INSTRUCTION,
  UNSUPPORTED_INSTRUCTION,
  LOAD_CONSTANTS,
  FPUCONTROL,
  STATE_MANAGEMENT,
  CONVERSION_INSTRUCTION,
  SHUFFLE_UNPACK,
  PACKED_SINGLE_PRECISION,
  SIMD128bits,
  SIMD64bits,
  CACHEABILITY_CONTROL,
  FP_INTEGER_CONVERSION,
  SPECIALIZED_128bits,
  SIMD_FP_PACKED,
  SIMD_FP_HORIZONTAL ,
  AGENT_SYNCHRONISATION,
  PACKED_ALIGN_RIGHT  ,
  PACKED_SIGN,
  PACKED_BLENDING_INSTRUCTION,
  PACKED_TEST,
  PACKED_MINMAX,
  HORIZONTAL_SEARCH,
  PACKED_EQUALITY,
  STREAMING_LOAD,
  INSERTION_EXTRACTION,
  DOT_PRODUCT,
  SAD_INSTRUCTION,
  ACCELERATOR_INSTRUCTION,    /* crc32, popcnt (sse4.2) */
  ROUND_INSTRUCTION

};

enum EFLAGS_STATES
{
  TE_ = 1,
  MO_ = 2,
  RE_ = 4,
  SE_ = 8,
  UN_ = 0x10,
  PR_ = 0x20
};

enum BRANCH_TYPE
{
  JO = 1,
  JC = 2,
  JE = 3,
  JA = 4,
  JS = 5,
  JP = 6,
  JL = 7,
  JG = 8,
  JB = 2,       /* JC == JB */
  JECXZ = 10,
  JmpType = 11,
  CallType = 12,
  RetType = 13,
  JNO = -1,
  JNC = -2,
  JNE = -3,
  JNA = -4,
  JNS = -5,
  JNP = -6,
  JNL = -7,
  JNG = -8,
  JNB = -2      /* JNC == JNB */
};

enum ARGUMENTS_TYPE
{
  NO_ARGUMENT =          0x10000,
  REGISTER_TYPE =        0x20000,
  MEMORY_TYPE =          0x30000,
  CONSTANT_TYPE =        0x40000,

  GENERAL_REG =               0x1,
  MMX_REG =                   0x2,
  SSE_REG =                   0x4,
  AVX_REG =                   0x8,
  AVX512_REG =                0x10,
  SPECIAL_REG =               0x20,
  CR_REG =                    0x40,
  DR_REG =                    0x80,
  MEMORY_MANAGEMENT_REG =     0x100,
  MPX_REG =                   0x200,
  OPMASK_REG =                0x400,
  SEGMENT_REG =               0x800,
  FPU_REG =                   0x1000,
  TMM_REG =                   0x2000,

  RELATIVE_ = 0x4000000,
  ABSOLUTE_ = 0x8000000,

  READ = 0x1,
  WRITE = 0x2,

  REG0 =  0x1,
  REG1 =  0x2,
  REG2 =  0x4,
  REG3 =  0x8,
  REG4 =  0x10,
  REG5 =  0x20,
  REG6 =  0x40,
  REG7 =  0x80,
  REG8 =  0x100,
  REG9 =  0x200,
  REG10 = 0x400,
  REG11 = 0x800,
  REG12 = 0x1000,
  REG13 = 0x2000,
  REG14 = 0x4000,
  REG15 = 0x8000,
  REG16 = 0x10000,
  REG17 = 0x20000,
  REG18 = 0x40000,
  REG19 = 0x80000,
  REG20 = 0x100000,
  REG21 = 0x200000,
  REG22 = 0x400000,
  REG23 = 0x800000,
  REG24 = 0x1000000,
  REG25 = 0x2000000,
  REG26 = 0x4000000,
  REG27 = 0x8000000,
  REG28 = 0x10000000,
  REG29 = 0x20000000,
  REG30 = 0x40000000,
  REG31 = 0x80000000
};

enum SPECIAL_INFO
{
  UNKNOWN_OPCODE = -1,
  OUT_OF_BLOCK = -2,

  /* === mask = 0xff */
  NoTabulation      = 0x00000000,
  Tabulation        = 0x00000001,

  /* === mask = 0xff00 */
  MasmSyntax        = 0x00000000,
  GoAsmSyntax       = 0x00000100,
  NasmSyntax        = 0x00000200,
  ATSyntax          = 0x00000400,
  IntrinsicMemSyntax= 0x00000800,

  /* === mask = 0xff0000 */
  PrefixedNumeral   = 0x00010000,
  SuffixedNumeral   = 0x00000000,

  /* === mask = 0xff000000 */
  ShowSegmentRegs   = 0x01000000,
  ShowEVEXMasking   = 0x02000000
};


#ifdef __cplusplus
extern "C" {
#endif

BEA_API int __bea_callspec__ Disasm (LPDISASM pDisAsm);
BEA_API const__ char* __bea_callspec__ BeaEngineVersion (void);
BEA_API const__ char* __bea_callspec__ BeaEngineRevision (void);

#ifdef __cplusplus
}
#endif


#if  defined(__cplusplus) && defined(__BORLANDC__)
};
using namespace BeaEngine;
#endif
#endif
