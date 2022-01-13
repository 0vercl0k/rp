using System;
using System.Runtime.InteropServices;

namespace Bea
{
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public class REX_Struct
  {
    public byte W_;
    public byte R_;
    public byte X_;
    public byte B_;
    public byte state;
  }

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public class PrefixInfo
  {
    public int Number;
    public int NbUndefined;
    public byte LockPrefix;
    public byte OperandSize;
    public byte AddressSize;
    public byte RepnePrefix;
    public byte RepPrefix;
    public byte FSPrefix;
    public byte SSPrefix;
    public byte GSPrefix;
    public byte ESPrefix;
    public byte CSPrefix;
    public byte DSPrefix;
    public byte BranchTaken;
    public byte BranchNotTaken;
    public REX_Struct REX;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
    public string alignment;
  }

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public class EFLStruct
  {
    public byte OF_;
    public byte SF_;
    public byte ZF_;
    public byte AF_;
    public byte PF_;
    public byte CF_;
    public byte TF_;
    public byte IF_;
    public byte DF_;
    public byte NT_;
    public byte RF_;
    public byte alignment;
  }

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public class RegisterType
  {
    public Int64 type;
    public Int64 gpr;
    public Int64 mmx;
    public Int64 xmm;
    public Int64 ymm;
    public Int64 zmm;
    public Int64 special;
    public Int64 cr;
    public Int64 dr;
    public Int64 mem_management;
    public Int64 mpx;
    public Int64 opmask;
    public Int64 segment;
    public Int64 fpu;
    public Int64 tmm;
  }


  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public class MemoryType
  {
    public Int32 BaseRegister;
    public Int32 IndexRegister;
    public Int32 Scale;
    public Int64 Displacement;
  }

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public class InstructionType
  {
    public Int32 Category;
    public Int32 Opcode;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 24)]
    public string Mnemonic;
    public Int32 BranchType;
    public EFLStruct Flags;
    public UInt64 AddrValue;
    public Int64 Immediat;
    public RegisterType ImplicitModifiedRegs;
    public RegisterType ImplicitUsedRegs;
  }

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public class ArgumentType
  {
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 24)]
    public string OpMnemonic;
    public Int32 OpType;
    public Int32 OpSize;
    public Int32 OpPosition;
    public UInt32 AccessMode;
    public MemoryType Memory;
    public RegisterType Registers;
    public UInt32 SegmentReg;
  }

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public class Disasm
  {
    public IntPtr EIP;
    public UInt64 VirtualAddr;
    public UInt32 SecurityBlock;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string CompleteInstr;
    public UInt32 Archi;
    public UInt64 Options;
    public InstructionType Instruction;
    public ArgumentType Operand1;
    public ArgumentType Operand2;
    public ArgumentType Operand3;
    public ArgumentType Operand4;
    public ArgumentType Operand5;
    public ArgumentType Operand6;
    public ArgumentType Operand7;
    public ArgumentType Operand8;
    public ArgumentType Operand9;
    public PrefixInfo Prefix;
    public Int32 Error;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48, ArraySubType = UnmanagedType.U4)]
    UInt32[] Reserved_;
  }
}
