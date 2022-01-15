// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.X86_const.*;

public class X86 {

  public static class MemType extends Structure {
    public int segment;
    public int base;
    public int index;
    public int scale;
    public long disp;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("segment", "base", "index", "scale", "disp");
    }
  }
  
  public static class Encoding extends Structure {
    public byte modrmOffset;
    public byte dispOffset;
    public byte dispSize;
    public byte immOffset;
    public byte immSize;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("modrmOffset", "dispOffset", "dispSize", "immOffset", "immSize");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public MemType mem;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("reg", "imm", "mem");
    }
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;
    public byte size;
    public byte access;
    public int avx_bcast;
    public boolean avx_zero_opmask;

    public void read() {
      super.read();
      if (type == X86_OP_MEM)
        value.setType(MemType.class);
      if (type == X86_OP_IMM)
        value.setType(Long.TYPE);
      if (type == X86_OP_REG)
        value.setType(Integer.TYPE);
      if (type == X86_OP_INVALID)
        return;
      readField("value");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("type", "value", "size", "access", "avx_bcast", "avx_zero_opmask");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte [] prefix;
    public byte [] opcode;
    public byte rex;
    public byte addr_size;
    public byte modrm;
    public byte sib;
    public long disp;
    public int sib_index;
    public byte sib_scale;
    public int sib_base;
    public int xop_cc;
    public int sse_cc;
    public int avx_cc;
    public byte avx_sae;
    public int avx_rm;
    public long eflags;

    public byte op_count;

    public Operand [] op;
    
    public Encoding encoding;

    public UnionOpInfo() {
      op = new Operand[8];
      opcode = new byte[4];
      prefix = new byte[4];
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("prefix", "opcode", "rex", "addr_size",
          "modrm", "sib", "disp", "sib_index", "sib_scale", "sib_base", "xop_cc", "sse_cc", "avx_cc", "avx_sae", "avx_rm", "eflags", "op_count", "op", "encoding");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public byte [] prefix;
    public byte [] opcode;
    public byte opSize;
    public byte rex;
    public byte addrSize;
    public byte dispSize;
    public byte immSize;
    public byte modrm;
    public byte sib;
    public long disp;
    public int sibIndex;
    public byte sibScale;
    public int sibBase;
    public int xopCC;
    public int sseCC;
    public int avxCC;
    public boolean avxSae;
    public int avxRm;
    public long eflags;

    public Operand[] op;
    
    public Encoding encoding;

    public OpInfo(UnionOpInfo e) {
      prefix = e.prefix;
      opcode = e.opcode;
      rex = e.rex;
      addrSize = e.addr_size;
      modrm = e.modrm;
      sib = e.sib;
      disp = e.disp;
      sibIndex = e.sib_index;
      sibScale = e.sib_scale;
      sibBase = e.sib_base;
      xopCC = e.xop_cc;
      sseCC = e.sse_cc;
      avxCC = e.avx_cc;
      avxSae = e.avx_sae > 0;
      avxRm = e.avx_rm;
      eflags = e.eflags;
      op = new Operand[e.op_count];
      for (int i=0; i<e.op_count; i++)
        op[i] = e.op[i];
      encoding = e.encoding;
    }
  }
}
