package devs.pikachu.deobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;

public final class AsmUtil implements Opcodes {
    public static final String PIKACHU = "devs/pikachu/protect/PikachuObf";
    public static final String PIKACHU_SHORT = "PikachuObf";
    public static final String BAD_EXCEPTION = "exceptions/BadException";

    private AsmUtil() {
    }

    public static boolean isPseudo(AbstractInsnNode node) {
        return node instanceof LabelNode || node instanceof LineNumberNode || node instanceof FrameNode;
    }

    public static AbstractInsnNode nextReal(AbstractInsnNode node) {
        AbstractInsnNode n = node == null ? null : node.getNext();
        while (n != null && isPseudo(n)) {
            n = n.getNext();
        }
        return n;
    }

    public static AbstractInsnNode prevReal(AbstractInsnNode node) {
        AbstractInsnNode n = node == null ? null : node.getPrevious();
        while (n != null && isPseudo(n)) {
            n = n.getPrevious();
        }
        return n;
    }

    public static AbstractInsnNode nextNonLabel(AbstractInsnNode node) {
        AbstractInsnNode n = node == null ? null : node.getNext();
        while (n != null && (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode)) {
            n = n.getNext();
        }
        return n;
    }

    public static boolean isPikachuOwner(String owner) {
        return PIKACHU.equals(owner) || PIKACHU_SHORT.equals(owner);
    }

    public static boolean isKami(MethodInsnNode m) {
        return m.getOpcode() == INVOKESTATIC
                && isPikachuOwner(m.owner)
                && "Kami".equals(m.name);
    }

    public static boolean isBadExceptionThrow(AbstractInsnNode node) {
        // NEW exceptions/BadException; DUP; LDC "SbUwU"; INVOKESPECIAL; ATHROW
        if (!(node instanceof TypeInsnNode t) || t.getOpcode() != NEW || !BAD_EXCEPTION.equals(t.desc)) {
            return false;
        }
        AbstractInsnNode n = nextReal(node);
        if (!(n instanceof InsnNode dup) || dup.getOpcode() != DUP) {
            return false;
        }
        n = nextReal(n);
        if (!(n instanceof LdcInsnNode ldc) || !(ldc.cst instanceof String)) {
            return false;
        }
        n = nextReal(n);
        if (!(n instanceof MethodInsnNode init) || init.getOpcode() != INVOKESPECIAL
                || !BAD_EXCEPTION.equals(init.owner) || !"<init>".equals(init.name)) {
            return false;
        }
        n = nextReal(n);
        return n != null && n.getOpcode() == ATHROW;
    }

    public static boolean isXsdField(FieldInsnNode f) {
        return f.getOpcode() == GETSTATIC
                && isPikachuOwner(f.owner)
                && f.name.startsWith("xsd_")
                && "Ljava/lang/String;".equals(f.desc);
    }

    public static int xsdIndex(FieldInsnNode f) {
        if (f.name.length() < 5) {
            return -1;
        }
        try {
            return Integer.parseInt(f.name.substring(4));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    public static int stackSize(Type type) {
        return type.getSize();
    }

    public static Type returnType(String desc) {
        return Type.getReturnType(desc);
    }

    public static Type[] argumentTypes(String desc) {
        return Type.getArgumentTypes(desc);
    }

    public static boolean isTerminator(AbstractInsnNode node) {
        int op = node.getOpcode();
        return op == ATHROW || (op >= IRETURN && op <= RETURN) || op == RET;
    }

    /**
     * 定数式の置換で消せる命令だけを許可。ロード・ストア、フィールド書き込み、
     * メモリ確保、モニター操作、定数でない呼び出しは対象外。
     */
    public static boolean isPureForRange(AbstractInsnNode node) {
        if (node instanceof LabelNode || node instanceof LineNumberNode || node instanceof FrameNode) {
            return true;
        }
        if (node instanceof LdcInsnNode) {
            return true;
        }
        if (node instanceof IntInsnNode ii) {
            return ii.getOpcode() == BIPUSH || ii.getOpcode() == SIPUSH;
        }
        if (node instanceof FieldInsnNode f) {
            return isXsdField(f);
        }
        if (node instanceof MethodInsnNode m) {
            if (isKami(m)) {
                return true;
            }
            return m.getOpcode() == INVOKEVIRTUAL
                    && "java/lang/String".equals(m.owner)
                    && ("hashCode".equals(m.name) || "length".equals(m.name) || "equals".equals(m.name));
        }
        if (node instanceof TypeInsnNode t) {
            return t.getOpcode() == CHECKCAST;
        }
        if (!(node instanceof InsnNode)) {
            return false;
        }
        int op = node.getOpcode();
        switch (op) {
            case NOP:
            case ACONST_NULL:
            case ICONST_M1:
            case ICONST_0:
            case ICONST_1:
            case ICONST_2:
            case ICONST_3:
            case ICONST_4:
            case ICONST_5:
            case LCONST_0:
            case LCONST_1:
            case FCONST_0:
            case FCONST_1:
            case FCONST_2:
            case DCONST_0:
            case DCONST_1:
            case I2L:
            case L2I:
            case I2F:
            case F2I:
            case I2D:
            case D2I:
            case L2F:
            case F2L:
            case L2D:
            case D2L:
            case F2D:
            case D2F:
            case I2B:
            case I2C:
            case I2S:
            case INEG:
            case LNEG:
            case FNEG:
            case DNEG:
            case IADD:
            case LADD:
            case FADD:
            case DADD:
            case ISUB:
            case LSUB:
            case FSUB:
            case DSUB:
            case IMUL:
            case LMUL:
            case FMUL:
            case DMUL:
            case IDIV:
            case LDIV:
            case FDIV:
            case DDIV:
            case IREM:
            case LREM:
            case FREM:
            case DREM:
            case ISHL:
            case LSHL:
            case ISHR:
            case LSHR:
            case IUSHR:
            case LUSHR:
            case IAND:
            case LAND:
            case IOR:
            case LOR:
            case IXOR:
            case LXOR:
            case LCMP:
            case FCMPL:
            case FCMPG:
            case DCMPL:
            case DCMPG:
                return true;
            default:
                return false;
        }
    }

    public static void removeRange(InsnList list, AbstractInsnNode start, AbstractInsnNode end) {
        AbstractInsnNode n = start;
        while (n != null) {
            AbstractInsnNode next = n.getNext();
            list.remove(n);
            if (n == end) {
                break;
            }
            n = next;
        }
    }

    public static Object constantOf(AbstractInsnNode node) {
        if (node instanceof LdcInsnNode ldc) {
            return ldc.cst;
        }
        if (node instanceof IntInsnNode ii) {
            if (ii.getOpcode() == BIPUSH || ii.getOpcode() == SIPUSH) {
                return ii.operand;
            }
            return null;
        }
        if (node instanceof InsnNode insn) {
            int op = insn.getOpcode();
            if (op >= ICONST_M1 && op <= ICONST_5) {
                return op - ICONST_0;
            }
            if (op == LCONST_0 || op == LCONST_1) {
                return (long) (op - LCONST_0);
            }
            if (op >= FCONST_0 && op <= FCONST_2) {
                return (float) (op - FCONST_0);
            }
            if (op == DCONST_0 || op == DCONST_1) {
                return (double) (op - DCONST_0);
            }
            if (op == ACONST_NULL) {
                return null;
            }
        }
        return null;
    }

    public static Integer intConstant(AbstractInsnNode node) {
        Object c = constantOf(node);
        return c instanceof Integer ? (Integer) c : null;
    }
}
