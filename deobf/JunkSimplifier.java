package devs.pikachu.deobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * More2JunkCodeTransformer のジャンプテーブル式整数隠蔽を戻す。整数ひとつ読むのにこれか:
 *   ldc (value ^ key)
 *   goto trampoline
 * back:
 *   ...
 * trampoline:
 *   ldc class PikachuObf; ifnull throw; ldc key; ixor; goto back
 * 定数畳み込みでキーが ldc になれば、値との XOR を元の整数に戻せる。
 * 用済みのトランポリンは到達不能になるので、デッドコード除去パスで撤去する。
 */
public final class JunkSimplifier implements Opcodes {
    private final DeobfContext ctx;
    private int changes;

    public JunkSimplifier(DeobfContext ctx) {
        this.ctx = ctx;
    }

    public int apply(ClassNode classNode) {
        changes = 0;
        for (MethodNode method : classNode.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode node = method.instructions.getFirst(); node != null; node = node.getNext()) {
                if (node instanceof LdcInsnNode ldc && ldc.cst instanceof Integer value) {
                    AbstractInsnNode next = AsmUtil.nextReal(ldc);
                    if (!(next instanceof JumpInsnNode jump) || jump.getOpcode() != GOTO) {
                        continue;
                    }
                    LabelNode trampoline = jump.label;
                    AbstractInsnNode backNode = jump.getNext();
                    while (backNode instanceof org.objectweb.asm.tree.LineNumberNode
                            || backNode instanceof org.objectweb.asm.tree.FrameNode) {
                        backNode = backNode.getNext();
                    }
                    if (!(backNode instanceof LabelNode backLabel)) {
                        continue;
                    }
                    Integer key = readTrampolineKey(trampoline, backLabel);
                    if (key == null) {
                        continue;
                    }
                    ldc.cst = value ^ key;
                    method.instructions.remove(jump);
                    changes++;
                    ctx.junk++;
                }
            }
        }
        return changes;
    }

    private Integer readTrampolineKey(LabelNode trampoline, LabelNode back) {
        AbstractInsnNode n = AsmUtil.nextReal(trampoline);
        if (n instanceof LdcInsnNode typeLdc && typeLdc.cst instanceof Type) {
            n = AsmUtil.nextReal(typeLdc);
            if (n instanceof JumpInsnNode ifNull && ifNull.getOpcode() == IFNULL) {
                n = AsmUtil.nextReal(ifNull);
            }
        }
        Integer key = AsmUtil.intConstant(n);
        if (key == null) {
            return null;
        }
        n = AsmUtil.nextReal(n);
        if (!(n instanceof InsnNode xor) || xor.getOpcode() != IXOR) {
            return null;
        }
        n = AsmUtil.nextReal(n);
        if (!(n instanceof JumpInsnNode backJump) || backJump.getOpcode() != GOTO
                || backJump.label != back) {
            return null;
        }
        return key;
    }
}
