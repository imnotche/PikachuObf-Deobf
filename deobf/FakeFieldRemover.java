package devs.pikachu.deobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * SyntheticBridgeApplyerTransformer が各クラスに足す exceptions/BadException 型の
 * ランダムな public static final フィールドを除去。参照されないフィールドを全クラスに足してたのか。
 */
public final class FakeFieldRemover implements Opcodes {
    public int apply(ClassNode classNode) {
        Set<String> referenced = new HashSet<>();
        for (MethodNode method : classNode.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode node = method.instructions.getFirst(); node != null; node = node.getNext()) {
                if (node instanceof FieldInsnNode f) {
                    referenced.add(f.name + "\u0000" + f.desc);
                }
            }
        }
        int removed = 0;
        for (Iterator<FieldNode> it = classNode.fields.iterator(); it.hasNext(); ) {
            FieldNode field = it.next();
            boolean fakeBadException = AsmUtil.BAD_EXCEPTION.equals(field.desc);
            boolean fakeIndyArray = "[LPikachuObf;".equals(field.desc)
                    || "[Ldevs/pikachu/protect/PikachuObf;".equals(field.desc);
            if ((fakeBadException || fakeIndyArray)
                    && !referenced.contains(field.name + "\u0000" + field.desc)) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }
}
