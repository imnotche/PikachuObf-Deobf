package devs.pikachu.deobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LocalVariableAnnotationNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * 文字列・数値・invokedynamic のダミーガードが生む到達不能コードを掃除する。
 * 各メソッド末尾の "throw new BadException" や定数条件の死んだ分岐は、
 * 定数畳み込み後に到達不能になる。投げる気のない例外を律儀に各メソッドへ足していた。
 */
public final class DeadCodeEliminator implements Opcodes {
    public int apply(ClassNode classNode) {
        int removed = 0;
        for (MethodNode method : classNode.methods) {
            if (method.instructions == null || method.instructions.size() == 0) {
                continue;
            }
            removed += process(method);
        }
        return removed;
    }

    private int process(MethodNode method) {
        Set<AbstractInsnNode> reachable = new HashSet<>();
        Set<AbstractInsnNode> keep = new HashSet<>();

        for (TryCatchBlockNode tcb : method.tryCatchBlocks) {
            keep.add(tcb.start);
            keep.add(tcb.end);
            keep.add(tcb.handler);
        }

        Deque<AbstractInsnNode> work = new ArrayDeque<>();
        AbstractInsnNode first = method.instructions.getFirst();
        if (first != null) {
            work.add(first);
        }
        for (TryCatchBlockNode tcb : method.tryCatchBlocks) {
            work.add(tcb.handler);
        }

        while (!work.isEmpty()) {
            AbstractInsnNode node = work.removeFirst();
            if (node == null || !reachable.add(node)) {
                continue;
            }
            if (node instanceof JumpInsnNode jump) {
                work.add(jump.label);
                if (jump.getOpcode() != GOTO) {
                    AbstractInsnNode next = node.getNext();
                    if (next != null) {
                        work.add(next);
                    }
                }
            } else if (node instanceof TableSwitchInsnNode table) {
                work.add(table.dflt);
                table.labels.forEach(work::add);
            } else if (node instanceof LookupSwitchInsnNode lookup) {
                work.add(lookup.dflt);
                lookup.labels.forEach(work::add);
            } else if (node instanceof VarInsnNode var) {
                if (var.getOpcode() != RET) {
                    AbstractInsnNode next = node.getNext();
                    if (next != null) {
                        work.add(next);
                    }
                }
            } else if (!AsmUtil.isTerminator(node)) {
                AbstractInsnNode next = node.getNext();
                if (next != null) {
                    work.add(next);
                }
            }
        }

        int before = method.instructions.size();
        List<AbstractInsnNode> toRemove = new ArrayList<>();
        for (AbstractInsnNode node = method.instructions.getFirst(); node != null; node = node.getNext()) {
            if (node instanceof FrameNode) {
                toRemove.add(node);
                continue;
            }
            if (!reachable.contains(node) && !(node instanceof LabelNode && keep.contains(node))) {
                toRemove.add(node);
            }
        }
        for (AbstractInsnNode node : toRemove) {
            method.instructions.remove(node);
        }

        // 削除済みラベルへのデバッグ情報も消す。命令だけ消して満足しそうなところ。
        if (method.localVariables != null) {
            method.localVariables.removeIf(lv -> lv.start == null || lv.end == null
                    || !method.instructions.contains(lv.start)
                    || !method.instructions.contains(lv.end));
        }
        if (method.tryCatchBlocks != null) {
            for (Iterator<TryCatchBlockNode> it = method.tryCatchBlocks.iterator(); it.hasNext(); ) {
                TryCatchBlockNode tcb = it.next();
                if (!method.instructions.contains(tcb.start)
                        || !method.instructions.contains(tcb.end)
                        || !method.instructions.contains(tcb.handler)) {
                    it.remove();
                }
            }
        }
        if (method.visibleLocalVariableAnnotations != null) {
            method.visibleLocalVariableAnnotations.removeIf(a -> !labelsPresent(method, a));
        }
        if (method.invisibleLocalVariableAnnotations != null) {
            method.invisibleLocalVariableAnnotations.removeIf(a -> !labelsPresent(method, a));
        }
        if (method.instructions.size() == 0) {
            method.instructions.add(new InsnNode(RETURN));
        }
        return before - method.instructions.size();
    }

    /**
     * ローカル変数アノテーションは範囲内の全ラベルが命令リストに残る場合だけ書ける。ここも参照してたのか。
     */
    private static boolean labelsPresent(MethodNode method, LocalVariableAnnotationNode annotation) {
        if (annotation.start == null || annotation.start.isEmpty()
                || annotation.end == null || annotation.end.isEmpty()) {
            return false;
        }
        for (LabelNode label : annotation.start) {
            if (label == null || !method.instructions.contains(label)) {
                return false;
            }
        }
        for (LabelNode label : annotation.end) {
            if (label == null || !method.instructions.contains(label)) {
                return false;
            }
        }
        return true;
    }
}
