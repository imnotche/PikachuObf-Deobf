package devs.pikachu.deobf;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.LocalVariableAnnotationNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 難読化ランタイムは参照がなければ削除。定数評価できない呼び出しなどで
 * PikachuObf がまだ必要なら、最小限のスタブに替える。
 * 旧クラスのライセンス・認証チェックとバナーは含めない。復号処理と同じクラスに入れてたのか。
 */
public final class HelperCleaner implements Opcodes {
    private final Map<String, ClassNode> classes;
    private final DeobfContext ctx;
    private final Map<String, byte[]> replacements = new java.util.LinkedHashMap<>();
    private final List<String> removed = new ArrayList<>();

    public HelperCleaner(Map<String, ClassNode> classes, DeobfContext ctx) {
        this.classes = classes;
        this.ctx = ctx;
    }

    public Map<String, byte[]> replacements() {
        return replacements;
    }

    public List<String> removed() {
        return removed;
    }

    public void apply() {
        boolean pikaLong = classes.containsKey(AsmUtil.PIKACHU);
        boolean pikaShort = classes.containsKey(AsmUtil.PIKACHU_SHORT);
        boolean bad = classes.containsKey(AsmUtil.BAD_EXCEPTION);

        boolean refLong = false;
        boolean refShort = false;
        boolean refBad = false;
        for (ClassNode cn : classes.values()) {
            if (isHelper(cn.name)) {
                continue;
            }
            if (pikaLong && references(cn, AsmUtil.PIKACHU)) {
                refLong = true;
            }
            if (pikaShort && references(cn, AsmUtil.PIKACHU_SHORT)) {
                refShort = true;
            }
            if (bad && references(cn, AsmUtil.BAD_EXCEPTION)) {
                refBad = true;
            }
        }

        if (!refLong && !refShort && !refBad) {
            remove(AsmUtil.PIKACHU);
            remove(AsmUtil.PIKACHU_SHORT);
            remove(AsmUtil.BAD_EXCEPTION);
            return;
        }

        if (ctx.keepHelper) {
            ctx.warn("PikachuObf/BadException are still referenced; keeping the original classes because --keep-helper was used");
            return;
        }

        boolean unresolvedIndy = hasUnresolvedIndy();
        if (unresolvedIndy && !ctx.forceStripHelper) {
            ctx.warn("Unresolved PikachuObf invoke-dynamic call sites remain; keeping the original helper classes. "
                    + "Use --force-strip-helper to remove them anyway.");
            return;
        }

        if (refLong) {
            replacements.put(AsmUtil.PIKACHU, stubPikachu(AsmUtil.PIKACHU));
            ctx.helperClassesStubbed++;
        } else {
            remove(AsmUtil.PIKACHU);
        }
        if (refShort) {
            replacements.put(AsmUtil.PIKACHU_SHORT, stubPikachu(AsmUtil.PIKACHU_SHORT));
            ctx.helperClassesStubbed++;
        } else {
            remove(AsmUtil.PIKACHU_SHORT);
        }
        if (refBad) {
            replacements.put(AsmUtil.BAD_EXCEPTION, stubBadException());
            ctx.helperClassesStubbed++;
        } else {
            remove(AsmUtil.BAD_EXCEPTION);
        }
        if (unresolvedIndy) {
            ctx.warn("Forced removal of the helper classes; unresolved invoke-dynamic sites will fail at runtime");
        }
        ctx.warn("Replaced PikachuObf runtime classes with clean stubs (auth/banner code is gone)");
    }

    private boolean hasUnresolvedIndy() {
        for (ClassNode cn : classes.values()) {
            if (isHelper(cn.name)) {
                continue;
            }
            for (MethodNode method : cn.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode node = method.instructions.getFirst(); node != null; node = node.getNext()) {
                    if (node instanceof InvokeDynamicInsnNode indy && indy.bsm != null
                            && AsmUtil.isPikachuOwner(indy.bsm.getOwner())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private void remove(String name) {
        if (classes.remove(name) != null) {
            removed.add(name);
            ctx.helperClassesRemoved++;
        }
    }

    private static boolean isHelper(String name) {
        return AsmUtil.PIKACHU.equals(name) || AsmUtil.PIKACHU_SHORT.equals(name)
                || AsmUtil.BAD_EXCEPTION.equals(name);
    }

    private static boolean references(ClassNode cn, String target) {
        if (target.equals(cn.superName)) {
            return true;
        }
        if (cn.interfaces != null && cn.interfaces.contains(target)) {
            return true;
        }
        for (FieldNode field : cn.fields) {
            if (referencesType(field.desc, target) || referencesType(field.signature, target)) {
                return true;
            }
        }
        for (MethodNode method : cn.methods) {
            if (referencesType(method.desc, target) || referencesType(method.signature, target)) {
                return true;
            }
            if (method.exceptions != null && method.exceptions.contains(target)) {
                return true;
            }
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode node = method.instructions.getFirst(); node != null; node = node.getNext()) {
                if (node instanceof TypeInsnNode t && target.equals(t.desc)) {
                    return true;
                }
                if (node instanceof FieldInsnNode f
                        && (target.equals(f.owner) || referencesType(f.desc, target))) {
                    return true;
                }
                if (node instanceof MethodInsnNode m && target.equals(m.owner)) {
                    return true;
                }
                if (node instanceof LdcInsnNode ldc && ldc.cst instanceof Type t
                        && target.equals(t.getInternalName())) {
                    return true;
                }
                if (node instanceof InvokeDynamicInsnNode indy) {
                    if (indy.bsm != null && target.equals(indy.bsm.getOwner())) {
                        return true;
                    }
                    for (Object arg : indy.bsmArgs) {
                        if (arg instanceof Handle h && target.equals(h.getOwner())) {
                            return true;
                        }
                        if (arg instanceof Type t && target.equals(t.getInternalName())) {
                            return true;
                        }
                    }
                }
            }
        }
        for (org.objectweb.asm.tree.InnerClassNode inner : cn.innerClasses) {
            if (target.equals(inner.name) || target.equals(inner.outerName)) {
                return true;
            }
        }
        if (target.equals(cn.nestHostClass) || (cn.nestMembers != null && cn.nestMembers.contains(target))) {
            return true;
        }
        return cn.permittedSubclasses != null && cn.permittedSubclasses.contains(target);
    }

    private static boolean referencesType(String descriptorOrSignature, String target) {
        if (descriptorOrSignature == null) {
            return false;
        }
        return descriptorOrSignature.contains("L" + target + ";")
                || descriptorOrSignature.contains("L" + target + "<")
                || descriptorOrSignature.contains("[L" + target + ";");
    }

    private static byte[] stubBadException() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(V1_8, ACC_PUBLIC | ACC_SUPER, AsmUtil.BAD_EXCEPTION, null,
                "java/lang/RuntimeException", null);
        ctor(cw, "()V", null);
        ctor(cw, "(Ljava/lang/String;)V", "Ljava/lang/String;");
        ctor(cw, "(Ljava/lang/String;Ljava/lang/Throwable;)V", "Ljava/lang/String;Ljava/lang/Throwable;");
        ctor(cw, "(Ljava/lang/Throwable;)V", "Ljava/lang/Throwable;");
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void ctor(ClassWriter cw, String desc, String argDesc) {
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", desc, null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        if (argDesc == null) {
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false);
        } else if ("Ljava/lang/String;".equals(argDesc)) {
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>",
                    "(Ljava/lang/String;)V", false);
        } else if ("Ljava/lang/String;Ljava/lang/Throwable;".equals(argDesc)) {
            mv.visitVarInsn(ALOAD, 1);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>",
                    "(Ljava/lang/String;Ljava/lang/Throwable;)V", false);
        } else {
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>",
                    "(Ljava/lang/Throwable;)V", false);
        }
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static byte[] stubPikachu(String name) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(V1_8, ACC_PUBLIC | ACC_SUPER, name, null, "java/lang/Object", null);
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "xsd_1", "Ljava/lang/String;", null, "PikachuObf").visitEnd();
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "xsd_2", "Ljava/lang/String;", null, "PikachuObf").visitEnd();
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "xsd_3", "Ljava/lang/String;", null, "PikachuObf3").visitEnd();
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "_________", "Z", null, Boolean.FALSE).visitEnd();

        ctorObject(cw);
        kamiString(cw);
        kamiInt(cw);
        kamiLong(cw);
        log(cw);
        test(cw);
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void ctorObject(ClassWriter cw) {
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>",
                "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void kamiString(ClassWriter cw) {
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "Kami",
                "(Ljava/lang/Object;)Ljava/lang/String;", null, null);
        mv.visitCode();
        org.objectweb.asm.Label notString = new org.objectweb.asm.Label();
        org.objectweb.asm.Label empty = new org.objectweb.asm.Label();
        org.objectweb.asm.Label loop = new org.objectweb.asm.Label();
        org.objectweb.asm.Label done = new org.objectweb.asm.Label();

        mv.visitVarInsn(ALOAD, 0);
        mv.visitTypeInsn(INSTANCEOF, "java/lang/String");
        mv.visitJumpInsn(IFNE, notString); // 文字列なら先へ。notString って付けたの誰だよ、自分か。
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESTATIC, "java/lang/String", "valueOf",
                "(Ljava/lang/Object;)Ljava/lang/String;", false);
        mv.visitInsn(ARETURN);

        mv.visitLabel(notString);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitTypeInsn(CHECKCAST, "java/lang/String");
        mv.visitVarInsn(ASTORE, 1);
        mv.visitVarInsn(ALOAD, 1);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "isEmpty", "()Z", false);
        mv.visitJumpInsn(IFEQ, empty); // 空でなければ先へ。こっちも名前が逆じゃないか。
        mv.visitVarInsn(ALOAD, 1);
        mv.visitInsn(ARETURN);

        mv.visitLabel(empty);
        mv.visitVarInsn(ALOAD, 1);
        mv.visitInsn(ICONST_0);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false);
        mv.visitVarInsn(ISTORE, 2);

        mv.visitVarInsn(ALOAD, 1);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
        mv.visitInsn(ICONST_1);
        mv.visitInsn(ISUB);
        mv.visitIntInsn(NEWARRAY, T_CHAR);
        mv.visitVarInsn(ASTORE, 3);
        mv.visitInsn(ICONST_0);
        mv.visitVarInsn(ISTORE, 4);

        mv.visitLabel(loop);
        mv.visitVarInsn(ILOAD, 4);
        mv.visitVarInsn(ALOAD, 3);
        mv.visitInsn(ARRAYLENGTH);
        mv.visitJumpInsn(IF_ICMPGE, done);
        mv.visitVarInsn(ALOAD, 3);
        mv.visitVarInsn(ILOAD, 4);
        mv.visitVarInsn(ALOAD, 1);
        mv.visitVarInsn(ILOAD, 4);
        mv.visitInsn(ICONST_1);
        mv.visitInsn(IADD);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false);
        mv.visitVarInsn(ILOAD, 2);
        mv.visitVarInsn(ILOAD, 4);
        mv.visitInsn(ICONST_1);
        mv.visitInsn(IADD);
        mv.visitInsn(IMUL);
        mv.visitInsn(IXOR);
        mv.visitInsn(I2C);
        mv.visitInsn(CASTORE);
        mv.visitIincInsn(4, 1);
        mv.visitJumpInsn(GOTO, loop);

        mv.visitLabel(done);
        mv.visitTypeInsn(NEW, "java/lang/String");
        mv.visitInsn(DUP);
        mv.visitVarInsn(ALOAD, 3);
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false);
        mv.visitInsn(ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void kamiInt(ClassWriter cw) {
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "Kami",
                "(III)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ILOAD, 0);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitInsn(IXOR);
        mv.visitVarInsn(ILOAD, 2);
        mv.visitInsn(ICONST_M1);
        mv.visitInsn(IXOR);
        mv.visitInsn(IXOR);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void kamiLong(ClassWriter cw) {
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "Kami",
                "(JJJ)J", null, null);
        mv.visitCode();
        mv.visitVarInsn(LLOAD, 0);
        mv.visitVarInsn(LLOAD, 2);
        mv.visitInsn(LXOR);
        mv.visitVarInsn(LLOAD, 4);
        mv.visitLdcInsn(-1L);
        mv.visitInsn(LXOR);
        mv.visitInsn(LXOR);
        mv.visitInsn(LRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void log(ClassWriter cw) {
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "log",
                "(Ljava/lang/Object;)V", null, null);
        mv.visitCode();
        mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println",
                "(Ljava/lang/Object;)V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void test(ClassWriter cw) {
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "test",
                "(Ljava/lang/String;)Ljava/lang/String;", null, null);
        mv.visitCode();
        mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println",
                "(Ljava/lang/String;)V", false);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitInsn(ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }
}

