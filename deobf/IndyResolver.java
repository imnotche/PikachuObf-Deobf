package devs.pikachu.deobf;

import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PikachuObf の invokedynamic を普通の呼び出しへ戻す。呼び出し先を隠すためによくここまでやったな。
 * 公開ソースのブートストラップは 2 種類:
 * - BROZOZOTOWN(...): 引数に所有クラス名・メソッド名・記述子を保持し、XOR 符号化
 *   （-dontEncode 指定時は平文。符号化しない選択肢は用意してあった）。
 * - invoke(...): クラス初期化子で作る PikachuObf[] 静的配列に実際の呼び出し先を格納。
 *   引数には符号化したクラス名・フィールド名と 2 つのハッシュ断片を持つ。
 */
public final class IndyResolver implements Opcodes {
    private static final String ARRAY_DESC_LONG = "[Ldevs/pikachu/protect/PikachuObf;";
    private static final String ARRAY_DESC_SHORT = "[LPikachuObf;";

    private final Map<String, ClassNode> classes;
    private final DeobfContext ctx;
    private final Hierarchy hierarchy;
    private final Map<String, ArrayInfo> arrays = new HashMap<>();
    private final Set<String> unresolved = new HashSet<>();

    public IndyResolver(Map<String, ClassNode> classes, DeobfContext ctx, Hierarchy hierarchy) {
        this.classes = classes;
        this.ctx = ctx;
        this.hierarchy = hierarchy;
    }

    public int apply() {
        for (ClassNode cn : classes.values()) {
            parseArrays(cn);
        }
        int count = 0;
        for (ClassNode cn : classes.values()) {
            for (MethodNode method : cn.methods) {
                if (method.instructions == null) {
                    continue;
                }
                AbstractInsnNode node = method.instructions.getFirst();
                while (node != null) {
                    AbstractInsnNode next = node.getNext();
                    if (node instanceof InvokeDynamicInsnNode indy) {
                        MethodInsnNode replacement = resolve(cn, indy);
                        if (replacement != null) {
                            method.instructions.set(indy, replacement);
                            count++;
                            ctx.indy++;
                        }
                    }
                    node = next;
                }
            }
        }
        removeResolvedArrays();
        return count;
    }

    private MethodInsnNode resolve(ClassNode current, InvokeDynamicInsnNode indy) {
        Handle bsm = indy.bsm;
        if (bsm == null || !AsmUtil.isPikachuOwner(bsm.getOwner())) {
            return null;
        }
        if ("BROZOZOTOWN".equals(bsm.getName())) {
            return resolveBrozozotown(current, indy);
        }
        if ("invoke".equals(bsm.getName())) {
            return resolveInvoke(current, indy);
        }
        return null;
    }

    private MethodInsnNode resolveBrozozotown(ClassNode current, InvokeDynamicInsnNode indy) {
        Object[] args = indy.bsmArgs;
        if (args == null || args.length < 4) {
            return null;
        }
        String marker;
        String owner;
        String name;
        String desc;
        if (args.length >= 5 && args[0] instanceof String m && args[1] instanceof Integer key
                && args[2] instanceof String o && args[3] instanceof String n && args[4] instanceof String d) {
            marker = m;
            String decodedOwner = PikaCrypto.decodeIndyString(o, key);
            String decodedName = PikaCrypto.decodeIndyString(n, key);
            String decodedDesc = PikaCrypto.decodeIndyString(d, key);
            if (validOwner(decodedOwner) && validName(decodedName) && validDesc(decodedDesc)) {
                owner = decodedOwner;
                name = decodedName;
                desc = decodedDesc;
            } else {
                owner = o;
                name = n;
                desc = d;
            }
        } else if (args.length >= 4 && args[0] instanceof String m
                && args[1] instanceof String o && args[2] instanceof String n && args[3] instanceof String d) {
            marker = m;
            owner = o;
            name = n;
            desc = d;
        } else {
            return null;
        }

        if (!validOwner(owner) || !validName(name) || !validDesc(desc)) {
            ctx.warn("BROZOZOTOWN: could not decode target in " + current.name
                    + " (" + owner + "." + name + desc + ")");
            return null;
        }
        String internalOwner = owner.replace('.', '/');
        boolean isStatic = "SbUwU".equals(marker);
        boolean isInterface = hierarchy.isInterface(internalOwner);
        int opcode = isStatic ? INVOKESTATIC : (isInterface ? INVOKEINTERFACE : INVOKEVIRTUAL);
        return new MethodInsnNode(opcode, internalOwner, name, desc, isInterface);
    }

    private MethodInsnNode resolveInvoke(ClassNode current, InvokeDynamicInsnNode indy) {
        Object[] args = indy.bsmArgs;
        if (args == null || args.length < 4
                || !(args[0] instanceof String encClass)
                || !(args[1] instanceof String encField)
                || !(args[2] instanceof Integer hash3)
                || !(args[3] instanceof Integer hash4)) {
            return null;
        }
        String className = PikaCrypto.decodeSimpleString(encClass);
        String fieldName = PikaCrypto.decodeSimpleString(encField);
        if (!validOwner(className) || !validName(fieldName)) {
            ctx.warn("invoke: could not decode array reference in " + current.name);
            return null;
        }
        String classDotted = className.replace('/', '.');
        String classInternal = classDotted.replace('.', '/');
        ArrayInfo info = arrays.get(arrayKey(classInternal, fieldName));
        if (info == null) {
            info = arrays.get(arrayKey(current.name, fieldName));
            if (info != null) {
                classDotted = current.name.replace('/', '.');
                classInternal = current.name;
            }
        }
        if (info == null) {
            unresolved.add(arrayKey(classInternal, fieldName));
            ctx.warn("invoke: array " + classDotted + "." + fieldName + " was not found");
            return null;
        }
        int index = hash4 ^ hash3 ^ fieldName.hashCode() ^ classDotted.hashCode();
        MethodInfo method = info.entries.get(index);
        if (method == null) {
            unresolved.add(arrayKey(classInternal, fieldName));
            ctx.warn("invoke: no method at index " + index + " in " + classDotted + "." + fieldName);
            return null;
        }
        String owner = method.owner.replace('.', '/');
        boolean isInterface = hierarchy.isInterface(owner);
        int opcode = method.isStatic ? INVOKESTATIC : (isInterface ? INVOKEINTERFACE : INVOKEVIRTUAL);
        return new MethodInsnNode(opcode, owner, method.name, method.desc, isInterface);
    }

    private void parseArrays(ClassNode cn) {
        MethodNode clinit = null;
        for (MethodNode method : cn.methods) {
            if ("<clinit>".equals(method.name)) {
                clinit = method;
                break;
            }
        }
        if (clinit == null || clinit.instructions == null) {
            return;
        }
        for (AbstractInsnNode node = clinit.instructions.getFirst(); node != null; node = node.getNext()) {
            if (!(node instanceof org.objectweb.asm.tree.FieldInsnNode f)
                    || f.getOpcode() != PUTSTATIC
                    || !cn.name.equals(f.owner)
                    || !(ARRAY_DESC_LONG.equals(f.desc) || ARRAY_DESC_SHORT.equals(f.desc))) {
                continue;
            }
            AbstractInsnNode start = findArrayStart(f);
            if (start == null) {
                continue;
            }
            ArrayInfo info = new ArrayInfo(cn, f.name, f.desc, start, f);
            if (parseEntries(info) > 0) {
                arrays.put(arrayKey(cn.name, f.name), info);
            }
        }
    }

    private AbstractInsnNode findArrayStart(org.objectweb.asm.tree.FieldInsnNode putstatic) {
        AbstractInsnNode node = putstatic.getPrevious();
        while (node != null) {
            if (node instanceof TypeInsnNode t && t.getOpcode() == ANEWARRAY
                    && ("PikachuObf".equals(t.desc) || AsmUtil.PIKACHU.equals(t.desc))) {
                AbstractInsnNode prev = AsmUtil.prevReal(node);
                if (prev instanceof LdcInsnNode ldc && ldc.cst instanceof Integer) {
                    return prev;
                }
                return node;
            }
            node = node.getPrevious();
        }
        return null;
    }

    private int parseEntries(ArrayInfo info) {
        int parsed = 0;
        AbstractInsnNode node = info.blockStart;
        while (node != null && node != info.blockEnd) {
            if (!(node instanceof TypeInsnNode wrapper) || wrapper.getOpcode() != NEW
                    || !("PikachuObf".equals(wrapper.desc) || AsmUtil.PIKACHU.equals(wrapper.desc))) {
                node = node.getNext();
                continue;
            }
            AbstractInsnNode indexNode = AsmUtil.prevReal(wrapper);
            if (!(indexNode instanceof LdcInsnNode indexLdc) || !(indexLdc.cst instanceof Integer index)) {
                node = node.getNext();
                continue;
            }
            AbstractInsnNode markerNode = AsmUtil.nextReal(wrapper);
            if (markerNode instanceof InsnNode dup && dup.getOpcode() == DUP) {
                markerNode = AsmUtil.nextReal(markerNode);
            }
            if (!(markerNode instanceof LdcInsnNode markerLdc) || !(markerLdc.cst instanceof String marker)) {
                node = node.getNext();
                continue;
            }
            AbstractInsnNode cursor = AsmUtil.nextReal(markerLdc);
            EncodedPart[] parts = new EncodedPart[3];
            boolean ok = true;
            for (int i = 0; i < 3; i++) {
                if (!(cursor instanceof TypeInsnNode exc) || exc.getOpcode() != NEW) {
                    ok = false;
                    break;
                }
                int line = lineBefore(cursor);
                AbstractInsnNode x = AsmUtil.nextReal(exc);
                if (!(x instanceof InsnNode dup) || dup.getOpcode() != DUP) {
                    ok = false;
                    break;
                }
                x = AsmUtil.nextReal(x);
                if (!(x instanceof LdcInsnNode encLdc) || !(encLdc.cst instanceof String enc)) {
                    ok = false;
                    break;
                }
                x = AsmUtil.nextReal(x);
                if (!(x instanceof MethodInsnNode init) || init.getOpcode() != INVOKESPECIAL
                        || !exc.desc.equals(init.owner) || !"<init>".equals(init.name)
                        || !"(Ljava/lang/String;)V".equals(init.desc)) {
                    ok = false;
                    break;
                }
                parts[i] = new EncodedPart(exc.desc, enc, line);
                cursor = AsmUtil.nextReal(x);
            }
            if (!ok || cursor == null) {
                node = node.getNext();
                continue;
            }
            if (!(cursor instanceof MethodInsnNode ctor) || ctor.getOpcode() != INVOKESPECIAL
                    || !AsmUtil.isPikachuOwner(ctor.owner) || !"<init>".equals(ctor.name)
                    || !"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V".equals(ctor.desc)) {
                node = node.getNext();
                continue;
            }
            String owner = decodePart(parts[0]);
            String name = decodePart(parts[1]);
            String desc = decodePart(parts[2]);
            if (validOwner(owner) && validName(name) && validDesc(desc)) {
                info.entries.put(index, new MethodInfo(owner, name, desc, "SbUwU".equals(marker)));
                parsed++;
            } else {
                ctx.warn("invoke: bad array entry " + index + " in " + info.owner.name + "." + info.fieldName);
            }
            node = AsmUtil.nextReal(cursor);
        }
        return parsed;
    }

    private String decodePart(EncodedPart part) {
        if (part == null) {
            return null;
        }
        String exceptionName = part.exceptionType.replace('/', '.');
        return PikaCrypto.decodeThrowableString(part.encoded, part.line, exceptionName);
    }

    private int lineBefore(AbstractInsnNode node) {
        AbstractInsnNode n = node.getPrevious();
        while (n != null) {
            if (n instanceof LineNumberNode line) {
                return line.line;
            }
            if (n instanceof org.objectweb.asm.tree.LabelNode
                    || n instanceof org.objectweb.asm.tree.FrameNode) {
                n = n.getPrevious();
                continue;
            }
            break;
        }
        return -1;
    }

    private void removeResolvedArrays() {
        for (Map.Entry<String, ArrayInfo> entry : arrays.entrySet()) {
            ArrayInfo info = entry.getValue();
            if (unresolved.contains(entry.getKey())) {
                ctx.warn("keeping " + info.owner.name + "." + info.fieldName
                        + " because some invoke-dynamic call sites could not be resolved");
                continue;
            }
            if (hasDirectFieldReference(info)) {
                ctx.warn("keeping " + info.owner.name + "." + info.fieldName
                        + " because application code reads it directly");
                continue;
            }
            for (Iterator<FieldNode> it = info.owner.fields.iterator(); it.hasNext(); ) {
                FieldNode field = it.next();
                if (field.name.equals(info.fieldName) && field.desc.equals(info.desc)) {
                    it.remove();
                    break;
                }
            }
            MethodNode clinit = null;
            for (MethodNode method : info.owner.methods) {
                if ("<clinit>".equals(method.name)) {
                    clinit = method;
                    break;
                }
            }
            if (clinit != null) {
                AsmUtil.removeRange(clinit.instructions, info.blockStart, info.blockEnd);
                if (clinit.instructions.size() == 0) {
                    clinit.instructions.add(new InsnNode(RETURN));
                }
            }
        }
    }

    private boolean hasDirectFieldReference(ArrayInfo info) {
        for (MethodNode method : info.owner.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode node = method.instructions.getFirst(); node != null; node = node.getNext()) {
                if (node instanceof org.objectweb.asm.tree.FieldInsnNode f
                        && info.owner.name.equals(f.owner)
                        && info.fieldName.equals(f.name)
                        && info.desc.equals(f.desc)) {
                    // このブロックの PUTSTATIC は 1 つ。全部追わずに済むのは助かる。
                    if (node == info.blockEnd) {
                        continue;
                    }
                    return true;
                }
            }
        }
        return false;
    }

    private static String arrayKey(String classInternal, String fieldName) {
        return classInternal + "#" + fieldName;
    }

    private static boolean validOwner(String owner) {
        if (owner == null || owner.isEmpty()) {
            return false;
        }
        if (owner.indexOf('/') < 0 && owner.indexOf('.') < 0) {
            return false;
        }
        return owner.indexOf('[') < 0 && owner.indexOf('(') < 0 && owner.indexOf(')') < 0
                && owner.indexOf(' ') < 0 && owner.indexOf(';') < 0;
    }

    private static boolean validName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isWhitespace(c) || c == '(' || c == ')' || c == ';' || c == '/') {
                return false;
            }
        }
        return true;
    }

    private static boolean validDesc(String desc) {
        return desc != null && desc.startsWith("(") && desc.indexOf(')') > 0;
    }

    private record EncodedPart(String exceptionType, String encoded, int line) {
    }

    private static final class ArrayInfo {
        final ClassNode owner;
        final String fieldName;
        final String desc;
        final AbstractInsnNode blockStart;
        final AbstractInsnNode blockEnd;
        final Map<Integer, MethodInfo> entries = new HashMap<>();

        ArrayInfo(ClassNode owner, String fieldName, String desc,
                  AbstractInsnNode blockStart, AbstractInsnNode blockEnd) {
            this.owner = owner;
            this.fieldName = fieldName;
            this.desc = desc;
            this.blockStart = blockStart;
            this.blockEnd = blockEnd;
        }
    }

    private static final class MethodInfo {
        final String owner;
        final String name;
        final String desc;
        final boolean isStatic;

        MethodInfo(String owner, String name, String desc, boolean isStatic) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
            this.isStatic = isStatic;
        }
    }
}
