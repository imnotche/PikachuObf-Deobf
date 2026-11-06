package devs.pikachu.deobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * PikachuObf がリテラルを変換した式を記号評価する。定数ひとつに書きすぎだろ殺すぞ:
 *   ldc a; ldc b; ldc c; invokestatic Kami(III)I
 *   ldc "payload"; invokestatic Kami(Object)String
 *   ldc "hash"; invokevirtual String.hashCode()I
 * 抽象スタックで式を単一の LDC に戻し、定数オペランドの条件分岐も評価する。
 * 残る到達不能コードは {@link DeadCodeEliminator} で消す。
 */
public final class ConstantFolder {
    private final DeobfContext ctx;
    private int folds;
    private Set<LabelNode> currentTargets;

    public ConstantFolder(DeobfContext ctx) {
        this.ctx = ctx;
    }

    public int apply(ClassNode classNode) {
        folds = 0;
        for (MethodNode method : classNode.methods) {
            if (method.instructions == null || method.instructions.size() == 0) {
                continue;
            }
            removeRedundantGotos(method.instructions);
            removeDupPop(method.instructions);
            processMethod(method, classNode);
        }
        return folds;
    }

    private static Set<LabelNode> collectJumpTargets(MethodNode method) {
        Set<LabelNode> targets = new HashSet<>();
        for (AbstractInsnNode node = method.instructions.getFirst(); node != null; node = node.getNext()) {
            if (node instanceof JumpInsnNode jump) {
                targets.add(jump.label);
            } else if (node instanceof TableSwitchInsnNode table) {
                targets.add(table.dflt);
                targets.addAll(table.labels);
            } else if (node instanceof LookupSwitchInsnNode lookup) {
                targets.add(lookup.dflt);
                targets.addAll(lookup.labels);
            }
        }
        for (org.objectweb.asm.tree.TryCatchBlockNode tcb : method.tryCatchBlocks) {
            targets.add(tcb.handler);
            targets.add(tcb.start);
            targets.add(tcb.end);
        }
        return targets;
    }

    /** 次の実命令に飛ぶ GOTO を除去。 */
    private static void removeRedundantGotos(InsnList list) {
        AbstractInsnNode node = list.getFirst();
        while (node != null) {
            AbstractInsnNode next = node.getNext();
            if (node instanceof JumpInsnNode jump && jump.getOpcode() == Opcodes.GOTO) {
                AbstractInsnNode after = AsmUtil.nextReal(jump);
                AbstractInsnNode target = AsmUtil.nextReal(jump.label);
                if (after != null && after == target) {
                    list.remove(jump);
                }
            }
            node = next;
        }
    }

    /**
     * StringNumberTransformer.visitNegNumber がリテラルに付ける INEG DUP POP のうち、
     * スタックを変えない DUP POP を先に除去し、記号評価を助ける。これで複雑にしたつもりだったらしい。
     */
    private static void removeDupPop(InsnList list) {
        AbstractInsnNode node = list.getFirst();
        while (node != null) {
            AbstractInsnNode next = node.getNext();
            if (node instanceof InsnNode a && next instanceof InsnNode b
                    && ((a.getOpcode() == Opcodes.DUP && b.getOpcode() == Opcodes.POP)
                    || (a.getOpcode() == Opcodes.DUP2 && b.getOpcode() == Opcodes.POP2))) {
                AbstractInsnNode afterPair = b.getNext();
                list.remove(a);
                list.remove(b);
                node = afterPair;
            } else {
                node = next;
            }
        }
    }

    private void processMethod(MethodNode method, ClassNode classNode) {
        Deque<Value> stack = new ArrayDeque<>();
        Map<Integer, Value> locals = new HashMap<>();
        Set<LabelNode> targets = collectJumpTargets(method);
        currentTargets = targets;

        AbstractInsnNode node = method.instructions.getFirst();
        while (node != null) {
            AbstractInsnNode after = node.getNext();

            if (node instanceof LabelNode label) {
                if (targets.contains(label)) {
                    stack.clear();
                    locals.clear();
                }
                node = after;
                continue;
            }
            if (node instanceof org.objectweb.asm.tree.LineNumberNode
                    || node instanceof org.objectweb.asm.tree.FrameNode) {
                node = after;
                continue;
            }

            if (node instanceof LdcInsnNode ldc) {
                push(stack, valueOfConstant(ldc.cst, ldc));
                node = after;
                continue;
            }

            if (node instanceof IntInsnNode ii) {
                switch (ii.getOpcode()) {
                    case Opcodes.BIPUSH:
                    case Opcodes.SIPUSH:
                        push(stack, Value.constant(ii.operand, Kind.INT, ii));
                        break;
                    case Opcodes.NEWARRAY:
                        pop(stack);
                        push(stack, Value.unknown(Kind.REF));
                        break;
                    default:
                        clear(stack);
                }
                node = after;
                continue;
            }

            if (node instanceof VarInsnNode var) {
                handleVar(var, stack, locals);
                if (var.getOpcode() == Opcodes.RET) {
                    stack.clear();
                    locals.clear();
                }
                node = after;
                continue;
            }

            if (node instanceof IincInsnNode iinc) {
                locals.remove(iinc.var);
                node = after;
                continue;
            }

            if (node instanceof TypeInsnNode type) {
                handleType(type, stack);
                node = after;
                continue;
            }

            if (node instanceof FieldInsnNode field) {
                handleField(field, stack);
                node = after;
                continue;
            }

            if (node instanceof MethodInsnNode call) {
                AbstractInsnNode foldedTo = handleMethod(call, stack, method, after);
                if (foldedTo != null) {
                    node = foldedTo;
                    continue;
                }
                node = after;
                continue;
            }

            if (node instanceof InvokeDynamicInsnNode indy) {
                popDiscard(stack, Type.getArgumentTypes(indy.desc));
                Kind kind = kindOf(Type.getReturnType(indy.desc));
                if (kind != Kind.VOID) {
                    push(stack, Value.unknown(kind));
                }
                node = after;
                continue;
            }

            if (node instanceof JumpInsnNode jump) {
                JumpEval eval = evalJump(jump, stack);
                if (eval != null && eval.start != null
                        && isFoldableRange(eval.start, jump, true)) {
                    if (eval.taken) {
                        method.instructions.insertBefore(eval.start, new JumpInsnNode(Opcodes.GOTO, jump.label));
                    }
                    AsmUtil.removeRange(method.instructions, eval.start, jump);
                    folds++;
                    stack.clear();
                    locals.clear();
                    node = after;
                    continue;
                }
                if (jump.getOpcode() == Opcodes.GOTO || jump.getOpcode() == Opcodes.JSR) {
                    stack.clear();
                    locals.clear();
                }
                node = after;
                continue;
            }

            if (node instanceof TableSwitchInsnNode table) {
                Value key = pop(stack);
                if (key.cst instanceof Integer k && key.pure && key.start != null) {
                    LabelNode target = table.dflt;
                    for (int i = 0; i < table.labels.size(); i++) {
                        if (table.min + i == k) {
                            target = table.labels.get(i);
                            break;
                        }
                    }
                    if (isFoldableRange(key.start, table, true)) {
                        method.instructions.insertBefore(key.start, new JumpInsnNode(Opcodes.GOTO, target));
                        AsmUtil.removeRange(method.instructions, key.start, table);
                        folds++;
                    }
                }
                stack.clear();
                locals.clear();
                node = after;
                continue;
            }
            if (node instanceof LookupSwitchInsnNode lookup) {
                Value key = pop(stack);
                if (key.cst instanceof Integer k && key.pure && key.start != null) {
                    LabelNode target = lookup.dflt;
                    for (int i = 0; i < lookup.keys.size(); i++) {
                        if (lookup.keys.get(i) == k) {
                            target = lookup.labels.get(i);
                            break;
                        }
                    }
                    if (isFoldableRange(key.start, lookup, true)) {
                        method.instructions.insertBefore(key.start, new JumpInsnNode(Opcodes.GOTO, target));
                        AsmUtil.removeRange(method.instructions, key.start, lookup);
                        folds++;
                    }
                }
                stack.clear();
                locals.clear();
                node = after;
                continue;
            }

            if (node instanceof MultiANewArrayInsnNode multi) {
                for (int i = 0; i < multi.dims; i++) {
                    pop(stack);
                }
                push(stack, Value.unknown(Kind.REF));
                node = after;
                continue;
            }

            if (node instanceof InsnNode insn) {
                AbstractInsnNode foldedTo = handleInsn(insn, stack, method);
                if (foldedTo != null) {
                    node = foldedTo;
                    continue;
                }
                node = after;
                continue;
            }

            clear(stack);
            node = after;
        }
    }

    private AbstractInsnNode handleInsn(InsnNode insn, Deque<Value> stack, MethodNode method) {
        int op = insn.getOpcode();
        switch (op) {
            case Opcodes.NOP:
                return null;
            case Opcodes.ACONST_NULL:
                push(stack, Value.constant(null, Kind.REF, insn));
                return null;
            case Opcodes.ICONST_M1:
            case Opcodes.ICONST_0:
            case Opcodes.ICONST_1:
            case Opcodes.ICONST_2:
            case Opcodes.ICONST_3:
            case Opcodes.ICONST_4:
            case Opcodes.ICONST_5:
                push(stack, Value.constant(op - Opcodes.ICONST_0, Kind.INT, insn));
                return null;
            case Opcodes.LCONST_0:
            case Opcodes.LCONST_1:
                push(stack, Value.constant((long) (op - Opcodes.LCONST_0), Kind.LONG, insn));
                return null;
            case Opcodes.FCONST_0:
            case Opcodes.FCONST_1:
            case Opcodes.FCONST_2:
                push(stack, Value.constant((float) (op - Opcodes.FCONST_0), Kind.FLOAT, insn));
                return null;
            case Opcodes.DCONST_0:
            case Opcodes.DCONST_1:
                push(stack, Value.constant((double) (op - Opcodes.DCONST_0), Kind.DOUBLE, insn));
                return null;
            case Opcodes.POP:
                pop(stack);
                return null;
            case Opcodes.POP2:
                Value p = pop(stack);
                if (p.kind.size() == 1) {
                    pop(stack);
                }
                return null;
            case Opcodes.DUP: {
                Value v = pop(stack);
                Value shared = v.sharedCopy();
                push(stack, shared);
                push(stack, shared);
                return null;
            }
            case Opcodes.DUP2: {
                Value a = pop(stack);
                if (a.kind.size() == 2) {
                    Value shared = a.sharedCopy();
                    push(stack, shared);
                    push(stack, shared);
                } else {
                    Value b = pop(stack);
                    Value sa = a.sharedCopy();
                    Value sb = b.sharedCopy();
                    push(stack, sb);
                    push(stack, sa);
                    push(stack, sb);
                    push(stack, sa);
                }
                return null;
            }
            case Opcodes.SWAP: {
                Value a = pop(stack);
                Value b = pop(stack);
                push(stack, a.sharedCopy());
                push(stack, b.sharedCopy());
                return null;
            }
            case Opcodes.IALOAD:
            case Opcodes.LALOAD:
            case Opcodes.FALOAD:
            case Opcodes.DALOAD:
            case Opcodes.AALOAD:
            case Opcodes.BALOAD:
            case Opcodes.CALOAD:
            case Opcodes.SALOAD:
                pop(stack);
                pop(stack);
                push(stack, Value.unknown(kindForArrayLoad(op)));
                return null;
            case Opcodes.IASTORE:
            case Opcodes.LASTORE:
            case Opcodes.FASTORE:
            case Opcodes.DASTORE:
            case Opcodes.AASTORE:
            case Opcodes.BASTORE:
            case Opcodes.CASTORE:
            case Opcodes.SASTORE:
                pop(stack);
                pop(stack);
                pop(stack);
                return null;
            case Opcodes.ARRAYLENGTH:
                pop(stack);
                push(stack, Value.unknown(Kind.INT));
                return null;
            case Opcodes.ATHROW:
                pop(stack);
                clear(stack);
                return null;
            case Opcodes.MONITORENTER:
            case Opcodes.MONITOREXIT:
                pop(stack);
                return null;
            case Opcodes.IRETURN:
            case Opcodes.LRETURN:
            case Opcodes.FRETURN:
            case Opcodes.DRETURN:
            case Opcodes.ARETURN:
                pop(stack);
                clear(stack);
                return null;
            case Opcodes.RETURN:
                clear(stack);
                return null;
            case Opcodes.INEG:
            case Opcodes.LNEG:
            case Opcodes.FNEG:
            case Opcodes.DNEG:
                return foldUnary(stack, insn, method, op);
            case Opcodes.I2L:
            case Opcodes.L2I:
            case Opcodes.I2F:
            case Opcodes.F2I:
            case Opcodes.I2D:
            case Opcodes.D2I:
            case Opcodes.L2F:
            case Opcodes.F2L:
            case Opcodes.L2D:
            case Opcodes.D2L:
            case Opcodes.F2D:
            case Opcodes.D2F:
            case Opcodes.I2B:
            case Opcodes.I2C:
            case Opcodes.I2S:
                return foldConvert(stack, insn, method, op);
            case Opcodes.IADD:
            case Opcodes.LADD:
            case Opcodes.FADD:
            case Opcodes.DADD:
            case Opcodes.ISUB:
            case Opcodes.LSUB:
            case Opcodes.FSUB:
            case Opcodes.DSUB:
            case Opcodes.IMUL:
            case Opcodes.LMUL:
            case Opcodes.FMUL:
            case Opcodes.DMUL:
            case Opcodes.IDIV:
            case Opcodes.LDIV:
            case Opcodes.FDIV:
            case Opcodes.DDIV:
            case Opcodes.IREM:
            case Opcodes.LREM:
            case Opcodes.FREM:
            case Opcodes.DREM:
            case Opcodes.ISHL:
            case Opcodes.LSHL:
            case Opcodes.ISHR:
            case Opcodes.LSHR:
            case Opcodes.IUSHR:
            case Opcodes.LUSHR:
            case Opcodes.IAND:
            case Opcodes.LAND:
            case Opcodes.IOR:
            case Opcodes.LOR:
            case Opcodes.IXOR:
            case Opcodes.LXOR:
            case Opcodes.LCMP:
            case Opcodes.FCMPL:
            case Opcodes.FCMPG:
            case Opcodes.DCMPL:
            case Opcodes.DCMPG:
                return foldBinary(stack, insn, method, op);
            default:
                clear(stack);
                return null;
        }
    }

    private AbstractInsnNode foldUnary(Deque<Value> stack, InsnNode insn, MethodNode method, int op) {
        Value a = pop(stack);
        if (a.cst == null || !a.pure || a.start == null) {
            push(stack, Value.unknown(a.kind));
            return null;
        }
        Object result = null;
        Kind kind = a.kind;
        switch (op) {
            case Opcodes.INEG -> result = -(Integer) a.cst;
            case Opcodes.LNEG -> result = -(Long) a.cst;
            case Opcodes.FNEG -> result = -(Float) a.cst;
            case Opcodes.DNEG -> result = -(Double) a.cst;
        }
        Value v = Value.derived(result, kind, a.start, insn, envPure(a), true);
        push(stack, v);
        return foldValue(stack, v, method, insn);
    }

    private AbstractInsnNode foldConvert(Deque<Value> stack, InsnNode insn, MethodNode method, int op) {
        Value a = pop(stack);
        if (a.cst == null || !a.pure || a.start == null) {
            push(stack, Value.unknown(kindOfConversion(op)));
            return null;
        }
        Object result = convert(op, a.cst);
        if (result == null) {
            push(stack, Value.unknown(kindOfConversion(op)));
            return null;
        }
        Value v = Value.derived(result, kindOfConversion(op), a.start, insn, envPure(a), true);
        push(stack, v);
        return foldValue(stack, v, method, insn);
    }

    private AbstractInsnNode foldBinary(Deque<Value> stack, InsnNode insn, MethodNode method, int op) {
        Value b = pop(stack);
        Value a = pop(stack);
        Kind resultKind = kindOfBinary(op);
        if (a.cst == null || b.cst == null || !a.pure || !b.pure || a.start == null || b.start == null) {
            push(stack, Value.unknown(resultKind));
            return null;
        }
        Object result = evalBinary(op, a.cst, b.cst);
        if (result == null) {
            push(stack, Value.unknown(resultKind));
            return null;
        }
        Value v = Value.derived(result, resultKind, a.start, insn, envPure(a) && envPure(b), contiguous(a, b));
        push(stack, v);
        return foldValue(stack, v, method, insn);
    }

    private AbstractInsnNode handleMethod(MethodInsnNode call, Deque<Value> stack, MethodNode method,
                                         AbstractInsnNode after) {
        Type[] args = Type.getArgumentTypes(call.desc);
        Value[] values = popArgs(stack, args);
        boolean receiver = call.getOpcode() != Opcodes.INVOKESTATIC;
        Value receiverValue = receiver ? pop(stack) : null;

        if (AsmUtil.isKami(call)) {
            Value v;
            if ("(Ljava/lang/Object;)Ljava/lang/String;".equals(call.desc)) {
                Value a = values.length == 1 ? values[0] : Value.unknown(Kind.REF);
                if (a.cst instanceof String s) {
                    String decoded = PikaCrypto.decodeKamiString(s);
                    v = Value.derived(decoded, Kind.REF, a.start, call, envPure(a), true);
                    ctx.strings++;
                } else {
                    v = Value.unknown(Kind.REF);
                }
            } else if ("(III)I".equals(call.desc) && values.length == 3
                    && values[0].cst instanceof Integer
                    && values[1].cst instanceof Integer
                    && values[2].cst instanceof Integer) {
                int result = PikaCrypto.kamiInt((Integer) values[0].cst, (Integer) values[1].cst,
                        (Integer) values[2].cst, ctx.kamiResourcePresent);
                v = Value.derived(result, Kind.INT, values[0].start, call,
                        allPure(values), contiguous(values));
                ctx.numbers++;
            } else if ("(JJJ)J".equals(call.desc) && values.length == 3
                    && values[0].cst instanceof Long
                    && values[1].cst instanceof Long
                    && values[2].cst instanceof Long) {
                long result = PikaCrypto.kamiLong((Long) values[0].cst, (Long) values[1].cst,
                        (Long) values[2].cst, ctx.kamiResourcePresent);
                v = Value.derived(result, Kind.LONG, values[0].start, call,
                        allPure(values), contiguous(values));
                ctx.numbers++;
            } else {
                v = Value.unknown(Kind.UNKNOWN);
            }
            push(stack, v);
            AbstractInsnNode folded = foldValue(stack, v, method, call);
            return folded != null ? folded : after;
        }

        if (call.getOpcode() == Opcodes.INVOKEVIRTUAL && "java/lang/String".equals(call.owner)) {
            Value result;
            switch (call.name) {
                case "hashCode" -> {
                    Value a = receiverValue;
                    if (a != null && a.cst instanceof String s) {
                        result = Value.derived(s.hashCode(), Kind.INT, a.start, call, envPure(a), true);
                    } else {
                        result = Value.unknown(Kind.INT);
                    }
                }
                case "length" -> {
                    Value a = receiverValue;
                    if (a != null && a.cst instanceof String s) {
                        result = Value.derived(s.length(), Kind.INT, a.start, call, envPure(a), true);
                    } else {
                        result = Value.unknown(Kind.INT);
                    }
                }
                case "equals" -> {
                    Value a = receiverValue;
                    Value b = values.length == 1 ? values[0] : Value.unknown(Kind.REF);
                    Boolean eq = evalStringEquals(a == null ? null : a.cst, b.cst);
                    if (eq == null || a == null) {
                        result = Value.unknown(Kind.INT);
                    } else {
                        result = Value.derived(eq ? 1 : 0, Kind.INT, a.start, call,
                                envPure(a) && envPure(b), contiguous(a, b));
                    }
                }
                default -> result = Value.unknown(Kind.UNKNOWN);
            }
            push(stack, result);
            AbstractInsnNode folded = foldValue(stack, result, method, call);
            return folded != null ? folded : after;
        }

        if (call.getOpcode() == Opcodes.INVOKESTATIC && "java/lang/Integer".equals(call.owner)
                && "parseInt".equals(call.name) && "(Ljava/lang/String;)I".equals(call.desc)) {
            Value a = values[0];
            if (a.cst instanceof String s) {
                try {
                    int parsed = Integer.parseInt(s);
                    Value v = Value.derived(parsed, Kind.INT, a.start, call, envPure(a), true);
                    push(stack, v);
                    AbstractInsnNode folded = foldValue(stack, v, method, call);
                    return folded != null ? folded : after;
                } catch (NumberFormatException ignored) {
                }
            }
        }

        Kind returnKind = kindOf(Type.getReturnType(call.desc));
        if (returnKind != Kind.VOID) {
            push(stack, Value.unknown(returnKind));
        }
        return after;
    }

    private void handleField(FieldInsnNode field, Deque<Value> stack) {
        switch (field.getOpcode()) {
            case Opcodes.GETSTATIC -> {
                if (AsmUtil.isXsdField(field)) {
                    push(stack, Value.constant(new Xsd(AsmUtil.xsdIndex(field)), Kind.REF, field));
                } else {
                    push(stack, Value.unknown(kindOf(Type.getType(field.desc))));
                }
            }
            case Opcodes.PUTSTATIC -> pop(stack);
            case Opcodes.GETFIELD -> {
                pop(stack);
                push(stack, Value.unknown(kindOf(Type.getType(field.desc))));
            }
            case Opcodes.PUTFIELD -> {
                pop(stack);
                pop(stack);
            }
            default -> {
            }
        }
    }

    private void handleType(TypeInsnNode type, Deque<Value> stack) {
        switch (type.getOpcode()) {
            case Opcodes.NEW -> push(stack, Value.unknown(Kind.REF));
            case Opcodes.ANEWARRAY -> {
                pop(stack);
                push(stack, Value.unknown(Kind.REF));
            }
            case Opcodes.CHECKCAST -> {
                // スタックに変化なし。
            }
            case Opcodes.INSTANCEOF -> {
                pop(stack);
                push(stack, Value.unknown(Kind.INT));
            }
            default -> clear(stack);
        }
    }

    private void handleVar(VarInsnNode var, Deque<Value> stack, Map<Integer, Value> locals) {
        int op = var.getOpcode();
        if (op >= Opcodes.ILOAD && op <= Opcodes.ALOAD) {
            Kind kind = kindForLoad(op);
            Value v = locals.get(var.var);
            if (v != null && v.cst != null) {
                // 格納値の生成式と離れたロードは消せない。同じ値なら消せる、とはいかない。
                push(stack, Value.derived(v.cst, v.kind, null, null, false, false));
            } else {
                push(stack, Value.unknown(kind));
            }
            return;
        }
        if (op >= Opcodes.ISTORE && op <= Opcodes.ASTORE) {
            Value v = pop(stack);
            locals.put(var.var, v);
            return;
        }
    }

    private JumpEval evalJump(JumpInsnNode jump, Deque<Value> stack) {
        int op = jump.getOpcode();
        switch (op) {
            case Opcodes.IFEQ:
            case Opcodes.IFNE:
            case Opcodes.IFLT:
            case Opcodes.IFGE:
            case Opcodes.IFGT:
            case Opcodes.IFLE: {
                Value a = pop(stack);
                if (a.cst instanceof Integer i && a.pure) {
                    return new JumpEval(evalIntCompare(op, i, 0), a.start);
                }
                return null;
            }
            case Opcodes.IF_ICMPEQ:
            case Opcodes.IF_ICMPNE:
            case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE:
            case Opcodes.IF_ICMPGT:
            case Opcodes.IF_ICMPLE: {
                Value b = pop(stack);
                Value a = pop(stack);
                if (a.cst instanceof Integer ai && b.cst instanceof Integer bi && a.pure && b.pure) {
                    return new JumpEval(evalIntCompare(op, ai, bi), a.start);
                }
                return null;
            }
            case Opcodes.IF_ACMPEQ:
            case Opcodes.IF_ACMPNE: {
                Value b = pop(stack);
                Value a = pop(stack);
                boolean aNullConst = a.cst == null && a.start != null && a.pure;
                boolean bNullConst = b.cst == null && b.start != null && b.pure;
                boolean aNonNullConst = a.cst != null && a.start != null && a.pure;
                boolean bNonNullConst = b.cst != null && b.start != null && b.pure;
                if (aNullConst && bNullConst) {
                    return new JumpEval(op == Opcodes.IF_ACMPEQ, a.start);
                }
                if ((aNullConst && bNonNullConst) || (aNonNullConst && bNullConst)) {
                    return new JumpEval(op == Opcodes.IF_ACMPNE, a.start != null ? a.start : b.start);
                }
                return null;
            }
            case Opcodes.IFNULL:
            case Opcodes.IFNONNULL: {
                Value a = pop(stack);
                if (a.pure && a.start != null) {
                    boolean isNull = a.cst == null;
                    return new JumpEval(op == Opcodes.IFNULL ? isNull : !isNull, a.start);
                }
                return null;
            }
            default:
                return null;
        }
    }

    private record JumpEval(boolean taken, AbstractInsnNode start) {
    }

    private static boolean evalIntCompare(int op, int a, int b) {
        return switch (op) {
            case Opcodes.IFEQ, Opcodes.IF_ICMPEQ -> a == b;
            case Opcodes.IFNE, Opcodes.IF_ICMPNE -> a != b;
            case Opcodes.IFLT, Opcodes.IF_ICMPLT -> a < b;
            case Opcodes.IFGE, Opcodes.IF_ICMPGE -> a >= b;
            case Opcodes.IFGT, Opcodes.IF_ICMPGT -> a > b;
            case Opcodes.IFLE, Opcodes.IF_ICMPLE -> a <= b;
            case Opcodes.IF_ACMPEQ -> a == b;
            case Opcodes.IF_ACMPNE -> a != b;
            default -> false;
        };
    }

    private Value pop(Deque<Value> stack) {
        return stack.isEmpty() ? Value.unknown(Kind.UNKNOWN) : stack.removeLast();
    }

    private void push(Deque<Value> stack, Value value) {
        stack.addLast(value);
    }

    private static void clear(Deque<Value> stack) {
        stack.clear();
    }

    private static void popDiscard(Deque<Value> stack, Type[] types) {
        for (int i = types.length - 1; i >= 0; i--) {
            if (!stack.isEmpty()) {
                stack.removeLast();
            }
        }
    }

    private Value[] popArgs(Deque<Value> stack, Type[] types) {
        Value[] values = new Value[types.length];
        for (int i = types.length - 1; i >= 0; i--) {
            values[i] = pop(stack);
        }
        return values;
    }

    private AbstractInsnNode foldValue(Deque<Value> stack, Value v, MethodNode method, AbstractInsnNode end) {
        if (v == null || v.cst == null || !v.pure || v.start == null || v.start == end) {
            return null;
        }
        if (!isFoldableRange(v.start, end, false)) {
            return null;
        }
        AbstractInsnNode after = end.getNext();
        LdcInsnNode replacement = new LdcInsnNode(v.cst);
        method.instructions.insertBefore(v.start, replacement);
        AsmUtil.removeRange(method.instructions, v.start, end);
        // ここから result は置換後の命令を指す。途中で意味が変わる名前、読み返すとつらい。
        if (!stack.isEmpty()) {
            stack.removeLast();
        }
        stack.addLast(Value.constant(v.cst, v.kind, replacement));
        folds++;
        return after;
    }

    private boolean isFoldableRange(AbstractInsnNode start, AbstractInsnNode end, boolean allowEndFlow) {
        if (start == null || end == null) {
            return false;
        }
        AbstractInsnNode n = start;
        while (n != null) {
            if (n instanceof LabelNode label) {
                if (currentTargets != null && !currentTargets.contains(label)) {
                    n = n.getNext();
                    continue;
                }
                return false;
            }
            if (n == end) {
                if (allowEndFlow && (n instanceof JumpInsnNode || n instanceof TableSwitchInsnNode
                        || n instanceof LookupSwitchInsnNode)) {
                    return true;
                }
                return AsmUtil.isPureForRange(n);
            }
            if (!AsmUtil.isPureForRange(n)) {
                return false;
            }
            n = n.getNext();
        }
        return false;
    }

    private static boolean contiguous(Value a, Value b) {
        if (a == null || b == null || a.end == null || b.start == null) {
            return false;
        }
        AbstractInsnNode n = a.end.getNext();
        while (n != null && n != b.start) {
            if (!AsmUtil.isPseudo(n)) {
                return false;
            }
            n = n.getNext();
        }
        return n == b.start;
    }

    private static boolean contiguous(Value[] values) {
        for (int i = 0; i + 1 < values.length; i++) {
            if (!contiguous(values[i], values[i + 1])) {
                return false;
            }
        }
        return true;
    }

    private static boolean allPure(Value[] values) {
        for (Value v : values) {
            if (v == null || !v.pure) {
                return false;
            }
        }
        return true;
    }

    private static boolean envPure(Value v) {
        return v != null && v.pure;
    }

    private static Kind kindForLoad(int op) {
        return switch (op) {
            case Opcodes.ILOAD -> Kind.INT;
            case Opcodes.LLOAD -> Kind.LONG;
            case Opcodes.FLOAD -> Kind.FLOAT;
            case Opcodes.DLOAD -> Kind.DOUBLE;
            case Opcodes.ALOAD -> Kind.REF;
            default -> Kind.UNKNOWN;
        };
    }

    private static Kind kindOfConversion(int op) {
        return switch (op) {
            case Opcodes.I2L, Opcodes.F2L, Opcodes.D2L -> Kind.LONG;
            case Opcodes.L2I, Opcodes.F2I, Opcodes.D2I, Opcodes.I2B, Opcodes.I2C, Opcodes.I2S -> Kind.INT;
            case Opcodes.I2F, Opcodes.L2F, Opcodes.D2F -> Kind.FLOAT;
            case Opcodes.I2D, Opcodes.L2D, Opcodes.F2D -> Kind.DOUBLE;
            default -> Kind.UNKNOWN;
        };
    }

    private static Kind kindOfBinary(int op) {
        return switch (op) {
            case Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IDIV, Opcodes.IREM,
                    Opcodes.ISHL, Opcodes.ISHR, Opcodes.IUSHR, Opcodes.IAND, Opcodes.IOR, Opcodes.IXOR,
                    Opcodes.LCMP, Opcodes.FCMPL, Opcodes.FCMPG, Opcodes.DCMPL, Opcodes.DCMPG -> Kind.INT;
            case Opcodes.LADD, Opcodes.LSUB, Opcodes.LMUL, Opcodes.LDIV, Opcodes.LREM,
                    Opcodes.LSHL, Opcodes.LSHR, Opcodes.LUSHR, Opcodes.LAND, Opcodes.LOR, Opcodes.LXOR -> Kind.LONG;
            case Opcodes.FADD, Opcodes.FSUB, Opcodes.FMUL, Opcodes.FDIV, Opcodes.FREM -> Kind.FLOAT;
            case Opcodes.DADD, Opcodes.DSUB, Opcodes.DMUL, Opcodes.DDIV, Opcodes.DREM -> Kind.DOUBLE;
            default -> Kind.UNKNOWN;
        };
    }

    private static Kind kindForArrayLoad(int op) {
        return switch (op) {
            case Opcodes.LALOAD -> Kind.LONG;
            case Opcodes.FALOAD -> Kind.FLOAT;
            case Opcodes.DALOAD -> Kind.DOUBLE;
            case Opcodes.AALOAD -> Kind.REF;
            default -> Kind.INT;
        };
    }

    private static Object convert(int op, Object v) {
        try {
            if (op == Opcodes.I2L) {
                return ((Integer) v).longValue();
            }
            if (op == Opcodes.L2I) {
                return (int) ((Long) v).longValue();
            }
            if (op == Opcodes.I2F) {
                return (float) ((Integer) v).intValue();
            }
            if (op == Opcodes.F2I) {
                return (int) ((Float) v).floatValue();
            }
            if (op == Opcodes.I2D) {
                return (double) ((Integer) v).intValue();
            }
            if (op == Opcodes.D2I) {
                return (int) ((Double) v).doubleValue();
            }
            if (op == Opcodes.L2F) {
                return (float) ((Long) v).longValue();
            }
            if (op == Opcodes.F2L) {
                return (long) ((Float) v).floatValue();
            }
            if (op == Opcodes.L2D) {
                return (double) ((Long) v).longValue();
            }
            if (op == Opcodes.D2L) {
                return (long) ((Double) v).doubleValue();
            }
            if (op == Opcodes.F2D) {
                return (double) ((Float) v).floatValue();
            }
            if (op == Opcodes.D2F) {
                return (float) ((Double) v).doubleValue();
            }
            if (op == Opcodes.I2B) {
                return (int) (byte) ((Integer) v).intValue();
            }
            if (op == Opcodes.I2C) {
                return (int) (char) ((Integer) v).intValue();
            }
            if (op == Opcodes.I2S) {
                return (int) (short) ((Integer) v).intValue();
            }
            return null;
        } catch (ClassCastException e) {
            return null;
        }
    }

    private static Object evalBinary(int op, Object av, Object bv) {
        try {
            switch (op) {
                case Opcodes.IADD: return (Integer) av + (Integer) bv;
                case Opcodes.ISUB: return (Integer) av - (Integer) bv;
                case Opcodes.IMUL: return (Integer) av * (Integer) bv;
                case Opcodes.IDIV: {
                    int b = (Integer) bv;
                    return b == 0 ? null : (Integer) av / b;
                }
                case Opcodes.IREM: {
                    int b = (Integer) bv;
                    return b == 0 ? null : (Integer) av % b;
                }
                case Opcodes.ISHL: return (Integer) av << ((Integer) bv & 31);
                case Opcodes.ISHR: return (Integer) av >> ((Integer) bv & 31);
                case Opcodes.IUSHR: return (Integer) av >>> ((Integer) bv & 31);
                case Opcodes.IAND: return (Integer) av & (Integer) bv;
                case Opcodes.IOR: return (Integer) av | (Integer) bv;
                case Opcodes.IXOR: return (Integer) av ^ (Integer) bv;

                case Opcodes.LADD: return (Long) av + (Long) bv;
                case Opcodes.LSUB: return (Long) av - (Long) bv;
                case Opcodes.LMUL: return (Long) av * (Long) bv;
                case Opcodes.LDIV: {
                    long b = (Long) bv;
                    return b == 0L ? null : (Long) av / b;
                }
                case Opcodes.LREM: {
                    long b = (Long) bv;
                    return b == 0L ? null : (Long) av % b;
                }
                case Opcodes.LSHL: return (Long) av << ((Integer) bv & 63);
                case Opcodes.LSHR: return (Long) av >> ((Integer) bv & 63);
                case Opcodes.LUSHR: return (Long) av >>> ((Integer) bv & 63);
                case Opcodes.LAND: return (Long) av & (Long) bv;
                case Opcodes.LOR: return (Long) av | (Long) bv;
                case Opcodes.LXOR: return (Long) av ^ (Long) bv;

                case Opcodes.FADD: return (Float) av + (Float) bv;
                case Opcodes.FSUB: return (Float) av - (Float) bv;
                case Opcodes.FMUL: return (Float) av * (Float) bv;
                case Opcodes.FDIV: return (Float) av / (Float) bv;
                case Opcodes.FREM: return (Float) av % (Float) bv;

                case Opcodes.DADD: return (Double) av + (Double) bv;
                case Opcodes.DSUB: return (Double) av - (Double) bv;
                case Opcodes.DMUL: return (Double) av * (Double) bv;
                case Opcodes.DDIV: return (Double) av / (Double) bv;
                case Opcodes.DREM: return (Double) av % (Double) bv;

                case Opcodes.LCMP: return Long.compare((Long) av, (Long) bv);
                case Opcodes.FCMPL: {
                    float a = (Float) av;
                    float b = (Float) bv;
                    return Float.isNaN(a) || Float.isNaN(b) ? -1 : (a < b ? -1 : (a > b ? 1 : 0));
                }
                case Opcodes.FCMPG: {
                    float a = (Float) av;
                    float b = (Float) bv;
                    return Float.isNaN(a) || Float.isNaN(b) ? 1 : (a > b ? 1 : (a < b ? -1 : 0));
                }
                case Opcodes.DCMPL: {
                    double a = (Double) av;
                    double b = (Double) bv;
                    return Double.isNaN(a) || Double.isNaN(b) ? -1 : (a < b ? -1 : (a > b ? 1 : 0));
                }
                case Opcodes.DCMPG: {
                    double a = (Double) av;
                    double b = (Double) bv;
                    return Double.isNaN(a) || Double.isNaN(b) ? 1 : (a > b ? 1 : (a < b ? -1 : 0));
                }
                default: return null;
            }
        } catch (ClassCastException | NullPointerException e) {
            return null;
        }
    }

    private static Boolean evalStringEquals(Object a, Object b) {
        if (a instanceof Xsd xa && b instanceof Xsd xb) {
            return xa.index == xb.index || (xa.index <= 2 && xb.index <= 2);
        }
        if (a instanceof String sa && b instanceof String sb) {
            return sa.equals(sb);
        }
        if (a instanceof Xsd || b instanceof Xsd) {
            return Boolean.FALSE;
        }
        return null;
    }

    private static Value valueOfConstant(Object cst, AbstractInsnNode node) {
        if (cst instanceof Integer i) {
            return Value.constant(i, Kind.INT, node);
        }
        if (cst instanceof Long l) {
            return Value.constant(l, Kind.LONG, node);
        }
        if (cst instanceof Float f) {
            return Value.constant(f, Kind.FLOAT, node);
        }
        if (cst instanceof Double d) {
            return Value.constant(d, Kind.DOUBLE, node);
        }
        if (cst instanceof String s) {
            return Value.constant(s, Kind.REF, node);
        }
        if (cst instanceof Type t) {
            return Value.constant(t, Kind.REF, node);
        }
        if (cst == null) {
            return Value.constant(null, Kind.REF, node);
        }
        return Value.unknown(Kind.REF);
    }

    public static Kind kindOf(Type type) {
        int sort = type.getSort();
        if (sort == Type.VOID) {
            return Kind.VOID;
        }
        if (sort == Type.BOOLEAN || sort == Type.CHAR || sort == Type.BYTE
                || sort == Type.SHORT || sort == Type.INT) {
            return Kind.INT;
        }
        if (sort == Type.LONG) {
            return Kind.LONG;
        }
        if (sort == Type.FLOAT) {
            return Kind.FLOAT;
        }
        if (sort == Type.DOUBLE) {
            return Kind.DOUBLE;
        }
        return Kind.REF;
    }

    public enum Kind {
        INT(1), LONG(2), FLOAT(1), DOUBLE(2), REF(1), VOID(0), UNKNOWN(1);

        final int size;

        Kind(int size) {
            this.size = size;
        }

        int size() {
            return size;
        }
    }

    public static final class Xsd {
        public final int index;

        Xsd(int index) {
            this.index = index;
        }

        @Override
        public String toString() {
            return "PikachuObf.xsd_" + index;
        }
    }

    private static final class Value {
        final Object cst;
        final Kind kind;
        final AbstractInsnNode start;
        final AbstractInsnNode end;
        final boolean pure;
        final boolean shared;

        private Value(Object cst, Kind kind, AbstractInsnNode start, AbstractInsnNode end,
                      boolean pure, boolean shared) {
            this.cst = cst;
            this.kind = kind;
            this.start = start;
            this.end = end;
            this.pure = pure;
            this.shared = shared;
        }

        static Value constant(Object cst, Kind kind, AbstractInsnNode node) {
            return new Value(cst, kind, node, node, true, false);
        }

        static Value unknown(Kind kind) {
            return new Value(null, kind, null, null, false, false);
        }

        static Value derived(Object cst, Kind kind, AbstractInsnNode start, AbstractInsnNode end,
                             boolean pure, boolean contiguous) {
            boolean ok = pure && contiguous && start != null && end != null;
            return new Value(cst, kind, ok ? start : null, ok ? end : null, ok, false);
        }

        Value sharedCopy() {
            return new Value(cst, kind, start, end, false, true);
        }
    }
}

