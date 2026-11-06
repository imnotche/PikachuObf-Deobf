package devs.pikachu.deobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * アプリをロードせず、最小限の型階層で invokevirtual / invokeinterface を選び、
 * スタックマップフレームを計算する。型を調べたいだけなので、アプリ本体までロードしない。
 */
public final class Hierarchy implements Opcodes {
    private final Map<String, ClassNode> classes;
    private final URLClassLoader loader;
    private final Set<String> interfaceCache = new HashSet<>();

    public Hierarchy(Map<String, ClassNode> classes, URL[] urls) {
        this.classes = classes;
        this.loader = new URLClassLoader(urls, ClassLoader.getSystemClassLoader());
    }

    public void close() {
        try {
            loader.close();
        } catch (Exception ignored) {
        }
    }

    public boolean isInterface(String internalName) {
        if (internalName == null) {
            return false;
        }
        ClassNode cn = classes.get(internalName);
        if (cn != null) {
            return (cn.access & ACC_INTERFACE) != 0;
        }
        if (interfaceCache.contains(internalName)) {
            return true;
        }
        try {
            Class<?> c = Class.forName(internalName.replace('/', '.'), false, loader);
            if (c.isInterface()) {
                interfaceCache.add(internalName);
                return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    public String commonSuperClass(String a, String b) {
        if (a == null || b == null) {
            return "java/lang/Object";
        }
        if (a.equals(b)) {
            return a;
        }
        if ("java/lang/Object".equals(a) || "java/lang/Object".equals(b)) {
            return "java/lang/Object";
        }
        if (a.startsWith("[") || b.startsWith("[")) {
            return arrayCommonSuperClass(a, b);
        }
        if (isAssignableFrom(a, b)) {
            return a;
        }
        if (isAssignableFrom(b, a)) {
            return b;
        }
        if (isInterface(a) || isInterface(b)) {
            return "java/lang/Object";
        }
        String c = getSuperClass(a);
        for (int i = 0; c != null && i < 1000; i++) {
            if (isAssignableFrom(c, b)) {
                return c;
            }
            c = getSuperClass(c);
        }
        return "java/lang/Object";
    }

    private String arrayCommonSuperClass(String a, String b) {
        if (!a.startsWith("[") || !b.startsWith("[")) {
            return "java/lang/Object";
        }
        try {
            Type ta = Type.getType(a);
            Type tb = Type.getType(b);
            if (ta.getSort() != Type.ARRAY || tb.getSort() != Type.ARRAY
                    || ta.getDimensions() != tb.getDimensions()) {
                return "java/lang/Object";
            }
            Type ea = ta.getElementType();
            Type eb = tb.getElementType();
            if (ea.getSort() == Type.OBJECT && eb.getSort() == Type.OBJECT) {
                String common = commonSuperClass(ea.getInternalName(), eb.getInternalName());
                String prefix = "[".repeat(ta.getDimensions());
                return prefix + Type.getObjectType(common).getDescriptor();
            }
        } catch (Throwable ignored) {
        }
        return "java/lang/Object";
    }

    public boolean isAssignableFrom(String target, String source) {
        if (target == null || source == null) {
            return false;
        }
        if (target.equals(source) || "java/lang/Object".equals(target)) {
            return true;
        }
        Set<String> seen = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(source);
        while (!queue.isEmpty()) {
            String current = queue.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            if (target.equals(current)) {
                return true;
            }
            String superName = getSuperClass(current);
            if (superName != null) {
                queue.addLast(superName);
            }
            for (String itf : getInterfaces(current)) {
                queue.addLast(itf);
            }
            if (seen.size() > 2000) {
                break;
            }
        }
        return false;
    }

    private String getSuperClass(String name) {
        ClassNode cn = classes.get(name);
        if (cn != null) {
            return cn.superName;
        }
        try {
            Class<?> c = Class.forName(name.replace('/', '.'), false, loader);
            Class<?> s = c.getSuperclass();
            return s == null ? null : s.getName().replace('.', '/');
        } catch (Throwable ignored) {
            return null;
        }
    }

    private String[] getInterfaces(String name) {
        ClassNode cn = classes.get(name);
        if (cn != null) {
            return cn.interfaces == null ? new String[0] : cn.interfaces.toArray(new String[0]);
        }
        try {
            Class<?> c = Class.forName(name.replace('/', '.'), false, loader);
            Class<?>[] itfs = c.getInterfaces();
            String[] out = new String[itfs.length];
            for (int i = 0; i < itfs.length; i++) {
                out[i] = itfs[i].getName().replace('.', '/');
            }
            return out;
        } catch (Throwable ignored) {
            return new String[0];
        }
    }
}
