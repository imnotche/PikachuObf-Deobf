package devs.pikachu.deobf;

import org.objectweb.asm.ClassWriter;

/** 入力 JAR から共通の上位型を探す ClassWriter。 */
public final class SafeClassWriter extends ClassWriter {
    private final Hierarchy hierarchy;

    public SafeClassWriter(int flags, Hierarchy hierarchy) {
        super(flags);
        this.hierarchy = hierarchy;
    }

    @Override
    protected String getCommonSuperClass(String type1, String type2) {
        try {
            return hierarchy.commonSuperClass(type1, type2);
        } catch (Throwable ignored) {
            return "java/lang/Object";
        }
    }
}
