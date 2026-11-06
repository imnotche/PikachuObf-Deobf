package devs.pikachu.deobf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** 1 回の難読化解除で共有する状態と統計。何を何個消したかくらいは残しておく。 */
public final class DeobfContext {
    public boolean kamiResourcePresent;
    public boolean verbose;
    public boolean keepHelper;
    public boolean forceStripHelper;

    public int classes;
    public int strings;
    public int numbers;
    public int jumps;
    public int indy;
    public int junk;
    public int helperClassesRemoved;
    public int helperClassesStubbed;

    public final List<String> warnings = new ArrayList<>();
    public final Set<String> interfaces = new HashSet<>();
    public final Map<String, byte[]> originalClasses = new HashMap<>();
    public final Map<String, String> classPaths = new HashMap<>();

    public void warn(String message) {
        warnings.add(message);
        if (verbose) {
            System.err.println("[!] " + message);
        }
    }

    public void info(String message) {
        if (verbose) {
            System.out.println("[*] " + message);
        }
    }
}
