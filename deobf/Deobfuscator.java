package devs.pikachu.deobf;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public final class Deobfuscator {
    private static final String VERSION = "1.0";

    public static void main(String[] args) {
        Options options;
        try {
            options = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            printUsage();
            System.exit(2);
            return;
        }
        if (options.help) {
            printUsage();
            return;
        }
        try {
            new Deobfuscator(options).run();
        } catch (Throwable t) {
            System.err.println("deobfuscation failed: " + t);
            if (options.verbose) {
                t.printStackTrace();
            }
            System.exit(1);
        }
    }

    private final Options options;

    private Deobfuscator(Options options) {
        this.options = options;
    }

    private void run() throws Exception {
        Path input = options.input.toAbsolutePath().normalize();
        if (!Files.isRegularFile(input)) {
            throw new IllegalArgumentException("input is not a file: " + input);
        }
        Path output = options.output != null
                ? options.output.toAbsolutePath().normalize()
                : defaultOutput(input);
        if (output.equals(input)) {
        } else if (Files.exists(output) && !options.overwrite) {
            throw new IllegalArgumentException("output already exists (use --overwrite): " + output);
        }
        Files.createDirectories(output.getParent() == null ? input.getParent() : output.getParent());

        DeobfContext ctx = new DeobfContext();
        ctx.verbose = options.verbose;
        ctx.keepHelper = options.keepHelper;
        ctx.forceStripHelper = options.forceStripHelper;

        Map<String, byte[]> resources = new LinkedHashMap<>();
        Map<String, Long> times = new HashMap<>();
        Set<String> handledClassEntries = new HashSet<>();
        Map<String, ClassNode> classes = new LinkedHashMap<>();
        Map<String, byte[]> originalClasses = new HashMap<>();

        readJar(input, ctx, resources, times, handledClassEntries, classes, originalClasses);

        ctx.classes = classes.size();
        ctx.originalClasses.putAll(originalClasses);

        URL[] classpath = buildClasspath(input);
        Hierarchy hierarchy = new Hierarchy(classes, classpath);
        try {
            ctx.info("resolving invoke-dynamic call sites");
            new IndyResolver(classes, ctx, hierarchy).apply();

            ctx.info("folding string/number constants");
            ConstantFolder folder = new ConstantFolder(ctx);
            for (ClassNode cn : new ArrayList<>(classes.values())) {
                folder.apply(cn);
            }

            ctx.info("removing junk trampolines");
            JunkSimplifier junk = new JunkSimplifier(ctx);
            for (ClassNode cn : new ArrayList<>(classes.values())) {
                junk.apply(cn);
            }

            ctx.info("removing unreachable code");
            DeadCodeEliminator dce = new DeadCodeEliminator();
            for (ClassNode cn : new ArrayList<>(classes.values())) {
                dce.apply(cn);
            }

            ctx.info("folding exposed constants");
            for (ClassNode cn : new ArrayList<>(classes.values())) {
                folder.apply(cn);
                junk.apply(cn);
                dce.apply(cn);
            }

            ctx.info("removing synthetic fields");
            FakeFieldRemover fields = new FakeFieldRemover();
            for (ClassNode cn : new ArrayList<>(classes.values())) {
                fields.apply(cn);
            }

            ctx.info("cleaning PikachuObf runtime");
            HelperCleaner helper = new HelperCleaner(classes, ctx);
            helper.apply();

            writeJar(output, classes, originalClasses, resources, times, handledClassEntries,
                    helper.replacements(), hierarchy, ctx);
        } finally {
            hierarchy.close();
        }

        printSummary(input, output, ctx);
        if (options.report != null) {
            writeReport(options.report, input, output, ctx);
        }
    }

    private static Path defaultOutput(Path input) {
        String name = input.getFileName().toString();
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            return input.resolveSibling(name.substring(0, dot) + "-deobf" + name.substring(dot));
        }
        return input.resolveSibling(name + "-deobf.jar");
    }

    private void readJar(Path input, DeobfContext ctx,
                         Map<String, byte[]> resources, Map<String, Long> times,
                         Set<String> handledClassEntries, Map<String, ClassNode> classes,
                         Map<String, byte[]> originalClasses) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(Files.newInputStream(input)))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String rawName = entry.getName();
                byte[] data = readAll(zis);
                String name = normalize(rawName);
                times.putIfAbsent(name, entry.getTime());

                boolean classEntry = name.endsWith(".class");
                boolean multiRelease = rawName.startsWith("META-INF/versions/");
                boolean moduleInfo = name.equals("module-info.class") || name.endsWith("/module-info.class");
                if (!classEntry || multiRelease || moduleInfo) {
                    if (!rawName.endsWith("/") || rawName.endsWith(".class/")) {
                        resources.put(name, data);
                    }
                    continue;
                }

                if (data.length < 4 || data[0] != (byte) 0xCA || data[1] != (byte) 0xFE) {
                    resources.put(name, data);
                    continue;
                }
                try {
                    ClassReader reader = new ClassReader(data);
                    if ((reader.getAccess() & Opcodes.ACC_MODULE) != 0) {
                        resources.put(name, data);
                        continue;
                    }
                    ClassNode cn = new ClassNode();
                    reader.accept(cn, 0);
                    String internal = cn.name + ".class";
                    handledClassEntries.add(name);
                    handledClassEntries.add(internal);
                    if (classes.containsKey(cn.name)) {
                        ctx.warn("duplicate class " + cn.name + " (keeping the last definition)");
                    }
                    classes.put(cn.name, cn);
                    originalClasses.put(cn.name, data);
                } catch (Throwable t) {
                    ctx.warn("could not parse " + name + ": " + t);
                    resources.put(name, data);
                }
            }
        }

        byte[] marker = resources.get("devs/pikachu/protect/PikachuObf.txt");
        if (marker == null) {
            marker = resources.get("PikachuObf.txt");
        }
        ctx.kamiResourcePresent = marker != null
                && new String(marker, StandardCharsets.ISO_8859_1).equals("PikachuObf");
        if (ctx.verbose) {
            ctx.info("Kami resource present: " + ctx.kamiResourcePresent);
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        return in.readAllBytes();
    }

    private static String normalize(String name) {
        if (name.endsWith("/") && name.endsWith(".class/")) {
            return name.substring(0, name.length() - 1);
        }
        return name;
    }

    private URL[] buildClasspath(Path input) throws IOException {
        List<URL> urls = new ArrayList<>();
        urls.add(input.toUri().toURL());
        if (options.classpath != null) {
            for (String part : options.classpath.split(File.pathSeparator)) {
                if (part.isBlank()) {
                    continue;
                }
                Path p = Path.of(part).toAbsolutePath().normalize();
                if (Files.exists(p)) {
                    urls.add(p.toUri().toURL());
                } else if (options.verbose) {
                    System.err.println("[!] classpath entry not found: " + p);
                }
            }
        }
        return urls.toArray(new URL[0]);
    }

    private void writeJar(Path output, Map<String, ClassNode> classes, Map<String, byte[]> originalClasses,
                          Map<String, byte[]> resources, Map<String, Long> times,
                          Set<String> handledClassEntries, Map<String, byte[]> replacements,
                          Hierarchy hierarchy, DeobfContext ctx) throws IOException {
        Path temp = output.resolveSibling(output.getFileName() + ".tmp");
        try (OutputStream fos = new BufferedOutputStream(Files.newOutputStream(temp));
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            zos.setLevel(9);

            // 多くのランチャーが要求するのでマニフェストを先に。順番まで気にする必要があるのか。
            byte[] manifest = resources.get("META-INF/MANIFEST.MF");
            if (manifest != null) {
                writeEntry(zos, "META-INF/MANIFEST.MF", manifest, times.get("META-INF/MANIFEST.MF"));
            }

            Set<String> written = new HashSet<>();
            for (Map.Entry<String, ClassNode> e : classes.entrySet()) {
                String internal = e.getKey();
                byte[] stub = replacements.get(internal);
                if (stub != null) {
                    writeEntry(zos, internal + ".class", stub, times.get(internal + ".class"));
                    written.add(internal + ".class");
                    continue;
                }
                byte[] bytes = writeClass(e.getValue(), originalClasses.get(internal), hierarchy, ctx);
                writeEntry(zos, internal + ".class", bytes, times.get(internal + ".class"));
                written.add(internal + ".class");
            }

            for (Map.Entry<String, byte[]> e : resources.entrySet()) {
                String name = e.getKey();
                if (name.equals("META-INF/MANIFEST.MF")) {
                    continue;
                }
                if (handledClassEntries.contains(name)) {
                    continue;
                }
                if (isSignatureFile(name) || name.equals("META-INF/INDEX.LIST")) {
                    continue;
                }
                if (name.equals("devs/pikachu/protect/PikachuObf.txt")
                        && (replacements.containsKey(AsmUtil.PIKACHU)
                        || replacements.containsKey(AsmUtil.PIKACHU_SHORT)
                        || !classes.containsKey(AsmUtil.PIKACHU)
                        && originalClasses.containsKey(AsmUtil.PIKACHU))) {
                    continue;
                }
                if (written.contains(name)) {
                    continue;
                }
                writeEntry(zos, name, e.getValue(), times.get(name));
                written.add(name);
            }
        } catch (IOException e) {
            try {
                Files.deleteIfExists(temp);
            } catch (IOException ignored) {
            }
            throw e;
        }
        try {
            Files.move(temp, output, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException atomicFailed) {
            Files.move(temp, output, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static byte[] writeClass(ClassNode cn, byte[] original, Hierarchy hierarchy, DeobfContext ctx) {
        for (MethodNode method : cn.methods) {
            if (method.instructions == null) {
                continue;
            }
            org.objectweb.asm.tree.AbstractInsnNode node = method.instructions.getFirst();
            while (node != null) {
                org.objectweb.asm.tree.AbstractInsnNode next = node.getNext();
                if (node instanceof FrameNode) {
                    method.instructions.remove(node);
                }
                node = next;
            }
        }
        try {
            ClassWriter cw = new SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, hierarchy);
            cn.accept(cw);
            return cw.toByteArray();
        } catch (Throwable t) {
            ctx.warn("could not recompute " + cn.name + " (" + t + "); keeping the original class");
            return original;
        }
    }

    private static boolean isSignatureFile(String name) {
        String upper = name.toUpperCase(java.util.Locale.ROOT);
        return upper.startsWith("META-INF/")
                && (upper.endsWith(".SF") || upper.endsWith(".RSA") || upper.endsWith(".DSA")
                || upper.endsWith(".EC") || upper.startsWith("META-INF/SIG-"));
    }

    private static void writeEntry(ZipOutputStream zos, String name, byte[] data, Long time) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        if (time != null && time > 0) {
            entry.setTime(time);
        }
        zos.putNextEntry(entry);
        zos.write(data);
        zos.closeEntry();
    }

    private static void printSummary(Path input, Path output, DeobfContext ctx) {
        System.out.println();
        System.out.println("PikachuObf Deobfuscator " + VERSION);
        System.out.println("  input : " + input);
        System.out.println("  output: " + output);
        System.out.println("  classes: " + ctx.classes);
        System.out.println("  strings decoded: " + ctx.strings);
        System.out.println("  numbers folded: " + ctx.numbers);
        System.out.println("  invoke-dynamic calls rewritten: " + ctx.indy);
        System.out.println("  junk trampolines folded: " + ctx.junk);
        System.out.println("  helper classes removed: " + ctx.helperClassesRemoved);
        System.out.println("  helper classes stubbed: " + ctx.helperClassesStubbed);
        if (!ctx.warnings.isEmpty()) {
            System.out.println("  warnings: " + ctx.warnings.size());
            for (String warning : ctx.warnings) {
                System.out.println("    - " + warning);
            }
        }
        System.out.println("im so sad;;");
        System.out.println();
    }

    private static void writeReport(Path report, Path input, Path output, DeobfContext ctx) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("PikachuObf Deobfuscator ").append(VERSION).append('\n');
        sb.append("input=").append(input).append('\n');
        sb.append("output=").append(output).append('\n');
        sb.append("classes=").append(ctx.classes).append('\n');
        sb.append("strings=").append(ctx.strings).append('\n');
        sb.append("numbers=").append(ctx.numbers).append('\n');
        sb.append("indy=").append(ctx.indy).append('\n');
        sb.append("junk=").append(ctx.junk).append('\n');
        sb.append("helper_removed=").append(ctx.helperClassesRemoved).append('\n');
        sb.append("helper_stubbed=").append(ctx.helperClassesStubbed).append('\n');
        for (String warning : ctx.warnings) {
            sb.append("warning=").append(warning).append('\n');
        }
        Files.writeString(report, sb.toString(), StandardCharsets.UTF_8);
    }

    private static void printUsage() {
        System.out.println("""
                PikachuObf Deobfuscator %s made by original obf developer

                Usage:
                  java -jar PikachuDeobf.jar <input.jar> [output.jar] [options]

                Options:
                  -o, --output <file>       output jar (default: <input>-deobf.jar)
                  --classpath <paths>       extra classpath, separated by %s
                  --overwrite               allow replacing an existing output
                  --keep-helper             keep PikachuObf/BadException instead of stubbing
                  --force-strip-helper      remove the helper even if indy call sites remain
                  -v, --verbose             verbose output
                  --report <file>           write a text report
                  -h, --help                show this help

                The tool reverses:
                  - classToFolder entries (*.class/)
                  - Kami string and number obfuscation
                  - String.hashCode()/reverse literals
                  - BROZOZOTOWN and PikachuObf.invoke invoke-dynamic call sites
                  - junk guards, dead throws and More2Junk trampolines
                  - synthetic BadException fields
                  - the PikachuObf runtime/auth class (stubbed or removed)
                """.formatted(VERSION, File.pathSeparator));
    }

    private static final class Options {
        Path input;
        Path output;
        String classpath;
        boolean overwrite;
        boolean keepHelper;
        boolean forceStripHelper;
        boolean verbose;
        boolean help;
        Path report;

        static Options parse(String[] args) {
            Options o = new Options();
            List<String> positional = new ArrayList<>();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "-h", "--help" -> o.help = true;
                    case "-v", "--verbose" -> o.verbose = true;
                    case "--overwrite" -> o.overwrite = true;
                    case "--keep-helper" -> o.keepHelper = true;
                    case "--force-strip-helper" -> o.forceStripHelper = true;
                    case "-o", "--output" -> {
                        if (++i >= args.length) {
                            throw new IllegalArgumentException(arg + " requires a value");
                        }
                        o.output = Path.of(args[i]);
                    }
                    case "--classpath", "-cp" -> {
                        if (++i >= args.length) {
                            throw new IllegalArgumentException(arg + " requires a value");
                        }
                        o.classpath = o.classpath == null ? args[i] : o.classpath + File.pathSeparator + args[i];
                    }
                    case "--report" -> {
                        if (++i >= args.length) {
                            throw new IllegalArgumentException(arg + " requires a value");
                        }
                        o.report = Path.of(args[i]);
                    }
                    default -> {
                        if (arg.startsWith("-")) {
                            throw new IllegalArgumentException("unknown option: " + arg);
                        }
                        positional.add(arg);
                    }
                }
            }
            if (o.help) {
                return o;
            }
            if (positional.isEmpty()) {
                throw new IllegalArgumentException("no input jar");
            }
            if (positional.size() > 2) {
                throw new IllegalArgumentException("too many positional arguments");
            }
            o.input = Path.of(positional.get(0));
            if (positional.size() == 2) {
                o.output = Path.of(positional.get(1));
            }
            return o;
        }
    }
}
