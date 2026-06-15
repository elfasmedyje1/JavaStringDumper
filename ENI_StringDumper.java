import org.objectweb.asm.*;

import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.jar.*;

public class ENI_StringDumper {

    static long    TIMEOUT_MS = 3000;
    static int     THREADS    = Runtime.getRuntime().availableProcessors();
    static int     MAX_DEPTH  = 10;
    static boolean DO_JSON    = false;
    static boolean DO_PATCH   = true;
    static boolean DO_STUBS   = true;
    static String  OUT_DIR    = null;
    static boolean DO_REEXEC  = true;

    static final Set<String> FLOW_STUB_CLASSES = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private static final Map<Class<?>, Field[]> FIELDS_CACHE = new ConcurrentHashMap<>();
    private static final boolean IS_TERMINAL = System.console() != null;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) { printUsage(); return; }

        List<String> positional = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-json":     DO_JSON   = true;                        break;
                case "-nopatch":  DO_PATCH  = false;                       break;
                case "-nostubs":  DO_STUBS  = false;                       break;
                case "-noreexec": DO_REEXEC = false;                       break;
                case "-timeout":  TIMEOUT_MS = Long.parseLong(args[++i]);  break;
                case "-threads":  THREADS    = Integer.parseInt(args[++i]); break;
                case "-depth":    MAX_DEPTH  = Integer.parseInt(args[++i]); break;
                case "-out":      OUT_DIR    = args[++i];                  break;
                default:          positional.add(args[i]);                 break;
            }
        }

        if (positional.isEmpty()) { printUsage(); return; }

        FLOW_STUB_CLASSES.clear();

        String jarPath     = positional.get(0);
        String triggerSpec = positional.size() > 1 ? positional.get(1) : null;

        File jarFile = new File(jarPath).getAbsoluteFile();
        if (!jarFile.exists()) {
            System.err.println("[-] JAR not found: " + jarPath);
            return;
        }

        System.out.println("[*] Target   : " + jarPath);
        System.out.println("[*] Timeout  : " + TIMEOUT_MS + "ms  Threads: " + THREADS
                + "  Depth: " + MAX_DEPTH + "  Stubs: " + DO_STUBS
                + "  Patch: " + DO_PATCH + "  JSON: " + DO_JSON);
        System.out.println();

        Map<String, byte[]> classBytes = new LinkedHashMap<>();
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")) continue;
                try (InputStream is = jar.getInputStream(entry)) {
                    byte[] bytes = readAllBytes(is);
                    classBytes.put(trueClassName(bytes, entry.getName()), bytes);
                }
            }
            Manifest manifest = jar.getManifest();
            if (manifest != null) {
                String mainClass = manifest.getMainAttributes().getValue("Main-Class");
                if (mainClass != null)
                    System.out.println("[+] Main-Class: " + mainClass + " (not executed)");
            }
        }

        System.out.println("[+] Found " + classBytes.size() + " classes.");

        if (DO_REEXEC) {
            int maxMajor = getMaxClassVersion(classBytes);
            int ourMajor = getRunningJvmMajor();
            if (maxMajor > ourMajor) {
                System.out.println("[!] JAR requires Java " + (maxMajor - 44)
                        + ", running Java " + (ourMajor - 44) + ".");
                String betterJvm = findJvm(maxMajor);
                if (betterJvm != null) {
                    System.out.println("[*] Re-execing with: " + betterJvm);
                    reExec(betterJvm, args);
                    return;
                }
                System.out.println("[!] No compatible JVM found — continuing (expect errors).");
            }
        }

        System.out.println("[*] Analysing classes...");
        Map<String, Set<String>> deps     = new HashMap<>();
        Map<String, StubInfo>    stubNeeds = new ConcurrentHashMap<>();
        combinedAnalysisPass(classBytes, deps, stubNeeds);
        List<String> sortedClasses = topologicalSort(classBytes.keySet(), deps);
        System.out.println("[+] Analysis done. "
                + (DO_STUBS ? stubNeeds.size() + " external refs." : "Stubs disabled.")
                + (FLOW_STUB_CLASSES.isEmpty() ? "" : " " + FLOW_STUB_CLASSES.size() + " flow-obf wrappers."));

        GhostClassLoader loader = new GhostClassLoader(
                new URL[]{jarFile.toURI().toURL()}, classBytes, stubNeeds);

        ExecutorService pool = Executors.newFixedThreadPool(THREADS, r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });

        ConcurrentLinkedQueue<DumpEntry> results  = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<String>    errors   = new ConcurrentLinkedQueue<>();
        Set<String>                      seenLines = Collections.newSetFromMap(new ConcurrentHashMap<>());
        AtomicInteger done = new AtomicInteger(0);

        int classCount = 0, failCount = 0, total = sortedClasses.size();
        System.out.println("[*] Processing " + total + " classes...");

        PrintStream originalErr = System.err;
        System.setErr(new PrintStream(new OutputStream() {
            public void write(int b) {}
            public void write(byte[] b, int off, int len) {}
        }));

        Thread progressThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                int d = done.get(), pct = total > 0 ? d * 100 / total : 100;
                if (IS_TERMINAL)
                    System.out.printf("\r    [%-40s] %d/%d (%d%%)  strings: %d",
                            "=".repeat(pct * 40 / 100), d, total, pct, results.size());
                try { Thread.sleep(150); } catch (InterruptedException e) { break; }
            }
        });
        progressThread.setDaemon(true);
        progressThread.start();

        CompletionService<ClassResult> cs = new ExecutorCompletionService<>(pool);
        for (String className : sortedClasses) {
            final String triggerMethod = (triggerSpec != null && triggerSpec.startsWith(className + "."))
                    ? triggerSpec.substring(className.length() + 1) : null;
            cs.submit(() -> {
                ClassResult r = processClass(loader, className, triggerMethod, results, errors, seenLines);
                done.incrementAndGet();
                return r;
            });
        }

        for (int i = 0; i < total; i++) {
            try {
                Future<ClassResult> f = cs.poll(TIMEOUT_MS, TimeUnit.MILLISECONDS);
                if (f == null) {
                    failCount++;
                    errors.add("[TIMEOUT] poll timed out");
                    continue;
                }
                if (f.get() == ClassResult.FAIL) failCount++; else classCount++;
            } catch (ExecutionException e) {
                failCount++;
                errors.add("[EXEC_FAIL] " + fullCauseChain(e.getCause()));
            }
        }

        pool.shutdownNow();
        pool.awaitTermination(2, TimeUnit.SECONDS);

        progressThread.interrupt();
        if (IS_TERMINAL)
            System.out.printf("\r    [%-40s] %d/%d (100%%)  strings: %d%n",
                    "=".repeat(40), total, total, results.size());
        else
            System.out.printf("    %d/%d (100%%)  strings: %d%n", total, total, results.size());

        System.setErr(originalErr);

        String jarBaseName = jarFile.getName();
        if (jarBaseName.toLowerCase().endsWith(".jar"))
            jarBaseName = jarBaseName.substring(0, jarBaseName.length() - 4);

        File outDir = OUT_DIR != null
                ? new File(OUT_DIR)
                : new File(jarFile.getParentFile(), jarBaseName + "_dump");
        outDir.mkdirs();
        new File(outDir, "packages").mkdirs();

        List<DumpEntry> sorted = new ArrayList<>(results);
        sorted.sort(Comparator.comparing((DumpEntry e) -> e.className).thenComparing(e -> e.source));

        Map<String, List<DumpEntry>> byPackage = new LinkedHashMap<>();
        for (DumpEntry e : sorted)
            byPackage.computeIfAbsent(topLevelPackage(e.className), k -> new ArrayList<>()).add(e);

        for (Map.Entry<String, List<DumpEntry>> pe : byPackage.entrySet()) {
            String pkg = pe.getKey();
            List<DumpEntry> pkgEntries = pe.getValue();
            File pkgFile = new File(outDir, "packages/" + pkg + ".log");
            try (PrintWriter out = openWriter(pkgFile)) {
                out.println("# Package : " + pkg);
                out.println("# Strings : " + pkgEntries.size());
                out.println();
                for (DumpEntry e : pkgEntries)
                    out.println(e.source + " = \"" + escapeLog(e.value) + "\"");
            }
            if (DO_JSON) {
                File pkgJson = new File(outDir, "packages/" + pkg + ".json");
                try (PrintWriter out = openWriter(pkgJson)) {
                    out.println("[");
                    for (int i = 0; i < pkgEntries.size(); i++) {
                        DumpEntry e = pkgEntries.get(i);
                        out.print("  {\"class\":" + jsonStr(e.className)
                                + ",\"field\":" + jsonStr(e.fieldName)
                                + ",\"index\":" + (e.index == null ? "null" : jsonStr(e.index))
                                + ",\"value\":" + jsonStr(e.value) + "}");
                        if (i < pkgEntries.size() - 1) out.print(",");
                        out.println();
                    }
                    out.println("]");
                }
            }
        }

        File allStringsFile = new File(outDir, "all_strings.txt");
        try (PrintWriter out = openWriter(allStringsFile)) {
            for (DumpEntry e : sorted) out.println(escapeLog(e.value));
        }

        List<String> errorList = new ArrayList<>(errors);
        Map<String, Integer> errorTypes = new LinkedHashMap<>();
        for (String line : errorList) {
            String type = line.startsWith("[") ? line.substring(0, line.indexOf(']') + 1) : "[OTHER]";
            errorTypes.merge(type, 1, Integer::sum);
        }

        File errorFile = new File(outDir, "errors.log");
        try (PrintWriter out = openWriter(errorFile)) {
            out.println("# Error summary (" + errorList.size() + " total)");
            errorTypes.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .forEach(e2 -> out.println("#   " + e2.getKey() + " x" + e2.getValue()));
            out.println();
            for (String line : errorList) out.println(line);
        }

        File summaryFile = new File(outDir, "summary.txt");
        try (PrintWriter out = openWriter(summaryFile)) {
            out.println("Target  : " + jarFile.getAbsolutePath());
            out.println("Date    : " + new java.util.Date());
            out.println();
            out.println("Classes processed : " + classCount);
            out.println("Classes failed    : " + failCount);
            out.println("Strings dumped    : " + sorted.size());
            out.println("Packages found    : " + byPackage.size());
            out.println();
            out.println("Settings:");
            out.println("  timeout=" + TIMEOUT_MS + "ms  threads=" + THREADS
                    + "  depth=" + MAX_DEPTH + "  stubs=" + DO_STUBS
                    + "  patch=" + DO_PATCH + "  json=" + DO_JSON);
            out.println();
            out.println("Package breakdown:");
            for (Map.Entry<String, List<DumpEntry>> pe : byPackage.entrySet())
                out.printf("  %-40s %d strings%n", pe.getKey(), pe.getValue().size());
            if (!errorTypes.isEmpty()) {
                out.println();
                out.println("Error breakdown:");
                errorTypes.entrySet().stream()
                        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                        .forEach(e2 -> out.printf("  %-20s x%d%n", e2.getKey(), e2.getValue()));
            }
        }

        System.out.println();
        System.out.println("  Done.");
        System.out.printf("  %-22s %d / %d classes   (%d failed)%n", "Coverage:", classCount, total, failCount);
        System.out.printf("  %-22s %d strings across %d packages%n", "Strings dumped:", sorted.size(), byPackage.size());
        System.out.println();
        System.out.println("  Output: " + outDir.getAbsolutePath());
        System.out.println("    |- all_strings.txt    (" + sorted.size() + " strings)");
        System.out.println("    |- packages/          (" + byPackage.size() + " files)");
        System.out.println("    |- errors.log         (" + errorList.size() + " entries)");
        System.out.println("    |- summary.txt");
        if (!errorTypes.isEmpty()) {
            System.out.println();
            System.out.println("  Top errors:");
            errorTypes.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .limit(4)
                    .forEach(e2 -> System.out.printf("    %-20s x%d%n", e2.getKey(), e2.getValue()));
        }
    }

    static String topLevelPackage(String className) {
        int first = className.indexOf('.');
        if (first < 0) return "(default)";
        int second = className.indexOf('.', first + 1);
        return second < 0 ? className.substring(0, first) : className.substring(0, second);
    }

    static ClassResult processClass(GhostClassLoader loader, String className,
                                    String triggerMethodName,
                                    ConcurrentLinkedQueue<DumpEntry> results,
                                    ConcurrentLinkedQueue<String> errors,
                                    Set<String> seenLines) {
        Class<?> clazz;
        try {
            clazz = loader.loadClass(className);
        } catch (Throwable t) {
            errors.add("[CLASS_FAIL] " + className + " -> " + fullCauseChain(t));
            byte[] bytes = loader.classBytes.get(className);
            if (bytes != null) ldcFallback(bytes, className, results, seenLines);
            return ClassResult.FAIL;
        }

        dumpStaticFields(clazz, className, results, errors, seenLines);
        Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        if (invokeStaticMethods(clazz, className, triggerMethodName, results, errors, seenLines, visited))
            dumpStaticFields(clazz, className, results, errors, seenLines);
        dumpInstanceFields(clazz, className, results, errors, seenLines, visited);
        return ClassResult.OK;
    }

    static void dumpStaticFields(Class<?> clazz, String className,
                                  ConcurrentLinkedQueue<DumpEntry> results,
                                  ConcurrentLinkedQueue<String> errors,
                                  Set<String> seenLines) {
        Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Field f : safeGetFields(clazz, errors, className)) {
            if (!Modifier.isStatic(f.getModifiers())) continue;
            try {
                collectFromObject(f.get(null), className, f.getName(), "", results, seenLines, 0, visited);
            } catch (Throwable t) {
                errors.add("[FIELD_FAIL] " + className + "." + f.getName() + " -> " + fullCauseChain(t));
            }
        }
    }

    static void dumpInstanceFields(Class<?> clazz, String className,
                                    ConcurrentLinkedQueue<DumpEntry> results,
                                    ConcurrentLinkedQueue<String> errors,
                                    Set<String> seenLines, Set<Object> visited) {
        Constructor<?> ctor = null;
        try {
            for (Constructor<?> c : clazz.getDeclaredConstructors()) {
                if (c.getParameterCount() == 0) { ctor = c; break; }
            }
        } catch (Throwable t) { return; }
        if (ctor == null) return;

        Object instance;
        try {
            ctor.setAccessible(true);
            instance = ctor.newInstance();
        } catch (Throwable t) {
            errors.add("[CTOR_FAIL] " + className + " -> " + fullCauseChain(t));
            return;
        }

        for (Field f : safeGetFields(clazz, errors, className)) {
            if (Modifier.isStatic(f.getModifiers())) continue;
            try {
                collectFromObject(f.get(instance), className, f.getName(), "", results, seenLines, 0, visited);
            } catch (Throwable t) {
                errors.add("[INST_FIELD_FAIL] " + className + "." + f.getName() + " -> " + fullCauseChain(t));
            }
        }
    }

    static boolean invokeStaticMethods(Class<?> clazz, String className,
                                       String namedTrigger,
                                       ConcurrentLinkedQueue<DumpEntry> results,
                                       ConcurrentLinkedQueue<String> errors,
                                       Set<String> seenLines, Set<Object> visited) {
        Method[] methods;
        try { methods = clazz.getDeclaredMethods(); } catch (Throwable t) { return false; }

        boolean anyInvoked = false;
        for (Method m : methods) {
            if (!Modifier.isStatic(m.getModifiers()) || m.getParameterCount() != 0) continue;
            String mname = m.getName();
            if (mname.equals("main") || mname.equals("equals") || mname.equals("hashCode")
                    || mname.equals("toString") || mname.equals("clone") || mname.startsWith("lambda$"))
                continue;
            if (namedTrigger != null && !mname.equals(namedTrigger)) continue;
            try {
                m.setAccessible(true);
                Object result = m.invoke(null);
                anyInvoked = true;
                if (result != null)
                    collectFromObject(result, className, mname + "()", "", results, seenLines, 0, visited);
            } catch (Throwable t) {
                errors.add("[INVOKE_FAIL] " + className + "." + mname + "() -> " + fullCauseChain(t));
            }
        }
        return anyInvoked;
    }

    static void collectFromObject(Object obj, String className, String fieldName,
                                   String prefix, ConcurrentLinkedQueue<DumpEntry> results,
                                   Set<String> seenLines, int depth, Set<Object> visited) {
        if (obj == null || depth > MAX_DEPTH) return;

        if (obj instanceof String) {
            if (interesting((String) obj))
                emit(results, seenLines, className, fieldName, prefix.isEmpty() ? null : prefix, (String) obj);
            return;
        }
        if (obj instanceof char[]) {
            char[] arr = (char[]) obj;
            if (interestingImpl(arr.length, i -> arr[i]))
                emit(results, seenLines, className, fieldName, prefix.isEmpty() ? null : prefix, new String(arr));
            return;
        }
        if (obj instanceof byte[]) {
            byte[] bytes = (byte[]) obj;
            if (bytes.length >= 3 && bytes.length < 50000 && isLikelyText(bytes)) {
                try {
                    String s = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                    if (interesting(s))
                        emit(results, seenLines, className, fieldName, prefix.isEmpty() ? null : prefix, s);
                } catch (Throwable ignored) {}
            }
            return;
        }

        if (!visited.add(obj)) return;

        if (obj.getClass().isArray()) {
            int len = Array.getLength(obj);
            for (int i = 0; i < len; i++)
                collectFromObject(Array.get(obj, i), className, fieldName,
                        prefix + '[' + i + ']', results, seenLines, depth + 1, visited);
            return;
        }
        if (obj instanceof Map<?, ?>) {
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) obj).entrySet()) {
                String k = entry.getKey() != null ? entry.getKey().toString() : "null";
                collectFromObject(entry.getKey(), className, fieldName,
                        prefix + "[key:" + k + ']', results, seenLines, depth + 1, visited);
                collectFromObject(entry.getValue(), className, fieldName,
                        prefix + '[' + k + ']', results, seenLines, depth + 1, visited);
            }
            return;
        }
        if (obj instanceof Iterable<?>) {
            int i = 0;
            for (Object item : (Iterable<?>) obj)
                collectFromObject(item, className, fieldName,
                        prefix + '[' + i++ + ']', results, seenLines, depth + 1, visited);
            return;
        }
        if (depth < MAX_DEPTH - 1) {
            for (Field f : cachedFields(obj.getClass())) {
                if (Modifier.isStatic(f.getModifiers())) continue;
                try {
                    collectFromObject(f.get(obj), className, fieldName,
                            prefix + '.' + f.getName(), results, seenLines, depth + 1, visited);
                } catch (Throwable ignored) {}
            }
        }
    }

    static void emit(ConcurrentLinkedQueue<DumpEntry> results, Set<String> seenLines,
                     String className, String fieldName, String index, String value) {
        if (seenLines.add(className + "." + fieldName + (index != null ? index : "") + "=" + value))
            results.add(new DumpEntry(className, fieldName, index, value));
    }

    static void combinedAnalysisPass(Map<String, byte[]> classBytes,
                                      Map<String, Set<String>> deps,
                                      Map<String, StubInfo> stubNeeds) {
        final Set<String> internal = new HashSet<>(classBytes.keySet());
        final Set<String> internalSlash = new HashSet<>(internal.size());
        for (String n : internal) internalSlash.add(n.replace('.', '/'));

        for (Map.Entry<String, byte[]> entry : classBytes.entrySet()) {
            final String name = entry.getKey();
            final Set<String> myDeps = new HashSet<>();
            deps.put(name, myDeps);

            final int[]     methodCount   = {0};
            final boolean[] hasTimingCall = {false};

            try {
                new ClassReader(entry.getValue()).accept(new ClassVisitor(Opcodes.ASM9) {
                    @Override
                    public void visit(int version, int access, String cname,
                                      String signature, String superName, String[] interfaces) {
                        if (!DO_STUBS) return;
                        if (interfaces != null) {
                            for (String iface : interfaces) {
                                if (!internalSlash.contains(iface)) {
                                    String ifaceDot = iface.replace('/', '.');
                                    if (!isJdkClass(ifaceDot)) {
                                        StubInfo info = stubNeeds.computeIfAbsent(ifaceDot, k -> new StubInfo(k, true));
                                        info.isInterface = true;
                                    }
                                }
                            }
                        }
                        if (superName != null && !superName.equals("java/lang/Object")
                                && !internalSlash.contains(superName)) {
                            String superDot = superName.replace('/', '.');
                            if (!isJdkClass(superDot))
                                stubNeeds.computeIfAbsent(superDot, k -> new StubInfo(k, false));
                        }
                    }

                    @Override
                    public MethodVisitor visitMethod(int access, String mname,
                                                     String desc, String sig, String[] exc) {
                        methodCount[0]++;
                        return new MethodVisitor(Opcodes.ASM9) {
                            @Override
                            public void visitFieldInsn(int opcode, String owner, String fname, String fdesc) {
                                if (internalSlash.contains(owner) && !owner.equals(name.replace('.', '/'))) {
                                    if (opcode == Opcodes.GETSTATIC) myDeps.add(owner.replace('/', '.'));
                                } else if (DO_STUBS && !internalSlash.contains(owner)) {
                                    String ownerDot = owner.replace('/', '.');
                                    if (!isJdkClass(ownerDot))
                                        stubNeeds.computeIfAbsent(ownerDot, k -> new StubInfo(k, false));
                                }
                            }

                            @Override
                            public void visitMethodInsn(int opcode, String owner, String mname2,
                                                        String descriptor, boolean isInterface) {
                                if ((owner.equals("java/lang/System")
                                        && (mname2.equals("nanoTime") || mname2.equals("currentTimeMillis")))
                                        || (owner.equals("sun/reflect/Reflection") && mname2.equals("getCallerClass"))
                                        || (owner.equals("java/lang/Thread") && mname2.equals("getStackTrace")))
                                    hasTimingCall[0] = true;

                                if (!DO_STUBS || internalSlash.contains(owner)) return;
                                String ownerDot = owner.replace('/', '.');
                                if (isJdkClass(ownerDot)) return;
                                boolean iface = isInterface || opcode == Opcodes.INVOKEINTERFACE;
                                StubInfo info = stubNeeds.computeIfAbsent(ownerDot, k -> new StubInfo(k, iface));
                                if (iface) info.isInterface = true;
                                info.methods.add(new MethodRef(mname2, descriptor, opcode == Opcodes.INVOKESTATIC));
                            }
                        };
                    }
                }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);

                if (hasTimingCall[0] && methodCount[0] <= 8 && entry.getValue().length < 3000)
                    FLOW_STUB_CLASSES.add(name);

            } catch (Throwable ignored) {}
        }
    }

    static List<String> topologicalSort(Set<String> nodes, Map<String, Set<String>> deps) {
        Map<String, Integer>    inDegree = new HashMap<>(nodes.size());
        Map<String, Set<String>> revDeps = new HashMap<>(nodes.size());
        for (String n : nodes) inDegree.put(n, 0);

        for (Map.Entry<String, Set<String>> e : deps.entrySet()) {
            String a = e.getKey();
            for (String b : e.getValue()) {
                if (!nodes.contains(b)) continue;
                revDeps.computeIfAbsent(b, k -> new HashSet<>()).add(a);
                inDegree.merge(a, 1, Integer::sum);
            }
        }

        Queue<String> queue = new ArrayDeque<>();
        for (Map.Entry<String, Integer> e : inDegree.entrySet())
            if (e.getValue() == 0) queue.add(e.getKey());

        List<String> result = new ArrayList<>(nodes.size());
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            result.add(cur);
            Set<String> dependents = revDeps.get(cur);
            if (dependents != null)
                for (String dep : dependents)
                    if (inDegree.merge(dep, -1, Integer::sum) == 0) queue.add(dep);
        }

        if (result.size() < nodes.size()) {
            Set<String> emitted = new HashSet<>(result);
            for (String n : nodes) if (!emitted.contains(n)) result.add(n);
        }
        return result;
    }

    static int countArgSlots(String descriptor, boolean hasThis) {
        int slots = hasThis ? 1 : 0;
        for (org.objectweb.asm.Type t : org.objectweb.asm.Type.getArgumentTypes(descriptor)) slots += t.getSize();
        return slots;
    }

    static boolean isJdkClass(String name) {
        if (name.isEmpty()) return false;
        switch (name.charAt(0)) {
            case 'j': return name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("jdk.");
            case 's': return name.startsWith("sun.");
            case 'c': return name.startsWith("com.sun.");
            case 'o': return name.startsWith("org.xml.") || name.startsWith("org.w3c.");
            default:  return false;
        }
    }

    static void emitZeroReturn(MethodVisitor mv, String ret, String descriptor, int opcode) {
        int slots = countArgSlots(descriptor, opcode != Opcodes.INVOKESTATIC);
        for (int i = 0; i < slots; i++) mv.visitInsn(Opcodes.POP);
        switch (ret) {
            case "V":                                        break;
            case "J": mv.visitInsn(Opcodes.LCONST_0);      break;
            case "D": mv.visitInsn(Opcodes.DCONST_0);      break;
            case "F": mv.visitInsn(Opcodes.FCONST_0);      break;
            case "I": case "Z": case "B": case "C": case "S":
                      mv.visitInsn(Opcodes.ICONST_0);       break;
            default:  mv.visitInsn(Opcodes.ACONST_NULL);   break;
        }
    }

    static byte[] patchAntiAnalysis(byte[] classBytes) {
        try {
            ClassReader cr = new ClassReader(classBytes);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                  String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitMethodInsn(int opcode, String owner, String mname,
                                                    String descriptor, boolean isInterface) {
                            if (owner.equals("sun/reflect/Reflection") && mname.equals("getCallerClass")) {
                                super.visitInsn(Opcodes.ACONST_NULL); return;
                            }
                            if (owner.equals("java/lang/Thread") && mname.equals("getStackTrace")) {
                                super.visitInsn(Opcodes.POP);
                                super.visitInsn(Opcodes.ICONST_0);
                                super.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/StackTraceElement"); return;
                            }
                            if (owner.equals("java/lang/Thread") && mname.equals("currentThread")) {
                                super.visitInsn(Opcodes.ACONST_NULL); return;
                            }
                            if (owner.equals("java/lang/System") && mname.equals("currentTimeMillis")) {
                                super.visitLdcInsn(1000L); return;
                            }
                            if (owner.equals("java/lang/System") && mname.equals("nanoTime")) {
                                super.visitLdcInsn(1000000L); return;
                            }
                            if ((owner.equals("sun/misc/Unsafe") || owner.equals("jdk/internal/misc/Unsafe"))
                                    && (mname.startsWith("put") || mname.startsWith("get")
                                        || mname.startsWith("compare") || mname.equals("allocateMemory")
                                        || mname.equals("freeMemory") || mname.equals("setMemory")
                                        || mname.equals("copyMemory") || mname.equals("ensureClassInitialized"))) {
                                emitZeroReturn(this, descriptor.substring(descriptor.lastIndexOf(')') + 1), descriptor, opcode);
                                return;
                            }
                            if (owner.equals("java/lang/System")
                                    && (mname.equals("load") || mname.equals("loadLibrary"))) {
                                super.visitInsn(Opcodes.POP); return;
                            }
                            if (owner.equals("java/lang/Runtime")
                                    && (mname.equals("load") || mname.equals("loadLibrary"))) {
                                super.visitInsn(Opcodes.POP); super.visitInsn(Opcodes.POP); return;
                            }
                            if (owner.equals("java/lang/StackWalker")) {
                                super.visitInsn(Opcodes.ACONST_NULL); return;
                            }
                            if (owner.equals("native0/Loader") && mname.equals("registerNativesForClass")) {
                                super.visitInsn(Opcodes.POP); super.visitInsn(Opcodes.POP); return;
                            }
                            if (owner.equals("native0/hidden/Hidden0") && mname.startsWith("special_clinit_")) {
                                super.visitInsn(Opcodes.POP); return;
                            }
                            if (FLOW_STUB_CLASSES.contains(owner.replace('/', '.'))) {
                                emitZeroReturn(this, descriptor.substring(descriptor.lastIndexOf(')') + 1), descriptor, opcode);
                                return;
                            }
                            super.visitMethodInsn(opcode, owner, mname, descriptor, isInterface);
                        }
                    };
                }
            }, ClassReader.EXPAND_FRAMES);
            return cw.toByteArray();
        } catch (Throwable t) {
            return classBytes;
        }
    }

    static class GhostClassLoader extends URLClassLoader {
        final Map<String, byte[]>  classBytes;
        private final Map<String, StubInfo>  stubNeeds;
        private final ConcurrentHashMap<String, Class<?>> defined = new ConcurrentHashMap<>();

        GhostClassLoader(URL[] urls, Map<String, byte[]> classBytes, Map<String, StubInfo> stubNeeds) {
            super(urls, null);
            this.classBytes = classBytes;
            this.stubNeeds  = stubNeeds;
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            Class<?> cached = defined.get(name);
            if (cached != null) return cached;
            if (isBootClass(name)) return getSystemClassLoader().loadClass(name);
            if (name.startsWith("native0."))
                return loadFromBytes(name, generateStub(stubNeeds.getOrDefault(name, new StubInfo(name, false))), resolve);
            if (classBytes.containsKey(name))
                return loadFromBytes(name, classBytes.get(name), resolve);
            if (DO_STUBS)
                return loadFromBytes(name, generateStub(stubNeeds.getOrDefault(name, new StubInfo(name, false))), resolve);
            throw new ClassNotFoundException(name);
        }

        private Class<?> loadFromBytes(String name, byte[] bytes, boolean resolve) {
            return defined.computeIfAbsent(name, k -> {
                byte[] patched = DO_PATCH ? patchAntiAnalysis(bytes) : bytes;
                try {
                    Class<?> clazz = defineClass(k, patched, 0, patched.length);
                    if (resolve) resolveClass(clazz);
                    return clazz;
                } catch (Throwable t) {
                    if (DO_PATCH && patched != bytes) {
                        try {
                            Class<?> clazz = defineClass(k, bytes, 0, bytes.length);
                            if (resolve) resolveClass(clazz);
                            return clazz;
                        } catch (Throwable t2) {
                            throw new RuntimeException("defineClass failed for " + k, t2);
                        }
                    }
                    throw new RuntimeException("defineClass failed for " + k, t);
                }
            });
        }

        private static boolean isBootClass(String name) {
            return name.startsWith("java.") || name.startsWith("javax.")
                    || name.startsWith("sun.") || name.startsWith("com.sun.")
                    || name.startsWith("jdk.") || name.startsWith("org.xml.")
                    || name.startsWith("org.w3c.");
        }
    }

    static byte[] generateStub(StubInfo info) {
        String internalName = info.className.replace('.', '/');
        ClassWriter cw = new ClassWriter(0);
        int classAccess = info.isInterface
                ? Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE
                : Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        cw.visit(Opcodes.V1_8, classAccess, internalName, null, "java/lang/Object", null);

        if (!info.isInterface) {
            MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
            mv.visitCode();
            mv.visitVarInsn(Opcodes.ALOAD, 0);
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
            mv.visitInsn(Opcodes.RETURN);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
        }

        Set<String> added = new HashSet<>();
        for (MethodRef mref : info.methods) {
            if (mref.name.equals("<init>") || mref.name.equals("<clinit>")) continue;
            if (!added.add(mref.name + mref.descriptor + mref.isStatic)) continue;

            int mAccess = Opcodes.ACC_PUBLIC;
            if (mref.isStatic)    mAccess |= Opcodes.ACC_STATIC;
            if (info.isInterface) mAccess |= Opcodes.ACC_ABSTRACT;

            MethodVisitor mv = cw.visitMethod(mAccess, mref.name, mref.descriptor, null, null);
            if (!info.isInterface) {
                mv.visitCode();
                String ret = mref.descriptor.substring(mref.descriptor.lastIndexOf(')') + 1);
                int loc = mref.isStatic ? 0 : 1;
                switch (ret) {
                    case "V":
                        mv.visitInsn(Opcodes.RETURN);       mv.visitMaxs(0, loc); break;
                    case "Z": case "B": case "C": case "S": case "I":
                        mv.visitInsn(Opcodes.ICONST_0);
                        mv.visitInsn(Opcodes.IRETURN);      mv.visitMaxs(1, loc); break;
                    case "J":
                        mv.visitInsn(Opcodes.LCONST_0);
                        mv.visitInsn(Opcodes.LRETURN);      mv.visitMaxs(2, loc); break;
                    case "F":
                        mv.visitInsn(Opcodes.FCONST_0);
                        mv.visitInsn(Opcodes.FRETURN);      mv.visitMaxs(1, loc); break;
                    case "D":
                        mv.visitInsn(Opcodes.DCONST_0);
                        mv.visitInsn(Opcodes.DRETURN);      mv.visitMaxs(2, loc); break;
                    default:
                        mv.visitInsn(Opcodes.ACONST_NULL);
                        mv.visitInsn(Opcodes.ARETURN);      mv.visitMaxs(1, loc); break;
                }
            }
            mv.visitEnd();
        }
        cw.visitEnd();
        return cw.toByteArray();
    }

    enum ClassResult { OK, FAIL }

    static class DumpEntry {
        final String className, fieldName, index, value, source;
        DumpEntry(String className, String fieldName, String index, String value) {
            this.className = className;
            this.fieldName = fieldName;
            this.index     = index;
            this.value     = value;
            this.source    = className + "." + fieldName + (index != null ? index : "");
        }
    }

    static class StubInfo {
        String className;
        boolean isInterface;
        Set<MethodRef> methods = new LinkedHashSet<>();
        StubInfo(String className, boolean isInterface) {
            this.className   = className;
            this.isInterface = isInterface;
        }
    }

    static class MethodRef {
        final String name, descriptor;
        final boolean isStatic;
        MethodRef(String name, String descriptor, boolean isStatic) {
            this.name = name; this.descriptor = descriptor; this.isStatic = isStatic;
        }
        @Override public boolean equals(Object o) {
            if (!(o instanceof MethodRef)) return false;
            MethodRef r = (MethodRef) o;
            return isStatic == r.isStatic && name.equals(r.name) && descriptor.equals(r.descriptor);
        }
        @Override public int hashCode() {
            return (name.hashCode() * 31 + descriptor.hashCode()) * 31 + Boolean.hashCode(isStatic);
        }
    }

    static Field[] cachedFields(Class<?> clazz) {
        return FIELDS_CACHE.computeIfAbsent(clazz, c -> {
            try {
                Field[] fields = c.getDeclaredFields();
                AccessibleObject.setAccessible(fields, true);
                return fields;
            } catch (Throwable t) { return new Field[0]; }
        });
    }

    static Field[] safeGetFields(Class<?> clazz, ConcurrentLinkedQueue<String> errors, String className) {
        try {
            return cachedFields(clazz);
        } catch (Throwable t) {
            errors.add("[FIELDS_FAIL] " + className + " -> " + fullCauseChain(t));
            return new Field[0];
        }
    }

    private interface CharAt { char get(int i); }

    private static boolean interestingImpl(int len, CharAt fn) {
        if (len < 3) return false;
        int ctrl = 0, highByte = 0, printableAscii = 0;
        for (int i = 0; i < len; i++) {
            char c = fn.get(i);
            if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') ctrl++;
            else if (c > 0x7e) highByte++;
            else printableAscii++;
        }
        return ctrl / (double) len < 0.15 && highByte / (double) len <= 0.40 && printableAscii >= 3;
    }

    static boolean interesting(String s) {
        return s != null && interestingImpl(s.length(), s::charAt);
    }

    static boolean interestingChars(char[] arr) {
        return arr != null && interestingImpl(arr.length, i -> arr[i]);
    }

    static boolean isLikelyText(byte[] bytes) {
        int printable = 0, limit = Math.min(bytes.length, 256);
        for (int i = 0; i < limit; i++) {
            byte b = bytes[i];
            if (b == 0) return false;
            if ((b >= 0x20 && b <= 0x7E) || b == '\n' || b == '\r' || b == '\t') printable++;
        }
        return printable / (double) limit > 0.70;
    }

    static String escapeLog(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0, len = s.length(); i < len; i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:   sb.append(c);
            }
        }
        return sb.toString();
    }

    static String jsonStr(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append("\\u");
                        sb.append(Character.forDigit((c >> 12) & 0xF, 16));
                        sb.append(Character.forDigit((c >>  8) & 0xF, 16));
                        sb.append(Character.forDigit((c >>  4) & 0xF, 16));
                        sb.append(Character.forDigit( c        & 0xF, 16));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    static String fullCauseChain(Throwable t) {
        if (t == null) return "(null)";
        StringBuilder sb = new StringBuilder();
        for (Throwable cur = t; cur != null; cur = cur.getCause()) {
            if (sb.length() > 0) sb.append(" <- ");
            sb.append(cur.getClass().getName());
            if (cur.getMessage() != null) sb.append(": ").append(cur.getMessage());
        }
        return sb.toString();
    }

    static void ldcFallback(byte[] bytes, String className,
                             ConcurrentLinkedQueue<DumpEntry> results, Set<String> seenLines) {
        try {
            new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String mname,
                                                  String desc, String sig, String[] exc) {
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitLdcInsn(Object cst) {
                            if (cst instanceof String && interesting((String) cst))
                                emit(results, seenLines, className, "[ldc:" + mname + "]", null, (String) cst);
                        }
                    };
                }
            }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
        } catch (Throwable ignored) {}
    }

    static int getMaxClassVersion(Map<String, byte[]> classBytes) {
        int max = 0;
        for (byte[] b : classBytes.values()) {
            if (b.length < 8) continue;
            int major = ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);
            if (major > max) max = major;
        }
        return max;
    }

    static int getRunningJvmMajor() {
        try { return (int) Double.parseDouble(System.getProperty("java.class.version", "52.0")); }
        catch (NumberFormatException e) { return 52; }
    }

    static String findJvm(int neededMajor) {
        List<String> roots = new ArrayList<>(Arrays.asList(
                System.getenv("JAVA_HOME"),
                System.getProperty("java.home"),
                "C:\\Program Files\\Java",
                "C:\\Program Files\\Eclipse Adoptium",
                "C:\\Program Files\\BellSoft",
                "C:\\Program Files\\Microsoft",
                "C:\\Program Files\\Zulu",
                "C:\\Program Files\\Amazon Corretto",
                "C:\\Program Files\\Semeru",
                "/usr/lib/jvm",
                "/usr/local/lib/jvm",
                System.getProperty("user.home") + "/.jdks",
                System.getProperty("user.home") + "/.sdkman/candidates/java"
        ));
        for (String root : roots) {
            if (root == null) continue;
            File dir = new File(root);
            if (!dir.isDirectory()) continue;
            String found = searchDirForJvm(dir, neededMajor, 2);
            if (found != null) return found;
        }
        return null;
    }

    static String searchDirForJvm(File dir, int neededMajor, int depth) {
        if (depth < 0) return null;
        for (String exec : new String[]{"bin/java", "bin/java.exe"}) {
            File javaExec = new File(dir, exec);
            if (javaExec.isFile() && javaExec.canExecute() && probeJvmVersion(javaExec.getAbsolutePath()) >= neededMajor)
                return javaExec.getAbsolutePath();
        }
        File[] children = dir.listFiles();
        if (children == null) return null;
        for (File child : children) {
            if (!child.isDirectory()) continue;
            String found = searchDirForJvm(child, neededMajor, depth - 1);
            if (found != null) return found;
        }
        return null;
    }

    static int probeJvmVersion(String javaPath) {
        try {
            Process p = new ProcessBuilder(javaPath, "-version").redirectErrorStream(true).start();
            final byte[][] out = {null};
            Thread drain = new Thread(() -> {
                try { out[0] = readAllBytes(p.getInputStream()); } catch (Exception ignored) {}
            });
            drain.setDaemon(true);
            drain.start();
            p.waitFor(5, TimeUnit.SECONDS);
            drain.join(1000);
            if (out[0] == null) return 0;
            String output = new String(out[0]);
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("version \"(\\d+)(?:\\.(\\d+))?").matcher(output);
            if (m.find()) {
                int major = Integer.parseInt(m.group(1));
                if (major == 1 && m.group(2) != null) major = Integer.parseInt(m.group(2));
                return major >= 8 ? major + 44 : 52;
            }
        } catch (Throwable ignored) {}
        return 0;
    }

    static void reExec(String javaPath, String[] originalArgs) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(javaPath);
        cmd.add("-cp");
        cmd.add(System.getProperty("java.class.path", "."));
        cmd.add("ENI_StringDumper");
        cmd.add("-noreexec");
        cmd.addAll(Arrays.asList(originalArgs));
        Process p = new ProcessBuilder(cmd).inheritIO().start();
        p.waitFor();
        System.exit(p.exitValue());
    }

    static PrintWriter openWriter(File f) throws IOException {
        return new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(f), java.nio.charset.StandardCharsets.UTF_8));
    }

    static byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[8192];
        int n;
        while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
        return buf.toByteArray();
    }

    static String trueClassName(byte[] bytes, String entryPath) {
        try {
            return new ClassReader(bytes).getClassName().replace('/', '.');
        } catch (Throwable t) {
            String raw = entryPath.replace('/', '.');
            return raw.substring(0, raw.length() - 6);
        }
    }

    static void printUsage() {
        System.out.println("Usage: java -cp .;asm-9.8.jar ENI_StringDumper [options] target.jar [Class.method]");
        System.out.println("Options:");
        System.out.println("  -json        Write per-package JSON files alongside plain logs");
        System.out.println("  -timeout N   Per-class timeout ms (default 3000)");
        System.out.println("  -threads N   Thread pool size (default: CPU count)");
        System.out.println("  -depth N     Max recursion depth (default 10)");
        System.out.println("  -nopatch     Skip anti-analysis patching");
        System.out.println("  -nostubs     Skip ghost class stubs");
        System.out.println("  -out DIR     Output directory (default: <jarname>_dump/ next to JAR)");
        System.out.println("  -noreexec    Skip automatic JVM version re-exec");
    }
}
