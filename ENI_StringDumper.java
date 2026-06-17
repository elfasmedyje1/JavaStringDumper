import org.objectweb.asm.*;

import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.jar.*;

/**
 * ENI_StringDumper - High-performance string extraction tool for Java JARs.
 * 
 * Features:
 * - Multithreaded dynamic analysis and field dumping.
 * - Static LDC constant pool extraction (LDC-everywhere).
 * - Automatic "Ghost Class" stubbing for external dependencies.
 * - Anti-analysis patching (bypasses common runtime checks).
 * - Package-specific filtering for targeted analysis.
 * - Automatic JVM re-execution for version compatibility.
 */
public class ENI_StringDumper {

    // ── Configuration ─────────────────────────────────────────────────────────
    static long    TIMEOUT_MS     = 3000;
    static int     THREADS        = Runtime.getRuntime().availableProcessors();
    static int     MAX_DEPTH      = 10;
    static boolean DO_JSON        = false;
    static boolean DO_PATCH       = true;
    static boolean DO_STUBS       = true;
    static String  OUT_DIR        = null;
    static boolean DO_REEXEC      = true;
    static String  PACKAGE_FILTER = null;
    static List<String> LIBS      = new ArrayList<>();
    // Max index to brute-force for single-int-arg decryptors
    static int     BRUTE_MAX      = 512;

    // ── Named constants ───────────────────────────────────────────────────────
    /** Minimum byte-array length before we attempt UTF-8 text interpretation. */
    private static final int  BYTES_MIN_LEN          = 3;
    /** Maximum byte-array length we will attempt to interpret as text (avoids huge arrays). */
    private static final int  BYTES_MAX_LEN          = 50_000;
    /** Number of bytes sampled from the start of an array for the isLikelyText heuristic. */
    private static final int  TEXT_PROBE_LIMIT        = 256;
    /** Minimum fraction of sampled bytes that must be printable ASCII for isLikelyText to pass. */
    private static final double TEXT_PRINTABLE_RATIO  = 0.70;
    /** Lowest printable ASCII code point (space). */
    private static final byte  ASCII_PRINTABLE_LOW   = 0x20;
    /** Highest printable ASCII code point (~). */
    private static final byte  ASCII_PRINTABLE_HIGH  = 0x7E;

    static final Set<String> FLOW_STUB_CLASSES = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private static final Map<Class<?>, Field[]> FIELDS_CACHE = new ConcurrentHashMap<>();
    private static final boolean IS_TERMINAL = System.console() != null;

    // ── Entry point / main loop ───────────────────────────────────────────────
    public static void main(String[] args) throws Exception {
        if (args.length < 1) { printUsage(); return; }

        List<String> positional = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-json":     DO_JSON        = true;                        break;
                case "-nopatch":  DO_PATCH       = false;                       break;
                case "-nostubs":  DO_STUBS       = false;                       break;
                case "-noreexec": DO_REEXEC      = false;                       break;
                case "-timeout":  TIMEOUT_MS     = Long.parseLong(args[++i]);  break;
                case "-threads":  THREADS        = Integer.parseInt(args[++i]); break;
                case "-depth":    MAX_DEPTH      = Integer.parseInt(args[++i]); break;
                case "-out":      OUT_DIR        = args[++i];                  break;
                case "-package":  PACKAGE_FILTER = args[++i];                  break;
                case "-libs":     LIBS.add(args[++i]);                         break;
                case "-brutemax": BRUTE_MAX      = Integer.parseInt(args[++i]); break;
                default:          positional.add(args[i]);                     break;
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
        System.out.println("[*] Settings : Timeout: " + TIMEOUT_MS + "ms | Threads: " + THREADS
                + " | Depth: " + MAX_DEPTH + " | Stubs: " + DO_STUBS
                + " | Patch: " + DO_PATCH);
        if (PACKAGE_FILTER != null)
            System.out.println("[*] Filter   : Package prefix \"" + PACKAGE_FILTER + "\"");
        if (!LIBS.isEmpty())
            System.out.println("[*] Libs     : " + LIBS);
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
        }

        System.out.println("[+] Loaded " + classBytes.size() + " classes.");

        if (DO_REEXEC) {
            int maxMajor = getMaxClassVersion(classBytes);
            int ourMajor = getRunningJvmMajor();
            if (maxMajor > ourMajor) {
                System.out.println("[!] JAR requires Java " + (maxMajor - 44) + ", running Java " + (ourMajor - 44));
                String betterJvm = findJvm(maxMajor);
                if (betterJvm != null) {
                    System.out.println("[*] Re-execing with: " + betterJvm);
                    reExec(betterJvm, args);
                    return;
                }
            }
        }

        System.out.println("[*] Analyzing dependencies...");
        Map<String, Set<String>> deps     = new HashMap<>();
        Map<String, StubInfo>    stubNeeds = new ConcurrentHashMap<>();
        combinedAnalysisPass(classBytes, deps, stubNeeds);
        List<String> sortedClasses = topologicalSort(classBytes.keySet(), deps);

        // Build loader URL list: target JAR first, then any -libs JARs.
        List<URL> loaderUrls = new ArrayList<>();
        loaderUrls.add(jarFile.toURI().toURL());
        for (String lib : LIBS) {
            File libFile = new File(lib).getAbsoluteFile();
            if (libFile.exists()) loaderUrls.add(libFile.toURI().toURL());
            else System.err.println("[!] Lib not found: " + lib);
        }

        // poisonedClasses: classes whose <clinit> failed; dependents that GETSTATIC
        // from them would cascade-fail. We patch those GETSTATICs out in the loader.
        Set<String> poisonedClasses = Collections.newSetFromMap(new ConcurrentHashMap<>());

        GhostClassLoader loader = new GhostClassLoader(
                loaderUrls.toArray(new URL[0]), classBytes, stubNeeds, poisonedClasses);

        ExecutorService pool = Executors.newFixedThreadPool(THREADS, r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });

        ConcurrentLinkedQueue<DumpEntry> results      = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<String>    errors       = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<String>    failedClasses = new ConcurrentLinkedQueue<>();
        Set<String>                      seenLines   = Collections.newSetFromMap(new ConcurrentHashMap<>());
        AtomicInteger                    done        = new AtomicInteger(0);

        int total = sortedClasses.size();
        System.out.println("[*] Processing classes...");

        PrintStream originalErr = System.err;
        System.setErr(new PrintStream(new OutputStream() { public void write(int b) {} }));

        // Track futures individually so we can cancel hung tasks rather than
        // waiting TIMEOUT_MS per slot when the pool is full of hanging threads.
        List<Future<ClassResult>> futures = new ArrayList<>();
        int submitted = 0;
        for (String className : sortedClasses) {
            if (PACKAGE_FILTER != null && !className.startsWith(PACKAGE_FILTER)) {
                done.incrementAndGet();
                continue;
            }
            submitted++;
            final String triggerMethod = (triggerSpec != null && triggerSpec.startsWith(className + "."))
                    ? triggerSpec.substring(className.length() + 1) : null;
            futures.add(pool.submit(() -> {
                if (!IS_TERMINAL) System.out.println("[*] Processing class: " + className);
                ClassResult r = processClass(loader, className, triggerMethod, results, errors, seenLines);
                if (r == ClassResult.FAIL) failedClasses.add(className);
                done.incrementAndGet();
                return r;
            }));
        }

        if (submitted == 0 && total > 0) System.err.println("[!] Warning: No classes matched the package filter.");

        int classCount = 0, failCount = 0;
        for (Future<ClassResult> f : futures) {
            try {
                ClassResult r = f.get(TIMEOUT_MS, TimeUnit.MILLISECONDS);
                if (r == ClassResult.FAIL) failCount++; else classCount++;
            } catch (java.util.concurrent.TimeoutException te) {
                f.cancel(true); // interrupt the hung thread immediately
                failCount++;
            } catch (Exception e) { failCount++; }
        }

        pool.shutdownNow();
        System.setErr(originalErr);

        // ── Single-thread retry for failed classes ────────────────────────────────
        // Race conditions in multithreaded loading can cause <clinit> failures when
        // a dependency hasn't finished initialising. Retrying failed classes
        // single-threaded in topological order (preserving dependency ordering) fixes this.
        if (!failedClasses.isEmpty()) {
            // Build retry list in topological order
            Set<String> failedSet = new HashSet<>(failedClasses);
            List<String> retryOrder = new ArrayList<>();
            for (String cls : sortedClasses) {
                if (failedSet.contains(cls)) retryOrder.add(cls);
            }
            System.out.println("[*] Retrying " + retryOrder.size() + " failed classes single-threaded...");
            int retryOk = 0, retryFail = 0;
            for (String className : retryOrder) {
                ClassResult r = processClass(loader, className, null, results, errors, seenLines);
                if (r == ClassResult.OK) { retryOk++; classCount++; failCount--; } else retryFail++;
            }
            if (retryOk > 0)
                System.out.println("[+] Retry recovered: " + retryOk + " additional classes (" + retryFail + " still failing)");
        }

        // ── String array index pass ───────────────────────────────────────────────
        System.out.println("[*] Running string array index pass...");
        stringTableIndexPass(classBytes, results, seenLines);

        saveResults(jarFile, results, errors, classCount, failCount);
    }

    /**
     * Scans every class for the "string table" access pattern:
     *   GETSTATIC SomeClass.stringArray [Ljava/lang/String;
     *   [integer push: ICONST_x, BIPUSH, SIPUSH, or LDC int]
     *   AALOAD
     *
     * When found, we look up index N in the dumped string table for SomeClass
     * and emit that string attributed to the *calling* class. This connects
     * string table entries to the classes that actually use them.
     */
    static void stringTableIndexPass(Map<String, byte[]> classBytes,
                                      ConcurrentLinkedQueue<DumpEntry> results,
                                      Set<String> seenLines) {
        // Build index maps from <clinit> of each class: fieldKey -> (index -> value)
        // fieldKey = "owner.dot.name.fieldName"
        Map<String, Map<Integer, String>> indexMaps = new ConcurrentHashMap<>();

        for (Map.Entry<String, byte[]> e : classBytes.entrySet()) {
            final String className = e.getKey();
            try {
                new ClassReader(e.getValue()).accept(new ClassVisitor(Opcodes.ASM9) {
                    @Override
                    public MethodVisitor visitMethod(int access, String mname, String desc, String sig, String[] exc) {
                        if (!mname.equals("<clinit>")) return null;
                        return new MethodVisitor(Opcodes.ASM9) {
                            int    pendingIndex = -1;
                            String pendingField = null;

                            @Override
                            public void visitFieldInsn(int opcode, String owner, String fname, String fdesc) {
                                if (opcode == Opcodes.PUTSTATIC && fdesc.equals("[Ljava/lang/String;")) {
                                    pendingField = owner.replace('/', '.') + "." + fname;
                                }
                            }

                            @Override
                            public void visitIntInsn(int opcode, int operand) {
                                if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) pendingIndex = operand;
                            }

                            @Override
                            public void visitInsn(int opcode) {
                                if (opcode >= Opcodes.ICONST_0 && opcode <= Opcodes.ICONST_5)
                                    pendingIndex = opcode - Opcodes.ICONST_0;
                            }

                            @Override
                            public void visitLdcInsn(Object cst) {
                                if (cst instanceof String && pendingIndex >= 0 && pendingField != null) {
                                    indexMaps.computeIfAbsent(pendingField, k -> new ConcurrentHashMap<>())
                                            .put(pendingIndex, (String) cst);
                                    pendingIndex = -1;
                                } else if (cst instanceof Integer) {
                                    pendingIndex = (Integer) cst;
                                }
                            }
                        };
                    }
                }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
            } catch (Throwable ignored) {}
        }

        if (indexMaps.isEmpty()) return;

        // Step 2: scan every class for GETSTATIC tableField + int push + AALOAD
        for (Map.Entry<String, byte[]> e : classBytes.entrySet()) {
            final String callerClass = e.getKey();
            try {
                new ClassReader(e.getValue()).accept(new ClassVisitor(Opcodes.ASM9) {
                    @Override
                    public MethodVisitor visitMethod(int access, String mname, String desc, String sig, String[] exc) {
                        return new MethodVisitor(Opcodes.ASM9) {
                            String lastTableField = null;
                            int    lastIndex      = -1;

                            @Override
                            public void visitFieldInsn(int opcode, String owner, String fname, String fdesc) {
                                if (opcode == Opcodes.GETSTATIC && fdesc.equals("[Ljava/lang/String;")) {
                                    String key = owner.replace('/', '.') + "." + fname;
                                    if (indexMaps.containsKey(key)) {
                                        lastTableField = key;
                                        lastIndex = -1;
                                        return;
                                    }
                                }
                                lastTableField = null;
                                lastIndex = -1;
                            }

                            @Override
                            public void visitIntInsn(int opcode, int operand) {
                                if (lastTableField != null && (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH))
                                    lastIndex = operand;
                                else { lastTableField = null; lastIndex = -1; }
                            }

                            @Override
                            public void visitInsn(int opcode) {
                                if (lastTableField != null) {
                                    if (opcode >= Opcodes.ICONST_0 && opcode <= Opcodes.ICONST_5) {
                                        lastIndex = opcode - Opcodes.ICONST_0;
                                    } else if (opcode == Opcodes.AALOAD && lastIndex >= 0) {
                                        String val = indexMaps.get(lastTableField).get(lastIndex);
                                        if (val != null && interesting(val))
                                            emit(results, seenLines, callerClass,
                                                 "[strtable:" + lastTableField + "]",
                                                 "[" + lastIndex + "]", val);
                                        lastTableField = null;
                                        lastIndex = -1;
                                    } else {
                                        lastTableField = null; lastIndex = -1;
                                    }
                                }
                            }

                            @Override
                            public void visitLdcInsn(Object cst) {
                                if (lastTableField != null && cst instanceof Integer) {
                                    lastIndex = (Integer) cst;
                                } else {
                                    lastTableField = null; lastIndex = -1;
                                }
                            }

                            @Override
                            public void visitVarInsn(int opcode, int var) {
                                // Any var instruction between GETSTATIC and AALOAD breaks the chain.
                            }
                        };
                    }
                }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
            } catch (Throwable ignored) {}
        }
    }

    private static void saveResults(File jarFile, ConcurrentLinkedQueue<DumpEntry> results, 
                                     ConcurrentLinkedQueue<String> errors, int classCount, int failCount) throws IOException {
        String jarBaseName = jarFile.getName().replace(".jar", "");
        File outDir = OUT_DIR != null ? new File(OUT_DIR) : new File(jarFile.getParentFile(), jarBaseName + "_dump");
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
            out.println("  timeout=" + TIMEOUT_MS + "ms | threads=" + THREADS + " | depth=" + MAX_DEPTH);
            if (PACKAGE_FILTER != null) out.println("  filter=" + PACKAGE_FILTER);
            if (!LIBS.isEmpty()) out.println("  libs=" + LIBS);
            out.println("  brutemax=" + BRUTE_MAX);
            out.println();
            out.println("Package breakdown:");
            for (Map.Entry<String, List<DumpEntry>> pe : byPackage.entrySet())
                out.printf("  %-40s %d strings\n", pe.getKey(), pe.getValue().size());
        }

        System.out.println("\n  Done.");
        System.out.printf("  Coverage:              %d classes processed (%d failed)\n", classCount, failCount);
        System.out.printf("  Strings dumped:        %d strings across %d packages\n", sorted.size(), byPackage.size());
        System.out.println("  Output: " + outDir.getAbsolutePath());
    }

    // ── Per-class processing ──────────────────────────────────────────────────
    static ClassResult processClass(GhostClassLoader loader, String className, String triggerMethodName,
                                    ConcurrentLinkedQueue<DumpEntry> results, ConcurrentLinkedQueue<String> errors,
                                    Set<String> seenLines) {
        try {
            Class<?> clazz = loader.loadClass(className);
            byte[] bytes = loader.classBytes.get(className);
            dumpIndyStrings(loader, bytes, className, results, seenLines);
            dumpStaticFields(clazz, className, results, errors, seenLines);
            Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
            if (invokeStaticMethods(clazz, className, triggerMethodName, results, errors, seenLines, visited))
                dumpStaticFields(clazz, className, results, errors, seenLines);
            bruteForceDecryptors(clazz, className, results, errors, seenLines);
            dumpInstanceFields(clazz, className, results, errors, seenLines, visited);
            return ClassResult.OK;
        } catch (Throwable t) {
            // Mark as poisoned so dependents can have their GETSTATIC calls patched out
            loader.poisonedClasses.add(className);
            errors.add("[CLASS_FAIL] " + className + " -> " + fullCauseChain(t));
            // Dynamic loading failed — fall back to static bytecode extraction
            byte[] bytes = loader.classBytes.get(className);
            if (bytes != null) ldcFallback(bytes, className, results, seenLines);
            return ClassResult.FAIL;
        }
    }

    /**
     * Attempts to execute an invokedynamic bootstrap method to recover the string
     * it would produce at runtime. Modern obfuscators (Skidfuscator, SkidSuite, etc.)
     * put entire string tables behind invokedynamic rather than INVOKESTATIC, so the
     * strings never appear as LDC constants.
     *
     * The approach:
     * 1. Load the BSM class via the GhostClassLoader
     * 2. Invoke the bootstrap method with a dummy MethodHandles.Lookup, the method name,
     *    and a MethodType of ()Ljava/lang/String;
     * 3. Call the returned CallSite's target with no arguments
     * 4. Return the String result
     *
     * This is best-effort — many BSMs will fail due to missing context, but the ones
     * that succeed (pure index-based string tables) yield the most valuable strings.
     */
    static String tryBootstrapIndy(GhostClassLoader loader, Handle bsm, Object[] bsmArgs,
                                    String callerClassName) {
        try {
            // Load the class that contains the bootstrap method
            Class<?> bsmClass = loader.loadClass(bsm.getOwner().replace('/', '.'));

            // Find the bootstrap method — BSMs always have signature:
            // (MethodHandles.Lookup, String, MethodType, ...) returning CallSite
            Method bsmMethod = null;
            for (Method m : bsmClass.getDeclaredMethods()) {
                if (!m.getName().equals(bsm.getName())) continue;
                Class<?>[] params = m.getParameterTypes();
                if (params.length < 3) continue;
                if (!params[0].getName().equals("java.lang.invoke.MethodHandles$Lookup")) continue;
                if (!params[1].equals(String.class)) continue;
                if (!params[2].getName().equals("java.lang.invoke.MethodType")) continue;
                bsmMethod = m;
                break;
            }
            if (bsmMethod == null) return null;
            bsmMethod.setAccessible(true);

            java.lang.invoke.MethodHandles.Lookup lookup = java.lang.invoke.MethodHandles.lookup();
            java.lang.invoke.MethodType dummyType = java.lang.invoke.MethodType.methodType(String.class);
            Object[] args = new Object[3 + bsmArgs.length];
            args[0] = lookup;
            args[1] = callerClassName; // method name hint
            args[2] = dummyType;
            for (int i = 0; i < bsmArgs.length; i++) {
                Object arg = bsmArgs[i];
                // Convert ASM Type to java.lang.invoke.MethodType
                if (arg instanceof org.objectweb.asm.Type) {
                    arg = java.lang.invoke.MethodType.fromMethodDescriptorString(
                            ((org.objectweb.asm.Type) arg).getDescriptor(),
                            loader);
                }
                args[3 + i] = arg;
            }

            Object callSite = bsmMethod.invoke(null, args);
            if (callSite == null) return null;

            Method getTarget = callSite.getClass().getMethod("getTarget");
            java.lang.invoke.MethodHandle target = (java.lang.invoke.MethodHandle) getTarget.invoke(callSite);
            if (target == null) return null;

            Object result = target.invokeWithArguments();
            return result instanceof String ? (String) result : null;

        } catch (Throwable t) {
            return null; // best-effort, most will fail
        }
    }

    static void dumpIndyStrings(GhostClassLoader loader, byte[] classBytes, String className,
                                  ConcurrentLinkedQueue<DumpEntry> results, Set<String> seenLines) {
        if (classBytes == null) return;
        try {
            new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String mname, String desc, String sig, String[] exc) {
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitInvokeDynamicInsn(String name, String descriptor,
                                                            Handle bsm, Object... bsmArgs) {
                            if (!descriptor.endsWith(")Ljava/lang/String;")) return;
                            String val = tryBootstrapIndy(loader, bsm, bsmArgs, className);
                            if (val != null && interesting(val))
                                emit(results, seenLines, className, "[bsm:" + mname + "]", null, val);
                        }
                    };
                }
            }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
        } catch (Throwable ignored) {}
    }

    /**
     * Brute-force invoke static methods that take a single int or long argument
     * and return String or String[]. These are the decrypt(int index) style
     * decryptors used by most modern obfuscators. We try indices 0..BRUTE_MAX-1.
     * For String[] returns we call once and harvest all elements.
     */
    static void bruteForceDecryptors(Class<?> clazz, String className,
                                      ConcurrentLinkedQueue<DumpEntry> results,
                                      ConcurrentLinkedQueue<String> errors,
                                      Set<String> seenLines) {
        Method[] methods;
        try { methods = clazz.getDeclaredMethods(); } catch (Throwable t) { return; }

        for (Method method : methods) {
            if (!Modifier.isStatic(method.getModifiers())) continue;
            Class<?>[] params = method.getParameterTypes();
            if (params.length != 1) continue;
            Class<?> param = params[0];
            boolean isInt  = param == int.class  || param == Integer.class;
            boolean isLong = param == long.class  || param == Long.class;
            if (!isInt && !isLong) continue;

            Class<?> ret = method.getReturnType();
            boolean returnsString      = ret == String.class;
            boolean returnsStringArray = ret == String[].class;
            if (!returnsString && !returnsStringArray) continue;

            try { method.setAccessible(true); } catch (Throwable ignored) { continue; }
            String label = method.getName() + "(brute)";

            if (returnsStringArray) {
                // Call once with 0 — the whole table comes back
                try {
                    Object result = isLong ? method.invoke(null, 0L) : method.invoke(null, 0);
                    if (result instanceof String[]) {
                        String[] arr = (String[]) result;
                        for (int i = 0; i < arr.length; i++) {
                            if (arr[i] != null && interesting(arr[i]))
                                emit(results, seenLines, className, label, "[" + i + "]", arr[i]);
                        }
                    }
                } catch (Throwable ignored) {}
                continue;
            }

            // String return: try each index
            for (int idx = 0; idx < BRUTE_MAX; idx++) {
                if (Thread.interrupted()) return; // respect class-level timeout cancellation
                try {
                    Object result = isLong ? method.invoke(null, (long) idx) : method.invoke(null, idx);
                    if (result instanceof String) {
                        String s = (String) result;
                        if (interesting(s))
                            emit(results, seenLines, className, label, "[" + idx + "]", s);
                    }
                } catch (Throwable ignored) {}
            }
        }
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
        if (clazz.isInterface() || Modifier.isAbstract(clazz.getModifiers())) return;
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
            collectString((String) obj, className, fieldName, prefix, results, seenLines);
            return;
        }
        if (obj instanceof char[]) {
            collectCharArray((char[]) obj, className, fieldName, prefix, results, seenLines);
            return;
        }
        if (obj instanceof byte[]) {
            collectByteArray((byte[]) obj, className, fieldName, prefix, results, seenLines);
            return;
        }

        if (!visited.add(obj)) return;

        if (obj.getClass().isArray()) {
            collectArray(obj, className, fieldName, prefix, results, seenLines, depth, visited);
            return;
        }
        if (obj instanceof Map<?, ?>) {
            collectMap((Map<?, ?>) obj, className, fieldName, prefix, results, seenLines, depth, visited);
            return;
        }
        if (obj instanceof Iterable<?>) {
            collectIterable((Iterable<?>) obj, className, fieldName, prefix, results, seenLines, depth, visited);
            return;
        }
        if (depth < MAX_DEPTH - 1) {
            collectFields(obj, className, fieldName, prefix, results, seenLines, depth, visited);
        }
    }

    private static void collectString(String s, String className, String fieldName,
                                       String prefix, ConcurrentLinkedQueue<DumpEntry> results,
                                       Set<String> seenLines) {
        if (interesting(s))
            emit(results, seenLines, className, fieldName, prefix.isEmpty() ? null : prefix, s);
    }

    private static void collectCharArray(char[] arr, String className, String fieldName,
                                          String prefix, ConcurrentLinkedQueue<DumpEntry> results,
                                          Set<String> seenLines) {
        if (interestingImpl(arr.length, i -> arr[i]))
            emit(results, seenLines, className, fieldName, prefix.isEmpty() ? null : prefix, new String(arr));
    }

    private static void collectByteArray(byte[] bytes, String className, String fieldName,
                                          String prefix, ConcurrentLinkedQueue<DumpEntry> results,
                                          Set<String> seenLines) {
        if (bytes.length >= BYTES_MIN_LEN && bytes.length < BYTES_MAX_LEN && isLikelyText(bytes)) {
            try {
                String s = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                if (interesting(s))
                    emit(results, seenLines, className, fieldName, prefix.isEmpty() ? null : prefix, s);
            } catch (Throwable ignored) {}
        }
    }

    private static void collectArray(Object obj, String className, String fieldName,
                                      String prefix, ConcurrentLinkedQueue<DumpEntry> results,
                                      Set<String> seenLines, int depth, Set<Object> visited) {
        int len = Array.getLength(obj);
        for (int i = 0; i < len; i++)
            collectFromObject(Array.get(obj, i), className, fieldName,
                    prefix + '[' + i + ']', results, seenLines, depth + 1, visited);
    }

    private static void collectMap(Map<?, ?> map, String className, String fieldName,
                                    String prefix, ConcurrentLinkedQueue<DumpEntry> results,
                                    Set<String> seenLines, int depth, Set<Object> visited) {
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            String k = entry.getKey() != null ? entry.getKey().toString() : "null";
            collectFromObject(entry.getKey(), className, fieldName,
                    prefix + "[key:" + k + ']', results, seenLines, depth + 1, visited);
            collectFromObject(entry.getValue(), className, fieldName,
                    prefix + '[' + k + ']', results, seenLines, depth + 1, visited);
        }
    }

    private static void collectIterable(Iterable<?> iterable, String className, String fieldName,
                                         String prefix, ConcurrentLinkedQueue<DumpEntry> results,
                                         Set<String> seenLines, int depth, Set<Object> visited) {
        int i = 0;
        for (Object item : iterable)
            collectFromObject(item, className, fieldName,
                    prefix + '[' + i++ + ']', results, seenLines, depth + 1, visited);
    }

    private static void collectFields(Object obj, String className, String fieldName,
                                       String prefix, ConcurrentLinkedQueue<DumpEntry> results,
                                       Set<String> seenLines, int depth, Set<Object> visited) {
        for (Field f : cachedFields(obj.getClass())) {
            if (Modifier.isStatic(f.getModifiers())) continue;
            try {
                collectFromObject(f.get(obj), className, fieldName,
                        prefix + '.' + f.getName(), results, seenLines, depth + 1, visited);
            } catch (Throwable ignored) {}
        }
    }

    static void emit(ConcurrentLinkedQueue<DumpEntry> results, Set<String> seenLines,
                     String className, String fieldName, String index, String value) {
        if (seenLines.add(className + "." + fieldName + (index != null ? index : "") + "=" + value))
            results.add(new DumpEntry(className, fieldName, index, value));
    }

    // ── Dependency analysis and class ordering ────────────────────────────────
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

            // single-element array used as mutable int in anonymous class (Java's closure limitation)
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

                if (hasTimingCall[0] && methodCount[0] <= 8 && entry.getValue().length < 20000)
                    FLOW_STUB_CLASSES.add(name);

            } catch (Throwable ignored) {}
        }
    }

    static List<String> topologicalSort(Set<String> nodes, Map<String, Set<String>> deps) {
        Map<String, Integer>    inDegree = new HashMap<>(nodes.size());
        Map<String, Set<String>> revDeps = new HashMap<>(nodes.size());
        for (String n : nodes) inDegree.put(n, 0);

        for (Map.Entry<String, Set<String>> e : deps.entrySet()) {
            String dependent = e.getKey();
            for (String dependency : e.getValue()) {
                if (!nodes.contains(dependency)) continue;
                revDeps.computeIfAbsent(dependency, k -> new HashSet<>()).add(dependent);
                inDegree.merge(dependent, 1, Integer::sum);
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

    // ── Bytecode patching ─────────────────────────────────────────────────────
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
            case 'c': return name.startsWith("com.sun.") || name.startsWith("com.oracle.");
            case 'o': return name.startsWith("org.xml.") || name.startsWith("org.w3c.") || name.startsWith("org.ietf.");
            case 'n': return name.startsWith("netscape.javascript.");
            default:  return false;
        }
    }

    static void emitZeroReturn(MethodVisitor mv, String ret, String descriptor, int opcode) {
        // The operand stack currently holds the receiver (if non-static) followed by
        // all arguments. We must pop them in reverse order before pushing the return
        // value, otherwise the stack depth will be wrong and the verifier will reject
        // the bytecode. Category-2 values (long, double, size==2) need POP2; all
        // others need POP.
        boolean hasThis = opcode != Opcodes.INVOKESTATIC;
        org.objectweb.asm.Type[] argTypes = org.objectweb.asm.Type.getArgumentTypes(descriptor);
        // Build a list of slot sizes (1 or 2) in push order so we can pop them in reverse.
        java.util.List<Integer> sizes = new java.util.ArrayList<>();
        if (hasThis) sizes.add(1);
        for (org.objectweb.asm.Type t : argTypes) sizes.add(t.getSize());
        for (int i = sizes.size() - 1; i >= 0; i--) {
            mv.visitInsn(sizes.get(i) == 2 ? Opcodes.POP2 : Opcodes.POP);
        }
        switch (ret) {
            case "V":                                        break;
            case "J": mv.visitInsn(Opcodes.LCONST_0);      break;
            case "D": mv.visitInsn(Opcodes.DCONST_0);      break;
            case "F": mv.visitInsn(Opcodes.FCONST_0);      break;
            case "I": case "Z": case "B": case "C": case "S":
                      mv.visitInsn(Opcodes.ICONST_0);       break;
            case "[B":
                // Return empty byte[] rather than null so callers don't NPE on new String(bytes, charset).
                mv.visitInsn(Opcodes.ICONST_0);
                mv.visitIntInsn(Opcodes.NEWARRAY, org.objectweb.asm.Opcodes.T_BYTE);
                break;
            default:  mv.visitInsn(Opcodes.ACONST_NULL);   break;
        }
    }

    static byte[] patchAntiAnalysis(byte[] classBytes) {
        try {
            ClassReader cr = new ClassReader(classBytes);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
            cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                  String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitMethodInsn(int opcode, String owner, String mname,
                                                    String descriptor, boolean isInterface) {
                            // ── Reflection stubs ─────────────────────────────────────────────
                            if (owner.equals("sun/reflect/Reflection") && mname.equals("getCallerClass")) {
                                super.visitInsn(Opcodes.ACONST_NULL); return;
                            }
                            if (owner.equals("java/lang/Thread") && mname.equals("getStackTrace")) {
                                super.visitInsn(Opcodes.POP);
                                super.visitInsn(Opcodes.ICONST_0);
                                super.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/StackTraceElement"); return;
                            }
                            // threadId() is Java 19+ API used as an anti-downgrade key.
                            // Return a stable constant so <clinit> can complete and decrypt strings.
                            // Must be patched before currentThread() to avoid NPE on the call chain.
                            if (owner.equals("java/lang/Thread") && mname.equals("threadId")) {
                                super.visitInsn(Opcodes.POP);
                                super.visitLdcInsn(1L); return;
                            }
                            // getId() is the pre-Java-19 equivalent — also used as a decryption key
                            // by obfuscators to tie strings to a specific thread. Return a stable
                            // constant (1L) so the same key is derived regardless of which thread
                            // happens to run the <clinit>.
                            if (owner.equals("java/lang/Thread") && mname.equals("getId")) {
                                super.visitInsn(Opcodes.POP);
                                super.visitLdcInsn(1L); return;
                            }
                            // Do NOT stub Class.getName() globally — it may be used as a decryption key.
                            // Do NOT stub currentThread() to null — threadId() would NPE.

                            // ── Timing stubs ─────────────────────────────────────────────────
                            if (owner.equals("java/lang/System") && mname.equals("currentTimeMillis")) {
                                super.visitLdcInsn(1000L); return;
                            }
                            if (owner.equals("java/lang/System") && mname.equals("nanoTime")) {
                                super.visitLdcInsn(1000000L); return;
                            }

                            // ── Unsafe stubs ─────────────────────────────────────────────────
                            if ((owner.equals("sun/misc/Unsafe") || owner.equals("jdk/internal/misc/Unsafe"))
                                    && (mname.startsWith("put") || mname.startsWith("get")
                                        || mname.startsWith("compare") || mname.equals("allocateMemory")
                                        || mname.equals("freeMemory") || mname.equals("setMemory")
                                        || mname.equals("copyMemory") || mname.equals("ensureClassInitialized"))) {
                                emitZeroReturn(this, descriptor.substring(descriptor.lastIndexOf(')') + 1), descriptor, opcode);
                                return;
                            }

                            // ── Native loader stubs ──────────────────────────────────────────
                            if (owner.equals("java/lang/System")
                                    && (mname.equals("load") || mname.equals("loadLibrary"))) {
                                super.visitInsn(Opcodes.POP); return;
                            }
                            if (owner.equals("java/lang/System") && mname.equals("exit")) {
                                super.visitInsn(Opcodes.POP); return;
                            }
                            if (owner.equals("java/lang/Runtime")
                                    && (mname.equals("load") || mname.equals("loadLibrary"))) {
                                super.visitInsn(Opcodes.POP); super.visitInsn(Opcodes.POP); return;
                            }
                            if (owner.equals("java/lang/Runtime") && mname.equals("halt")) {
                                super.visitInsn(Opcodes.POP); super.visitInsn(Opcodes.POP); return;
                            }
                            if (owner.equals("native0/Loader") && mname.equals("registerNativesForClass")) {
                                super.visitInsn(Opcodes.POP); super.visitInsn(Opcodes.POP); return;
                            }
                            if (owner.equals("native0/hidden/Hidden0") && mname.startsWith("special_clinit_")) {
                                super.visitInsn(Opcodes.POP); return;
                            }

                            // ── Integrity check stubs ────────────────────────────────────────
                            // Block bytecode self-integrity checks: return null so the check sees no data.
                            if ((owner.equals("java/lang/Class") || owner.equals("java/lang/ClassLoader"))
                                    && mname.equals("getResourceAsStream")) {
                                super.visitInsn(Opcodes.POP);
                                super.visitInsn(Opcodes.POP);
                                super.visitInsn(Opcodes.ACONST_NULL); return;
                            }
                            if (owner.equals("java/lang/StackWalker")) {
                                emitZeroReturn(this, descriptor.substring(descriptor.lastIndexOf(')') + 1), descriptor, opcode);
                                return;
                            }

                            // ── Cipher / Mac stubs ───────────────────────────────────────────
                            // Stub the full Cipher lifecycle so <clinit> routines that use
                            // AES/DES string decryption complete without throwing BadPaddingException.
                            // The decrypted strings will be empty/null, but the class loads cleanly
                            // and its other (non-encrypted) fields and strings are still recoverable.
                            //
                            // Cipher.getInstance  → null  (no Cipher object created)
                            // Cipher.init         → void  (no-op)
                            // Cipher.doFinal/update → empty byte[]
                            if (owner.equals("javax/crypto/Cipher")) {
                                emitZeroReturn(this, descriptor.substring(descriptor.lastIndexOf(')') + 1), descriptor, opcode);
                                return;
                            }
                            if (owner.equals("javax/crypto/Mac")
                                    && (mname.equals("doFinal") || mname.equals("update") || mname.equals("init"))) {
                                emitZeroReturn(this, descriptor.substring(descriptor.lastIndexOf(')') + 1), descriptor, opcode);
                                return;
                            }
                            // Stub SecretKeyFactory and KeyGenerator — obfuscators use these
                            // to build keys from hardcoded byte arrays before passing to Cipher.
                            // Stubbing them returns null keys so Cipher.init (also stubbed) is a no-op.
                            if ((owner.equals("javax/crypto/SecretKeyFactory")
                                    || owner.equals("javax/crypto/KeyGenerator"))
                                    && !mname.equals("<init>")) {
                                emitZeroReturn(this, descriptor.substring(descriptor.lastIndexOf(')') + 1), descriptor, opcode);
                                return;
                            }
                            // Stub all javax/crypto/spec key/param constructors and SecretKeySpec.
                            // When SecretKeyFactory is stubbed to null, calling generateSecret on
                            // null throws NPE. Stubbing the spec constructors as void no-ops (they
                            // are INVOKESPECIAL so NEW already pushed the ref — we just discard args)
                            // means the spec object exists but is uninitialized, which is fine since
                            // Cipher.init is also stubbed.
                            if (owner.startsWith("javax/crypto/spec/") && mname.equals("<init>")) {
                                // INVOKESPECIAL <init>: NEW already placed 'this' on stack.
                                // We just need to pop the arguments (not the receiver).
                                org.objectweb.asm.Type[] argTypes = org.objectweb.asm.Type.getArgumentTypes(descriptor);
                                for (int i = argTypes.length - 1; i >= 0; i--) {
                                    super.visitInsn(argTypes[i].getSize() == 2 ? Opcodes.POP2 : Opcodes.POP);
                                }
                                // Do NOT emit a RETURN — this is a constructor, control falls through.
                                return;
                            }

                            // ── JNA / LWJGL / Log4j version-mismatch stubs ──────────────────
                            // Bundled JNA/LWJGL/Log4j versions often differ from what is on the
                            // classpath, causing NoSuchMethodError at <clinit> time and
                            // cascade-poisoning every class that depends on them. Stubbing
                            // their calls to zero/null lets those <clinit>s complete so we
                            // can still recover decrypted strings from the class.
                            if (owner.startsWith("com/sun/jna/")
                                    || owner.startsWith("org/lwjgl/")
                                    || owner.startsWith("org/apache/logging/log4j/")) {
                                emitZeroReturn(this, descriptor.substring(descriptor.lastIndexOf(')') + 1), descriptor, opcode);
                                return;
                            }

                            // ── Flow-stub classes ────────────────────────────────────────────
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

    static byte[] recomputeFrames(byte[] classBytes) {
        try {
            ClassReader cr = new ClassReader(classBytes);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            cr.accept(cw, ClassReader.SKIP_FRAMES);
            return cw.toByteArray();
        } catch (Throwable t) {
            return classBytes;
        }
    }

    /**
     * Full bytecode rewrite: feeds only the method bodies through a fresh ClassWriter
     * without referencing the original ClassReader. This forces ASM to recompute
     * every stack map frame from scratch, discarding illegal type annotations that
     * cause "Bad type on operand stack" / "Bad return type" VerifyErrors in the JVM
     * strict verifier (Java 7+). Used as a last-resort step after recomputeFrames
     * fails because the original frames themselves contain the bad types.
     */
    static byte[] fullRewrite(byte[] classBytes) {
        try {
            ClassReader cr = new ClassReader(classBytes);
            // No ClassReader passed to ClassWriter — ASM infers the entire type hierarchy
            // from scratch. getCommonSuperClass falling back to Object is acceptable here
            // since we only need the class to load, not to verify perfectly.
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    return "java/lang/Object";
                }
            };
            cr.accept(cw, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
            return cw.toByteArray();
        } catch (Throwable t) {
            return classBytes;
        }
    }

    /**
     * Rewrites exception handlers whose catch type is not a Throwable subclass
     * to catch java/lang/Throwable instead, so the verifier accepts the bytecode.
     */
    static byte[] fixExceptionHandlers(byte[] classBytes) {
        try {
            ClassReader cr = new ClassReader(classBytes);
            // Quick scan: does this class have any suspicious try-catch blocks?
            boolean[] needsFix = {false};
            cr.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int a, String n, String d, String s, String[] e) {
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitTryCatchBlock(org.objectweb.asm.Label start,
                                org.objectweb.asm.Label end, org.objectweb.asm.Label handler, String type) {
                            if (type != null && !type.startsWith("java/lang/") && !type.startsWith("java/io/")
                                    && !type.startsWith("java/util/") && !type.startsWith("javax/")
                                    && !type.startsWith("sun/") && !type.startsWith("jdk/")
                                    && !type.startsWith("org/xml/") && !type.startsWith("org/w3c/")
                                    && !type.startsWith("com/sun/")) {
                                needsFix[0] = true;
                            }
                        }
                    };
                }
            }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
            if (!needsFix[0]) return classBytes;

            // COMPUTE_FRAMES is required: changing catch types invalidates existing stack map frames.
            // Resolve unknown types to Object to avoid ClassNotFoundException during frame computation.
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    return "java/lang/Object";
                }
            };
            cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
                    MethodVisitor mv = super.visitMethod(access, name, desc, sig, exc);
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitTryCatchBlock(org.objectweb.asm.Label start,
                                org.objectweb.asm.Label end, org.objectweb.asm.Label handler, String type) {
                            // Normalize non-Throwable catch types to Throwable
                            if (type != null && !type.startsWith("java/lang/") && !type.startsWith("java/io/")
                                    && !type.startsWith("java/util/") && !type.startsWith("javax/")
                                    && !type.startsWith("sun/") && !type.startsWith("jdk/")
                                    && !type.startsWith("org/xml/") && !type.startsWith("org/w3c/")
                                    && !type.startsWith("com/sun/")) {
                                super.visitTryCatchBlock(start, end, handler, "java/lang/Throwable");
                            } else {
                                super.visitTryCatchBlock(start, end, handler, type);
                            }
                        }
                    };
                }
            }, ClassReader.SKIP_FRAMES);
            return cw.toByteArray();
        } catch (Throwable t) {
            return classBytes;
        }
    }

    // ── Ghost class loader ────────────────────────────────────────────────────
    static class GhostClassLoader extends URLClassLoader {
        final Map<String, byte[]>  classBytes;
        private final Map<String, StubInfo>  stubNeeds;
        private final ConcurrentHashMap<String, Class<?>> defined = new ConcurrentHashMap<>();
        final Set<String> poisonedClasses;

        GhostClassLoader(URL[] urls, Map<String, byte[]> classBytes, Map<String, StubInfo> stubNeeds,
                         Set<String> poisonedClasses) {
            super(urls, null);
            this.classBytes      = classBytes;
            this.stubNeeds       = stubNeeds;
            this.poisonedClasses = poisonedClasses;
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            Class<?> cached = defined.get(name);
            if (cached != null) return cached;
            // Vendor library classes that require native loading always fail.
            // Return a stub immediately rather than attempting to load and cascade-poisoning dependents.
            if (isVendorClass(name)) {
                return loadFromBytes(name, generateStub(stubNeeds.getOrDefault(name, new StubInfo(name, false))), resolve);
            }
            if (isBootClass(name)) return getSystemClassLoader().loadClass(name);
            if (classBytes.containsKey(name))
                return loadFromBytes(name, classBytes.get(name), resolve);
            // Try parent URLs (library JARs) before falling back to stubs
            try {
                URL res = findResource(name.replace('.', '/') + ".class");
                if (res != null) {
                    try (InputStream is = res.openStream()) {
                        byte[] bytes = readAllBytes(is);
                        return loadFromBytes(name, bytes, resolve);
                    }
                }
            } catch (Throwable ignored) {}
            if (DO_STUBS)
                return loadFromBytes(name, generateStub(stubNeeds.getOrDefault(name, new StubInfo(name, false))), resolve);
            throw new ClassNotFoundException(name);
        }

        private Class<?> loadFromBytes(String name, byte[] bytes, boolean resolve) {
            Class<?> existing = defined.get(name);
            if (existing != null) return existing;
            synchronized (this) {
                existing = defined.get(name);
                if (existing != null) return existing;

                byte[] patched = DO_PATCH ? patchAntiAnalysis(bytes) : bytes;
                patched = patchPoisonedDeps(patched);
                patched = fixExceptionHandlers(patched);

                // Fallback chain: each step tries a different form of the bytecode.
                // tryDefine returns null on failure so the chain is linear.
                Class<?> clazz;

                clazz = tryDefine(name, patched, resolve);
                if (clazz != null) { defined.put(name, clazz); return clazz; }

                clazz = tryDefine(name, recomputeFrames(patched), resolve);
                if (clazz != null) { defined.put(name, clazz); return clazz; }

                // Full rewrite: discard original frames entirely and let ASM rebuild
                // from scratch — recovers "Bad type on operand stack" VerifyErrors.
                clazz = tryDefine(name, fullRewrite(patched), resolve);
                if (clazz != null) { defined.put(name, clazz); return clazz; }

                if (patched != bytes) {
                    clazz = tryDefine(name, recomputeFrames(bytes), resolve);
                    if (clazz != null) { defined.put(name, clazz); return clazz; }

                    clazz = tryDefine(name, fullRewrite(bytes), resolve);
                    if (clazz != null) { defined.put(name, clazz); return clazz; }

                    clazz = tryDefine(name, bytes, resolve);
                    if (clazz != null) { defined.put(name, clazz); return clazz; }
                }

                // Last resort: generate a stub so dependents don't cascade-fail
                poisonedClasses.add(name);
                byte[] stub = generateStub(stubNeeds.getOrDefault(name, new StubInfo(name, false)));
                clazz = tryDefine(name, stub, resolve);
                if (clazz != null) { defined.put(name, clazz); return clazz; }

                throw new RuntimeException("defineClass failed for " + name);
            }
        }

        /**
         * Attempt to define and optionally resolve a class from raw bytes.
         * Returns the defined Class on success, or null if defineClass throws.
         */
        private Class<?> tryDefine(String name, byte[] bytes, boolean resolve) {
            try {
                Class<?> clazz = defineClass(name, bytes, 0, bytes.length);
                if (resolve) resolveClass(clazz);
                return clazz;
            } catch (Throwable t) {
                return null;
            }
        }

        /**
         * Patch out GETSTATIC instructions that reference fields on poisoned classes.
         * When a class's <clinit> crashed, its static fields were never initialized.
         * Any other class that reads those fields via GETSTATIC will get
         * NoClassDefFoundError (cascade). We replace such GETSTATICs with a
         * null/zero push of the appropriate type so dependents can load cleanly.
         */
        private byte[] patchPoisonedDeps(byte[] classBytes) {
            if (poisonedClasses.isEmpty()) return classBytes;
            try {
                ClassReader cr = new ClassReader(classBytes);
                // Quick check: does this class reference any poisoned class at all?
                boolean[] hasDep = {false};
                cr.accept(new ClassVisitor(Opcodes.ASM9) {
                    @Override public MethodVisitor visitMethod(int a, String n, String d, String s, String[] e) {
                        return new MethodVisitor(Opcodes.ASM9) {
                            @Override public void visitFieldInsn(int op, String owner, String fn, String fd) {
                                if (op == Opcodes.GETSTATIC && poisonedClasses.contains(owner.replace('/', '.')))
                                    hasDep[0] = true;
                            }
                            @Override public void visitMethodInsn(int op, String owner, String name, String desc, boolean itf) {
                                if (op == Opcodes.INVOKESTATIC && poisonedClasses.contains(owner.replace('/', '.')))
                                    hasDep[0] = true;
                            }
                        };
                    }
                }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
                if (!hasDep[0]) return classBytes;

                ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
                cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
                        MethodVisitor mv = super.visitMethod(access, name, desc, sig, exc);
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitFieldInsn(int opcode, String owner, String fname, String fdesc) {
                                if (opcode == Opcodes.GETSTATIC
                                        && poisonedClasses.contains(owner.replace('/', '.'))) {
                                    // Push zero/null of the appropriate type instead
                                    switch (fdesc) {
                                        case "J": super.visitInsn(Opcodes.LCONST_0); break;
                                        case "D": super.visitInsn(Opcodes.DCONST_0); break;
                                        case "F": super.visitInsn(Opcodes.FCONST_0); break;
                                        case "Z": case "B": case "C": case "S": case "I":
                                            super.visitInsn(Opcodes.ICONST_0); break;
                                        default:  super.visitInsn(Opcodes.ACONST_NULL); break;
                                    }
                                    return;
                                }
                                super.visitFieldInsn(opcode, owner, fname, fdesc);
                            }

                            @Override
                            public void visitMethodInsn(int opcode, String owner, String mname, String descriptor, boolean isInterface) {
                                if (opcode == Opcodes.INVOKESTATIC && poisonedClasses.contains(owner.replace('/', '.'))) {
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

        private static boolean isBootClass(String name) {
            return name.startsWith("java.") || name.startsWith("javax.")
                    || name.startsWith("sun.") || name.startsWith("com.sun.")
                    || name.startsWith("jdk.") || name.startsWith("org.xml.")
                    || name.startsWith("org.w3c.");
        }

        private static boolean isVendorClass(String name) {
            // These libraries require native code, on-disk data files, or specific
            // runtime environment setup that is never present when running the dumper.
            // Stubbing them immediately prevents cascade poisoning of dependent classes.
            return name.startsWith("org.lwjgl.")
                || name.startsWith("net.java.games.")
                || name.startsWith("org.joml.")
                || name.startsWith("com.sun.jna.")
                // IBM ICU requires icudt*.icu data files on disk — MissingResourceException
                // cascade-poisons every class that depends on ICU text/date formatting.
                || name.startsWith("com.ibm.icu.")
                // Log4j 2.x loads plugins via ServiceLoader and reads config files at
                // <clinit> time; without them it throws and poisons every logging caller.
                || name.startsWith("org.apache.logging.log4j.");
        }
    }

    // ── Stub generation ───────────────────────────────────────────────────────
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

    // ── Data model ────────────────────────────────────────────────────────────
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

    // ── String / field utilities ──────────────────────────────────────────────
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

    private static boolean interestingImpl(int len, CharAt charAt) {
        if (len < 3) return false;
        int ctrl = 0, highByte = 0, printableAscii = 0;
        for (int i = 0; i < len; i++) {
            char c = charAt.get(i);
            if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') ctrl++;
            else if (c > 0x7e) highByte++;
            else printableAscii++;
        }
        // Tightened: reject any control chars (ciphertext) and cap high-byte at 10%.
        // DES/XOR ciphertext typically contains 5-20% control bytes; real strings have 0.
        return ctrl == 0 && highByte / (double) len <= 0.10 && printableAscii >= 3;
    }

    static boolean interesting(String s) {
        return s != null && interestingImpl(s.length(), s::charAt);
    }

    static boolean interestingChars(char[] arr) {
        return arr != null && interestingImpl(arr.length, i -> arr[i]);
    }

    static boolean isLikelyText(byte[] bytes) {
        int printable = 0, limit = Math.min(bytes.length, TEXT_PROBE_LIMIT);
        for (int i = 0; i < limit; i++) {
            byte b = bytes[i];
            if (b == 0) return false;
            if ((b >= ASCII_PRINTABLE_LOW && b <= ASCII_PRINTABLE_HIGH)
                    || b == '\n' || b == '\r' || b == '\t') printable++;
        }
        return printable / (double) limit > TEXT_PRINTABLE_RATIO;
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
                        String lastLdc = null;

                        @Override
                        public void visitLdcInsn(Object cst) {
                            if (cst instanceof String) {
                                String s = (String) cst;
                                lastLdc = s;
                                if (interesting(s))
                                    emit(results, seenLines, className, "[ldc:" + mname + "]", null, s);
                            } else {
                                lastLdc = null;
                            }
                        }

                        @Override
                        public void visitMethodInsn(int opcode, String owner, String mname2, String desc, boolean itf) {
                            // Class.forName(String) — the preceding LDC is a class name used for reflection.
                            if (lastLdc != null
                                    && owner.equals("java/lang/Class")
                                    && mname2.equals("forName")
                                    && desc.startsWith("(Ljava/lang/String;)")) {
                                String classRef = lastLdc.replace('/', '.');
                                if (interesting(classRef))
                                    emit(results, seenLines, className, "[classref:" + mname + "]", null, classRef);
                            }
                            lastLdc = null;
                        }

                        @Override
                        public void visitInvokeDynamicInsn(String name, String descriptor,
                                                            Handle bsm, Object... bsmArgs) {
                            // Many obfuscators (SkidFuscator, Allatori, Zelix) implement string
                            // decryption via invokedynamic rather than a plain INVOKESTATIC, so
                            // the encrypted payload never appears as an LDC constant. We can't
                            // execute the BSM here, but we emit any String-typed BSM arguments
                            // as hints, and also emit the BSM owner+name as a low-fidelity hint
                            // so the class at least gets *something* in the fallback output.
                            for (Object arg : bsmArgs) {
                                if (arg instanceof String && interesting((String) arg))
                                    emit(results, seenLines, className, "[indy:" + mname + "]", null, (String) arg);
                            }
                            if (!descriptor.endsWith(")Ljava/lang/String;")) {
                                lastLdc = null;
                            }
                        }

                        @Override
                        public void visitInsn(int opcode) { lastLdc = null; }
                        @Override
                        public void visitIntInsn(int opcode, int operand) { lastLdc = null; }
                        @Override
                        public void visitVarInsn(int opcode, int var) { lastLdc = null; }
                        @Override
                        public void visitTypeInsn(int opcode, String type) { lastLdc = null; }
                        @Override
                        public void visitFieldInsn(int opcode, String owner, String fname, String fdesc) { lastLdc = null; }
                        @Override
                        public void visitJumpInsn(int opcode, org.objectweb.asm.Label label) { lastLdc = null; }
                    };
                }
            }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
        } catch (Throwable ignored) {}
    }

    // ── JVM detection and re-execution ────────────────────────────────────────
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

    // ── I/O helpers ───────────────────────────────────────────────────────────
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

    static String topLevelPackage(String className) {
        int first = className.indexOf('.');
        if (first < 0) return "(default)";
        int second = className.indexOf('.', first + 1);
        return second < 0 ? className.substring(0, first) : className.substring(0, second);
    }

    static void printUsage() {
        System.out.println("Usage: java -cp \".;asm-9.8.jar\" ENI_StringDumper [options] <target.jar> [Class.method]");
        System.out.println("Options:");
        System.out.println("  -package <prefix> Filter classes by package (e.g., com.example)");
        System.out.println("  -libs <jar>       Library JAR to add to classloader (repeatable; use for Minecraft jar etc.)");
        System.out.println("  -json             Write per-package JSON files alongside plain logs");
        System.out.println("  -timeout <ms>     Per-class timeout (default 3000)");
        System.out.println("  -threads <n>      Thread pool size (default: CPU count)");
        System.out.println("  -depth <n>        Max recursion depth (default 10)");
        System.out.println("  -brutemax <n>     Max index for parameterized decryptor brute-force (default 512)");
        System.out.println("  -nopatch          Skip anti-analysis patching");
        System.out.println("  -nostubs          Skip ghost class stubs");
        System.out.println("  -out <dir>        Output directory");
        System.out.println("  -noreexec         Skip automatic JVM version re-exec");
    }
}
