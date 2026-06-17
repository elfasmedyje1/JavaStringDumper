# ENI_StringDumper

Java obfuscation string extractor. Originally started by StormingMoon, maintained and extended by elfasmedyje.

Loads an obfuscated JAR, triggers static initializers to run decryption routines, and dumps all recovered strings to an organised output directory.

Works on DES/AES/XOR string encryption, flow obfuscation, native agent loaders, `invokedynamic`-based string tables, index-based decryptors, and more. Auto-detects the required JVM version and re-execs with a compatible one if found.

---

## Requirements

- Java 8+ to run (auto-upgrades to a higher JVM if the target JAR needs it)
- [ASM 9.8](https://mvnrepository.com/artifact/org.ow2.asm/asm/9.8) on the classpath

---

## Compile

```
javac -cp asm-9.8.jar ENI_StringDumper.java
```

---

## Run

```
java -cp .;asm-9.8.jar ENI_StringDumper [options] target.jar
```

On Linux/macOS use `:` instead of `;` in the classpath.

---

## Options

| Flag | Description |
|------|-------------|
| `-json` | Write per-package `.json` files alongside plain `.log` files |
| `-package P` | Filter classes by package prefix (e.g. `com.example`) |
| `-libs JAR` | Add library JAR to classpath for better dependency resolution (repeatable) |
| `-brutemax N` | Max index for brute-forcing parameterized decryptors (default: `512`) |
| `-timeout N` | Per-class processing timeout in ms (default: `3000`) |
| `-threads N` | Worker thread count (default: CPU core count) |
| `-depth N` | Max object graph recursion depth (default: `10`) |
| `-nopatch` | Skip anti-analysis bytecode patching |
| `-nostubs` | Skip ghost class stub generation for missing dependencies |
| `-out DIR` | Custom output directory (default: `<jarname>_dump/` next to the JAR) |
| `-noreexec` | Skip automatic JVM version detection and re-exec |

---

## Output

Results are written to `<jarname>_dump/` next to the input JAR:

```
target_dump/
├── all_strings.txt       all recovered strings, one per line
├── packages/
│   ├── com.example.log   strings grouped by top-level package
│   └── org.lwjgl.log
├── errors.log            load/field/invoke failures with full cause chains
└── summary.txt           run metadata, settings, package breakdown
```

Source tags in the package logs indicate how each string was recovered:

| Tag | Meaning |
|-----|---------|
| `ClassName.fieldName` | Static or instance field value after `<clinit>` ran |
| `[ldc:method]` | Raw LDC constant from bytecode (class failed to load) |
| `[indy:method]` | String argument from an `invokedynamic` BSM (static extraction) |
| `[bsm:method]` | String recovered by executing the `invokedynamic` bootstrap method |
| `[strtable:Class.field][N]` | Entry N from a detected static `String[]` table, attributed to the accessing class |
| `[classref:method]` | Class name passed to `Class.forName()` — reflection anchor |
| `method(brute)[N]` | String returned by a parameterized decryptor at index N |

---

## Example

```
java -cp .;asm-9.8.jar ENI_StringDumper -json -threads 8 someobfuscated.jar
```

---

## How it works

1. **Dependency analysis** — scans all class bytecode to build a dependency graph and identify missing external classes that need stubs
2. **Topological sort** — processes classes in dependency order to minimise cascade failures
3. **Multithreaded loading** — loads and initialises classes in parallel, triggering `<clinit>` to run decryption routines
4. **Anti-analysis patching** — rewrites bytecode before loading to neutralise common obfuscation guards:
   - Timing checks (`nanoTime`, `currentTimeMillis`, `Thread.getId`, `Thread.threadId`) → stable constants
   - Stack inspection (`getStackTrace`, `getCallerClass`, `StackWalker`) → empty/null
   - Native loads (`System.load`, `Runtime.loadLibrary`) → no-ops
   - Unsafe memory ops → zero returns
   - Cipher lifecycle (`Cipher`, `SecretKeyFactory`, `javax.crypto.spec.*`) → stubs so `BadPaddingException` does not cascade
   - JNA / LWJGL / Log4j version-mismatch calls → zero returns
   - Bytecode integrity checks (`Class.getResourceAsStream`) → null
5. **Ghost class stubs** — generates minimal stub classes for missing dependencies so the target JAR loads even without its full runtime environment
6. **Poison propagation patching** — tracks classes whose `<clinit>` failed and patches out `GETSTATIC`/`INVOKESTATIC` references to them in dependents
7. **Multi-tier defineClass fallback** — patched bytes → recomputed frames → full ASM rewrite → original bytes → stub, in that order
8. **Single-thread retry** — after the parallel pass, classes that failed are retried single-threaded in topological order to recover from race conditions
9. **String array index pass** — scans bytecode for `GETSTATIC String[] + int + AALOAD` patterns and attributes the resolved string to the accessing class
10. **`invokedynamic` BSM execution** — attempts to reflectively bootstrap `invokedynamic` call sites that return `String` to recover runtime-decrypted values
11. **Brute-force decryptors** — calls static `(int) -> String` and `(long) -> String` methods with indices 0..brutemax to extract index-based string tables
12. **LDC fallback** — for classes that fail entirely, extracts raw string constants from the constant pool including `invokedynamic` BSM arguments and `Class.forName` reflection anchors
