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
