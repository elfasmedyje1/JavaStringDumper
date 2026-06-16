# ENI_StringDumper

Java obfuscation string extractor by StormingMoon.

Loads an obfuscated JAR, triggers static initializers to run decryption routines, and dumps all recovered strings to an organised output directory.

Works on DES/AES/XOR string encryption, flow obfuscation, native agent loaders, and more. Auto-detects the required JVM version and re-execs with a compatible one if found.

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
| `-brutemax N`| Max index for brute-forcing parameterized decryptors (default: `512`) |
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

---

## Example

```
java -cp .;asm-9.8.jar ENI_StringDumper -json someobfuscated.jar
```
