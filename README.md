# UnConfuserEx
[![.NET](https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![target](https://img.shields.io/badge/target-ConfuserEx2-A42E2B)](https://github.com/mkaring/ConfuserEx)
[![Website](https://img.shields.io/badge/zypherion.tech-1f6feb?logo=googlechrome&logoColor=white)](https://www.zypherion.tech)
[![Discord](https://img.shields.io/badge/Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/JXx32jKJXY)
[![Telegram](https://img.shields.io/badge/Telegram-26A5E4?logo=telegram&logoColor=white)](https://t.me/zypherion_technologies)
[![X](https://img.shields.io/badge/Follow-000000?logo=x&logoColor=white)](https://x.com/Zypherion_Tech)

> Enhanced fork of UnconfuserEx with improved support for modern ConfuserEx2 variants, anti-tamper recovery, compressor removal, control-flow restoration, and resource reconstruction.

---

If u ever played with malware samples, some of them are obfuscated with ConfuserEx, and ive tried some public deobfuscators against the latest but it just wouldnt work, so ive decided to fork a public one which did work against that latest ver and just mod it to my needs.

This repo is a fork of [MadMin3r/UnconfuserEx](https://github.com/MadMin3r/UnconfuserEx). Credit goes to him as well. The original project did the hard part of making a focused ConfuserEx2 deobfuscator that could actually remove real protections.

That is what this project does. Runs a list of removers in a fixed order, rewrites method bodies/resources/metadata where it can, and writes a new assembly back out. The important part is the order. Compressor and anti tamper have to happen early because the rest of the module might not even be real IL yet.


---

The upstream version was already useful, but a few cases kept showing up.

One was the LZMA path. Some samples hand you bytes that look like the constants/resources payload, but the LZMA properties are nonsense. If you pass that straight into the decoder, you get stupid dictionary sizes and eventually exceptions like array dimensions exceeding the supported range. So the local version checks the properties, caps the dictionary size, caps the uncompressed size, and bails before the decoder allocates something ridiculous.

```text
LZMA properties => CE FD 62 5F 9F
Invalid LZMA properties byte 0xCE or unreasonable dictionary size
```

---

Constants had another dumb but real problem. A lot of the resolver code wants the ID sitting in front of the getter call to be an `ldc.i4`. Sometimes it is not one instruction anymore. It is a tiny arithmetic expression.

```il
ldc.i4     0x1234
ldc.i4     0x55
xor
call       string <const getter>(int32)
```

Old code sees `xor`, calls `GetLdcI4Value()`, and dies because `xor` is obviously not an integer load. The local version walks back over the small arithmetic sequence, emulates the stack, collapses it back into one `ldc.i4`, and then lets the normal resolver keep going.

So instead of treating this as a totally different constants protection, it becomes this:

```il
ldc.i4     0x1261
call       string <const getter>(int32)
```

Then the existing normal/x86 constant resolver path can do its job.

---

Control flow is where it was meh

The switch remover can handle the normal ConfuserEx switch dispatcher shape. It walks blocks, recovers the next target, deletes dead blocks, and emits a sane method body. But there are samples where only part of the method is understood. If you mutate half a method and then discover it is still obfuscated, the output is worse than useless because now you have broken IL and no clean way to reason about what happened.

So the local version snapshots the method body before touching it:

```text
instructions
exception handlers
```

If deobfuscation throws, or if the method still looks obfuscated afterwards, the original body gets restored. The log can still say "this method was not solved", but the assembly does not get silently corrupted just because one method had a weird dispatcher.

Jump/trampoline control flow got its own pass too. Some methods are not just switch dispatchers. They are small branch trampolines chained together until the real block is reached. Those now get detected and folded instead of being ignored by the switch only path.

---

The compressor remover is the part that has to run before everyone else.

ConfuserEx compressor stubs usually keep the real assembly compressed, boot a tiny loader, decompress the payload, and load it at runtime.

The remover finds the loader shape, extracts the embedded payload, decompresses it, and swaps the module over to the real assembly. Normal and compact compressor layouts are both handled.

```text
[+] Compressor detected
[+] Extracted compressed module payload
[+] Decompressed real module
[+] Continuing pipeline on unpacked assembly
```

---

Anti-tamper has two paths now.

Normal/dynamic anti tamper decrypts method bodies from protected sections and writes the restored bodies back into the module. JIT anti tamper is more annoying because the bodies are meant to be materialised when the runtime asks for them.

The rough shape is:

```text
find init
extract keys
find encrypted JIT body section
derive per method key
read body
write CilBody back
```

This is still pattern based. If the stub changed enough, it will miss, obv.

---

Resources are handled similarly to constants: find the encrypted resource blob, recover the key/decryptor shape, decrypt, decompress if needed, then put the resources back where normal .NET tooling expects them.

There is also an optional embedded PE rebuild path. Some protected samples carry a managed PE inside a resource. With rebuild enabled, the remover tries to parse and rewrite that payload too instead of leaving a deobfuscated outer assembly with an untouched inner one.

```text
UnConfuserEx.exe sample.exe sample.clean.exe --rebuild-embedded-pe
```

Use that when you know the sample hides another managed assembly inside resources. If the payload is not a managed PE, the rebuild path should leave it alone.

---

# Usage

Build it:

```powershell
dotnet build .\UnConfuserEx.sln -c Release
```

Run it:

```powershell
.\UnConfuserEx\bin\Release\net9.0\UnConfuserEx.exe .\protected.exe
```

Or give it an explicit output path:

```powershell
.\UnConfuserEx\bin\Release\net9.0\UnConfuserEx.exe .\protected.exe .\protected.clean.exe
```

If you do not give an output path, it writes one next to the input with `-deobfuscated` added to the name.

For embedded managed payloads:

```powershell
.\UnConfuserEx\bin\Release\net9.0\UnConfuserEx.exe .\protected.exe .\protected.clean.exe --rebuild-embedded-pe
```

---

# Protections

This is the current support list. It does not mean every possible ConfuserEx fork works. It means these are the shapes the pipeline knows how to look for.

- [x] Anti-debug
  - [x] Safe
  - [x] Win32
  - [x] Antinet
- [x] Anti-dump
- [x] Anti-tamper
  - [x] Normal
  - [x] Dynamic
  - [x] JIT
  - [x] JIT dynamic
- [x] Compressor
  - [x] Normal
  - [x] Compact
- [x] Constants
  - [x] Normal
  - [x] Dynamic expression
  - [x] x86
  - [x] Small arithmetic ID collapse before getter calls
- [x] Control flow
  - [x] Switch dispatcher
  - [x] Jump/trampoline blocks
  - [x] Snapshot/restore when a method cannot be safely solved
- [x] Reference proxy
  - [x] Normal
  - [x] Dynamic expression
  - [x] x86
- [x] Renamer
  - [x] Non-ASCII names get replaced with readable generic names
- [x] Resources
  - [x] Normal
  - [x] Dynamic
  - [x] Optional embedded managed PE rebuild
- [x] Static cleanup
  - [x] Obfuscator attributes
  - [x] dead global helpers/fields where safe
  - [x] unreachable junk types where safe

There is probably more hidden in the code that i forgot to list xD.

---

# Logs

The useful logs are the ones that tell you which stage failed, not just that the output did not run.

Example of a constants path that got fixed:

```text
Constants detected, attempting to remove
Found 3 constant getter(s)
Detected constant decryption type is Dynamic
Decompressed constants blob to 18492 byte(s)
Resolving getter <Module>::???????? as String with 41 call site method(s)
Removed all instances of getter <Module>::????????
```

Example of a control-flow method that is intentionally left alone:

```text
Removing obfuscation from method System.Void Example::Run()
Method System.Void Example::Run() still appears obfuscated after deobfuscation -- left original body intact
Removed obfuscation from 42 methods. Failed to remove from 0 methods. 1 methods left untouched
```

That second log is not perfect, but it is ATLEAST honest

---

# Things this does not magically solve

A custom ConfuserEx fork that changes every helper shape.

A constants getter that computes its ID through a full cf mess instead of a small stack expression.

A cf graph where the dispatcher depends on runtime values the static emulator does not know.

Native helpers that need actual runtime execution instead of IL emulation.

Assemblies that were already broken before they got obfuscated.

JIT anti-tamper variants with a different encrypted body layout.

---

# Reporting issues

If you want an issue to be useful, include enough data to reproduce it.

Remove the file extensions from samples before uploading them.

Archive everything together and include this:

```text
Command:
UnConfuserEx.exe <target> <optional output>

Failure stage:
- compressor
- anti tamper
- constants
- control flow
- resources
- writing output
- runtime after deobfuscation

Expected result:

Actual result:

Console output:

Archive link:

Notes / investigation:
```

If all you send is "does not work", the answer is probably going to be "yeah".

---

# How does it look like after de-obfuscation?
### Before:

<img width="1270" height="576" alt="image" src="https://github.com/user-attachments/assets/5de991a3-23da-4527-ac07-baa773a9713a" />
<img width="1690" height="850" alt="image" src="https://github.com/user-attachments/assets/62db6069-5857-4f73-a40d-7b23f60e69d3" />

### After: 

<img width="1250" height="691" alt="image" src="https://github.com/user-attachments/assets/c6aee9c8-65e3-419a-8c9c-7e53416ec029" />
<img width="1274" height="582" alt="image" src="https://github.com/user-attachments/assets/a7e2ef00-d817-4b41-8f82-dc6a30f93bff" />


# Contributing

Small focused fixes are better than giant rewrites.

If you add support for a new protection shape, keep it isolated to the remover that owns it. If you add fallback behavior, make sure failure does not corrupt the output assembly. If you touch control flow, assume the weird sample you fixed is not the only weird sample that exists :DDD.

Just DO NOT make the tool harder to debug.

# Credits

This project is based on MadMin3r/UnconfuserEx.

The original project provided the foundation and most of the core deobfuscation pipeline. This fork focuses on improving reliability, adding support for additional protection variants, and handling edge cases observed in real world samples.

# Note

This project started as a practical reverse-engineering tool rather than a software engineering exercise. The focus has always been on recovering protected assemblies reliably rather than maintaining perfect code quality.

# Disclaimer

This tool is intended for malware analysis, reverse engineering, software recovery, interoperability, and educational research purposes.


