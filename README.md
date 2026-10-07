# psistorm: the classic-Mac Battle.net version check

`psistorm-PMAC-NN.mpq` is the challenge Battle.net sends a classic-Mac client (platform `PMAC`) in place of the Windows
**Lockdown** challenge. It was introduced in November 2006. The challenge is a code library the client runs over three of its
own files; the result goes back to the server in `SID_AUTH_CHECK` / `SID_REPORTVERSION`. Nothing public described the
algorithm (a 2006 BNETDocs call for research drew no answer, vL forum thread 161449). This repository documents it, with C code
that reproduces a real Mac client's answer exactly.

Status: archival research notes and sample code (2026-10-06). The target is a 2006 version check on a game that stopped
being updated years ago.

## Summary
- **One program, 20 parameter sets.** `psistorm-PMAC-00` ... `-19` are the same program. Each differs in the parameters of a
  hash that is built on the **RIPEMD-160 skeleton but is not RIPEMD-160**: initial state, round constants, message-word order,
  rotation amounts, and one rotation applied to the third working variable are all per-build parameters.
- **The answer** is `HMAC(key = seed, message = file1 || file2 || file3)` with that hash, where the seed is the server's value
  string passed through a base-255 transform. The checksum is the first 4 digest bytes; the "EXE info" is a base-255 re-encoding of the
  other 16 digest bytes.
- **Verified end to end against a real client** for builds 04 and 02 (below): a real Mac Diablo 1.09 client's and a real Mac Warcraft II 2.02 client's answers are reproduced
  exactly by `c/psistorm.c`.

## Why it exists, and how it relates to Lockdown
- **Closing a loophole.** Lockdown (Windows, October 2006) made bot logins hard, and bots worked around it by claiming to be a Mac: the Mac challenges at the time were the old file-hash formula, which a hashing server could answer without the real client. A forum poster reported that psistorm ended that workaround (vL message 161327, 2006-11-18) and another had predicted Blizzard would notice that PMAC/XMAC logins were a way around Lockdown (message 161455). The fragments were built 9 days after the Lockdown DLLs and first seen on the wire 8 days after that. That is the likely reason for a purpose-built Mac check *(inference from the forum thread and the dates)*.
- **Shared pieces.** Psistorm and Lockdown use the same value-string transform and the same exe-info transform, and both key an HMAC-style construction (ipad `0x36`, opad `0x5C`) with the 16-byte seed. Both were produced as a batch of 20 randomised builds: Lockdown's DLLs differ in two seed constants and function layout (one algorithm, two compiles), psistorm's fragments differ in every parameter of the hash.
- **Different inputs.** Lockdown hashes in-memory PE module images (undoing relocations with the per-DLL seed), the DLL's own image and a screen capture. Psistorm hashes three files raw, with no format interpretation and no screen. It is the simpler algorithm; the per-build randomisation is the elaborate part, and it is a generator over one template, not 20 hand-written programs *(inference: all 20 were compiled in about ten minutes)*.
- **The name.** Psionic Storm is the StarCraft High Templar ability, and Lockdown is a StarCraft Ghost ability: Blizzard named both after in-game spells *(inference; nothing says so)*.

## The other Mac challenges
| Archive | What it is |
|---|---|
| `ver-PMAC-0.mpq` | PowerPC CFM fragment, the Formula-Padded check (byte-swapped words; version and date from an 8-byte trailer at the end of the executable), stamped 2006-08-29 |
| `ver-XMAC-0.mpq` | PowerPC fragment linked against CarbonLib, stamped 2006-08-11; the original `XMAC` challenge, probably the same algorithm as `ver-PMAC-0` *(not disassembled)*; still served by `connect-forever.classic.blizzard.com` |
| `ver-OSXI-0.mpq` | Intel Mach-O bundle; the same Formula-Padded machinery, with the exe version and date read from `Version.txt` and `DateTime.txt` in the app bundle; what useast serves `XMAC` clients now |
| `psistorm-PMAC-NN.mpq` | this repository |

## Where it appears
| Observation (2026-10-06, `useast.battle.net`) | |
|---|---|
| Platform `PMAC`, W2BN with verbyte `0x4F`, DRTL or DSHR with `0x2A` | `psistorm-PMAC-NN.mpq`, NN seen over 00-19 |
| Any other verbyte on `PMAC` (all 256 tried for W2BN and DRTL) | `ver-PMAC-0.mpq`, the Mac Formula check (`A=0 B=0 C=0 4 A=A+S C=C+A`) |
| Platform `XMAC` (Mac OS X) | `ver-OSXI-0.mpq` (an Intel Mach-O bundle), never psistorm |
| Real Mac Diablo **v1.08** client | verbyte `0x28`: got `ver-PMAC-0`, was told to patch (`DRTL_PMAC_108_109.mpq`) |
| Real Mac Diablo **v1.09** client | verbyte `0x2A`: got `psistorm-PMAC-04`, answered, passed |

The first public sighting of a psistorm challenge is a packet capture naming `psistorm-PMAC-15` on 2006-11-17 (vL forum
message 161311). The 20 fragments are PEF files (PowerPC Code Fragment Manager) stamped **2006-11-08, 18:34:13 to 18:44:49**,
in NN order, 28 to 39 seconds apart: one batch of 20 generated builds. A PEF stamp has no time zone. The archives' original file times on a server that still
carries them are 2006-11-09 02:58:04-06 UTC, about 14 minutes after the last stamp if the stamps are Pacific time (UTC-8), so that is the likely reading.
(The 20 Windows Lockdown DLLs are stamped 2006-10-30 22:28:31 to 22:29:48 UTC, about nine and a half days earlier, in the same batch fashion.)

## The challenge
Server to client, the usual `SID_AUTH_INFO` (0x50) or `SID_STARTVERSIONING` (0x06) fields: the archive name
`psistorm-PMAC-NN.mpq`, a FILETIME, and a **binary value string** (16 bytes in the 2026 captures, followed by a NUL). The MPQ holds one PEF
fragment exporting `CheckRevision`, plus a resource fork (`cfrg`). The export has the same shape as the Windows one:

    CheckRevision(file1, file2, file3, valueString, *exeVersion, *checksum, exeInfo)  ->  1 on success, 0 on failure

## The algorithm
1. **seed** = value string transformed to 16 bytes: for each input byte from the last to the first, multiply the 16-byte
   little-endian buffer by 255, then add `byte - 1`. Fails (returns 0) if it needs more than 16 bytes. (The same transform the
   Windows Lockdown uses.)
2. **exeVersion** = the last 4 bytes of file 1, little-endian. (Mac Diablo 1.09's `Diablo` ends `02 09 00 01`, version 1.00.09.02; `Warcraft II BNE` ends `01 02 00 02` for `0x02000201`.)
3. **digest** = HMAC over `file1 || file2 || file3`: key = the seed zero-extended to 64 bytes, ipad `0x36`, opad `0x5C`, 20-byte
   inner digest. The files are read whole (0x4000-byte chunks, no padding, no interpretation of their format); a file that cannot
   be opened is skipped.
4. **checksum** = digest bytes 0-3, little-endian.
5. **exeInfo** = digest bytes 4-19 as a little-endian 128-bit number, divided by 255 repeatedly, emitting `remainder + 1` each
   time until the number is zero (up to 17 bytes, never containing a 0 byte). (The same transform as the Windows Lockdown's
   digest shuffle.)

### The hash
MD framing (64-byte blocks, little-endian message words, `0x80`, zeros, 64-bit little-endian bit count, state words written
little-endian) around a compression function that is the RIPEMD-160 skeleton with **every number a parameter**:

    two lines of 80 steps over the same block (steps 0-79 and 80-159 of the table); per step:
        t = rotl(a + f(b, c, d) + X[word] + K, rot) + e;   a = e;  e = d;  d = rotl(c, ROT_C);  c = b;  b = t
    then the RIPEMD-160 combination:
        t = h1 + c_left + d_right;  h1 = h2 + d_left + e_right;  h2 = h3 + e_left + a_right;
        h3 = h4 + a_left + b_right; h4 = h0 + b_left + c_right; h0 = t

A build is `INIT[5]`, `ROT_C`, and 160 steps of `{word, truth table of f, K, rot}` (`builds/psistorm-PMAC-NN.json`). In all 20
builds each block of 16 steps uses one of the **five standard RIPEMD-160 boolean functions** (as an 8-bit truth table: `0x96`
XOR, `0xD8` mux, `0x4B` `(x|~y)^z`, `0xAC` mux with arguments swapped, `0x65` `x^(y|~z)`) and a **permutation of the 16 message
words**; there are 8 distinct non-zero constants (9 in builds 03, 13, 15 and 19) besides 0; `ROT_C` is 2, 6, 10 or 14
(10 only in builds 01, 03, 04, 05, 12, 14). So each build is a randomly shuffled RIPEMD-160.

| NN | initial state h0..h4 | ROT_C | non-zero constants |
|---|---|---|---|
| 00 | `99a56345 70c3cfed 39b3a876 62953bce 88cfa5b0` | 2 | 8 |
| 01 | `8d5aca11 e8d31319 1e26bede c2ae75d6 fc2790f0` | 10 | 8 |
| 02 | `84490563 7bf7b1fb 2c1e7e3a 346fd1a2 167d9fd0` | 14 | 8 |
| 03 | `c4126780 3c5f5408 9d7dd3fd 2530e775 394f99ef` | 10 | 9 |
| 04 | `71f409b1 ab9c1fb9 7a271f9e 407f0996 b76cd6f0` | 10 | 8 |
| 05 | `a53cda9 92ac7f71 55527fae ccf9cde6 73c00770` | 10 | 8 |
| 06 | `401ab133 cccfa44b c7b8969a 3b03a382 eaa782d0` | 14 | 8 |
| 07 | `98ea0ca7 7728555f 47cabbb2 698c72fa 4e6bf390` | 6 | 8 |
| 08 | `e697f8f7 91d6cc2f 9a7dd312 ef3effda 98dace90` | 6 | 8 |
| 09 | `784f39e7 56f98c9f 9302132 2a85ce7a e4079f90` | 6 | 8 |
| 10 | `5fee1db af932e33 57f72d4a ae62e0f2 aa84850` | 14 | 8 |
| 11 | `1c951ad5 58740bfd 53ace956 17cdf82e 902c4cb0` | 2 | 8 |
| 12 | `a3159ec9 13136991 cee63d6e 5ee872a6 3d373570` | 10 | 8 |
| 13 | `654da43c 47cf14a4 23650e85 40e39e1d 9c65062f` | 2 | 9 |
| 14 | `81cf62a1 808fb829 7bd93dbe 7d18e836 120827f0` | 10 | 8 |
| 15 | `2499f48e 9fcf086 a97fa3e1 c41ca7e9 2953c50f` | 6 | 9 |
| 16 | `5dc29f2d b8da5f15 cd09e8a6 71f228be f8ca3730` | 2 | 8 |
| 17 | `caa674f7 bdd7282f dd54db12 ea2427da 20ab0e90` | 6 | 8 |
| 18 | `8b139dcd 6c08a2b5 3ab7cb66 59c2c67e a5018d30` | 2 | 8 |
| 19 | `24297526 348f41de fa956ab1 ea2f9df9 7f4e6b8f` | 6 | 9 |

## Verification
- **Real client (build 04).** A real Mac Diablo 1.09 client in a Mac OS 9 VM, served `psistorm-PMAC-04` by the live server
  (verbyte `0x2A`, value string `11ea193a1ef30cf4103fd130438193df`), answered exe version `0x01000902`, checksum `0x761B6192`,
  exe info `12e711545243f72d82c7298d559addd5`; the server replied "passed". `c/psistorm.c` built with
  `c/psistorm_build_04.h`, over the client's installed **`Diablo`, `Storm` and `Battle.net` data forks, in that order**, reproduces all three values
  exactly. The packets and the files' SHA-256s are in `real-client-vector-04.json`:

  | file (data fork) | bytes | SHA-256 |
  |---|---|---|
  | `Diablo` | 1,160,990 | `5c73c27fb6a25bdc7fc38a86336f0bdbf6b1a5ef06ea5f272e572a5861320dbb` |
  | `Storm` | 615,178 | `ce3531b9c4c2e3d90d5509e2fc4ffe5f1183471d6828b7eb97611c8296f2c87c` |
  | `Battle.net` | 213,397 | `bbc8d6fb338fd76b1800b9eaae1b68322134f1907643bcd43397722e96037ac7` |

  The files are Blizzard's and are not in this repository. `python3 tests/run_tests.py DIR` runs the check if you have them.
- **Real client (build 02, Warcraft II BNE 2.02).** The Mac Warcraft II client answered `psistorm-PMAC-02` (value string `bb3b059f39850b6e44413e7354c47d73`) with exe version `0x02000201`, checksum `0xEAA8AA30`, exe info `12b51c7cdd7097212c013148bb915fc1`. `c/psistorm.c` built with `c/psistorm_build_02.h` over the data forks of **`Warcraft II BNE`, `Storm` and `Battle.net`, in that order**, reproduces all three exactly (`real-client-vector-02-w2bn.json`, with the files' SHA-256s). Same function and file roles as Diablo, with the game executable first.
- **The PowerPC code itself.** The parameters were read from the real fragments: Ghidra decompilation of each build's compression
  function (about 1,450 straight-line statements per build, every parameter behind a tiny constant-returning function), lifted to Python and run with
  instrumented stubs, which gives the tables with no heuristics. The lifted functions were compared with Ghidra's p-code
  emulation of the real PowerPC code (8 random blocks per build, all 20 builds, plus build 14 end to end: hash, HMAC, both
  transforms), and the table-driven form reproduces the lifted function of every build on 30 of 30 random blocks.
- **Against the live server.** DRTL on `PMAC` **checks the hash.** Correct answers from `c/psistorm.c` (over the three files above) were accepted
  (result `0x000`) for builds 00, 04, 12, 14, 16 and 18, 8 of 8 runs; a wrong checksum was refused with `0x100` and the patch offer
  `DRTL_PMAC_108_109.mpq` in 4 of 4 runs (checksum XOR 1, 2, `0x80000000`, `0xDEADBEEF`, with the correct exe version). The exe-version dword in the answer is
  **not validated**: with the correct checksum, versions 0, 0xFFFFFFFF, 1.08, 1.09 and 1.0A.00 all passed. So the server verifies the checksum (DRTL reports
  a mismatch as "old version", not `0x102`), and acceptance of the answers from this code is a server-side check of the implementation.
- **W2BN live.** With a CD key block in the 0x51, a correct answer from `c/psistorm.c` over the Mac 2.02 files passed (`0x000`) and a wrong checksum got `0x102`; the exe-version dword is not validated (`0xFFFFFFFF`, `0x02000200` and `0` all passed). A 0x51 without a key block gets no reply.
- **Tests here.** `synthetic-vectors.json` has an answer per build for synthetic files, computed by an independent
  implementation; `tests/run_tests.py` checks `c/psistorm.c` on all 20 builds and `psistorm_ref.py` (pure Python) on four.

## What is not verified
- Builds other than 02 and 04 against a real client; only those two have a real answer, and only build 14 was checked end to end against the emulated PowerPC
  code (the other 18 share the wrapper code).
- Builds 01-03, 05-11, 13, 15, 17 and 19 against a server or client that accepted a correct answer (see below for the ones that did). Only wrong answers were sent for 06 and 19, and the other builds were never drawn.
- Which three files a real client hashes for products other than Mac Diablo and Mac Warcraft II. Diablo: `Diablo`, `Storm`, `Battle.net`; Warcraft II: `Warcraft II BNE`, `Storm`, `Battle.net`.
- `psistorm-XMAC-NN` (named in a 2006 forum post) has never been seen served.
- Another server, `connect-forever.classic.blizzard.com`, serves the same psistorm archives but refused every correct answer we sent for W2BN (six draws, exe version varied). Why is not established; it may simply not authenticate Mac builds (untested guess).
- A 0 byte in the value string adds `0xFFFF` in step 1 with truncating stores in the C code; the original's behavior for that case
  was not tested (real value strings are random bytes, so it is rare).

## Files
| | |
|---|---|
| `c/psistorm.c` | the program: hash, HMAC, both transforms, `ps_check_revision()`, and a small CLI (`-DPS_CLI`) |
| `c/psistorm_build_NN.h` | per-build parameters (generated by `c/gen_headers.py` from `builds/`) |
| `builds/psistorm-PMAC-NN.json` | the same parameters as data |
| `psistorm_ref.py` | the algorithm in plain Python (slow) |
| `real-client-vector-04.json`, `real-client-vector-02-w2bn.json`, `synthetic-vectors.json`, `tests/run_tests.py` | test vectors and runner |

## Build and run
    cc -O2 -DPS_CLI -DPS_BUILD_HEADER='"psistorm_build_04.h"' -Ic c/psistorm.c -o ps04
    ./ps04 Diablo Storm Battle.net 11ea193a1ef30cf4103fd130438193df
    # version=01000902 checksum=761b6192 info=12e711545243f72d82c7298d559addd5

Not included, on purpose: the challenge archives and fragments themselves, and any Blizzard game files.
