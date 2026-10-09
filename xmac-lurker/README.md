# Comparing the 20 `psistorm-XMAC-NN` libraries function by function (2026-10-09)

The libraries are Blizzard's and are not in this repository. With the 20 Mach-O bundles extracted from `psistorm-XMAC-NN.mpq` into a directory:

1. `GHIDRA_SCRIPTS=DIR ./decompile_all.sh LIBDIR OUTDIR` decompiles each with Ghidra headless into `OUTDIR/x00.c` .. `x19.c`. `DIR` must hold a `DecompileAll.java` that writes every function as a block `// ===== NAME @ ADDR  size N =====` followed by its decompiled C (a Ghidra `DecompInterface` loop over `getFunctions(true)`).
2. `python3 lurker_compare.py OUTDIR` compares them.

Result: the eight Lurker functions are identical in all 20 builds after normalization; of the 42 functions of build 05 (without 6-byte import stubs), 40 are identical in all 20 builds and only the compression function and the hash initialisation, the per-build parameters, differ. Normalization is described in the script's docstring.
