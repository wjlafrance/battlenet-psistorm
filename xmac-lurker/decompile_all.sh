#!/bin/bash
# usage: decompile_all.sh LIBDIR OUTDIR     LIBDIR holds psistorm-XMAC-00 .. -19 (the Mach-O bundles extracted from the MPQs)
# Decompiles every function of each library with Ghidra headless (4 at a time) into OUTDIR/xNN.c.
LIB=$(cd "$1" && pwd); OUT=$(mkdir -p "$2" && cd "$2" && pwd)
G=${GHIDRA_HEADLESS:-/opt/homebrew/Cellar/ghidra/12.0.4/libexec/support/analyzeHeadless}
SCRIPTS=${GHIDRA_SCRIPTS:?set GHIDRA_SCRIPTS to a directory holding a DecompileAll.java that writes every function as "// ===== NAME @ ADDR  size N =====" blocks}
run() { nn=$1; mkdir -p "$OUT/proj$nn"; "$G" "$OUT/proj$nn" "x$nn" -import "$LIB/psistorm-XMAC-$nn" -postScript DecompileAll.java "$OUT/x$nn.c" -scriptPath "$SCRIPTS" -deleteProject > "$OUT/run$nn.log" 2>&1; }
n=0
for i in $(seq 0 19); do run $(printf %02d $i) & n=$((n+1)); [ $((n%4)) -eq 0 ] && wait; done; wait
