#!/bin/sh
# runs on the Mac Pro: for each case, fresh copy of the XMAC lib, harness-as-Diablo-II-exe plus pad
cd ~/xmac || exit 1
A="fake/Diablo II.app/Contents"; X="$PWD/$A/MacOS/Diablo II"
while read nn sz vs; do
  cp harness "$X"; yes abcdefghij0123456789 | head -c $sz >> "$X"
  cp lib/psistorm-XMAC-$nn run/ps
  out=$("$X" "$PWD/run/ps" "$X" "" "" $vs 2>&1)
  echo "$nn $sz $vs $out"
done < cases.txt
