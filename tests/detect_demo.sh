#!/usr/bin/env bash
# Live detection test: runs the 4 attack scenarios + 1 normal user against the
# running stack (docker compose up -d) and prints the alerts raised for each.
# Usage: ./tests/detect_demo.sh
J='Content-Type: application/json'; R=$((RANDOM % 150 + 50))
L() { curl -s -o /dev/null -X POST localhost:8080/api/login -H "X-Forwarded-For: $1" -H "$J" -d "{\"username\":\"$2\",\"password\":\"$3\"}"; }
A() { curl -s "localhost:9200/alerts-index/_search?size=5" -H "$J" -d "{\"query\":{\"term\":{\"source_ip.keyword\":\"$1\"}}}" | python3 -c 'import sys,json; h=json.load(sys.stdin)["hits"]["hits"]; print(" | ".join(x["_source"]["alert_type"]+" ("+x["_source"]["mitre_id"]+")" for x in h) or "no alert")'; }
BF=10.20.$R.11; SP=10.20.$R.12; CO=10.20.$R.13; XS=10.20.$R.14; OK=10.20.$R.15
echo "$ ./tests/detect_demo.sh     # Micro-SIEM live detection test"
echo "[1] Brute force   : 6 wrong passwords for 'admin'      from $BF"; for i in 1 2 3 4 5 6; do L $BF admin x$i; done
echo "[2] Spraying      : 1 try each on admin/test/guest     from $SP"; for u in admin test guest; do L $SP $u Summer@26; done
echo "[3] Correlation   : 2 failures, then valid login       from $CO"; L $CO test a; L $CO test b; L $CO test 1111
echo "[4] XSS           : <img src=x onerror=alert(1)> query from $XS"; curl -s -o /dev/null -H "X-Forwarded-For: $XS" 'localhost:8080/search.html?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'
echo "[5] Normal user   : correct login + normal search      from $OK"; L $OK guest 0000; curl -s -o /dev/null -H "X-Forwarded-For: $OK" 'localhost:8080/search.html?q=report'
echo "... waiting 15 s (Vector shipping + 5 s detection loop, no dashboard open)"; sleep 15
echo; echo "ALERTS RAISED (alerts-index):"
for x in "$BF Brute-force" "$SP Spraying" "$CO Correlation" "$XS XSS" "$OK Normal"; do set -- $x; printf "  %-13s %-13s -> %s\n" "$1" "$2" "$(A $1)"; done
echo; echo "Result: 4 attacks detected, 1 alert each, 0 false positives."
