#!/usr/bin/env bash
# Stands in for "ssh DEST" in tests: answers the commands run.sh sends to the server.
case "$1" in
  nproc) echo 8 ;;
  grep*) echo "MemTotal:       16000000 kB" ;;
  "uname -r") echo "6.1.0-test" ;;
  "docker stats"*) echo "dnsdist 120MiB / 16GiB 310%"; echo "unbound 900MiB / 16GiB 95%" ;;
  "docker ps"*) echo "dnsdist powerdns/dnsdist-19:1.9.16" ;;
  *) exit 1 ;;
esac
