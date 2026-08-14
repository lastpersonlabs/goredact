#!/usr/bin/env zsh
set -euo pipefail

if (( $# != 3 )); then
  print -u2 "usage: $0 CORPUS_FILE GOREDACT_BINARY GITLEAKS_BINARY"
  exit 2
fi

corpus_file=$1
goredact_binary=$2
gitleaks_binary=$3
runs=${RUNS:-3}

if [[ ! -f $corpus_file ]]; then
  print -u2 "missing corpus file: $corpus_file"
  exit 1
fi

corpus_dir=${corpus_file:h}

print $'tool\tscenario\tcores\trun\telapsed_s\tuser_s\tsystem_s\tmax_rss_kib'

for tool in goredact gitleaks; do
  for run in {0..$runs}; do
    report_file="${TMPDIR:-/tmp}/gitleaks-onecore-${run}.json"
    TIMEFMT=$'%E\t%U\t%S\t%M'
    if [[ $tool == goredact ]]; then
      timing=$(
        { time taskset -c 0 env GOMAXPROCS=1 "$goredact_binary" stream \
            -profile balanced -input "$corpus_file" -output - >/dev/null
        } 2>&1
      )
    else
      timing=$(
        { time taskset -c 0 env GOMAXPROCS=1 "$gitleaks_binary" detect \
            --no-git --source "$corpus_dir" --max-decode-depth 0 \
            --max-archive-depth 0 --redact=100 --no-banner --no-color \
            --log-level error --report-format json --report-path "$report_file" \
            --exit-code 0
        } 2>&1
      )
      rm -f "$report_file"
    fi
    # Run zero warms code and filesystem caches; measured output starts at one.
    if (( run > 0 )); then
      print "$tool\tquiet\t1\t$run\t$timing"
    fi
  done
done
