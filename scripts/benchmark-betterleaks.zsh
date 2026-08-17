#!/usr/bin/env zsh
set -euo pipefail

if (( $# < 3 || $# > 5 )); then
  print -u2 "usage: $0 CORPUS_FILE GOREDACT_BINARY BETTERLEAKS_BINARY [GOREDACT_PROFILE] [SCENARIO]"
  exit 2
fi

corpus_file=$1
goredact_binary=$2
betterleaks_binary=$3
goredact_profile=${4:-balanced}
# Scenario is a label for the reported rows only: the corpus file is supplied by
# the caller (see tools/corpusfiles). It must match the scenario that file was
# generated with, otherwise the reported rows are mislabelled.
scenario=${5:-quiet}
runs=${RUNS:-3}

if [[ ! -f $corpus_file ]]; then
  print -u2 "missing corpus file: $corpus_file"
  exit 1
fi

corpus_dir=${corpus_file:h}

print $'tool\tprofile\tscenario\tcores\trun\telapsed_s\tuser_s\tsystem_s\tmax_rss_kib'

for tool in goredact betterleaks; do
  for run in {0..$runs}; do
    report_file="${TMPDIR:-/tmp}/betterleaks-onecore-${scenario}-${run}.json"
    TIMEFMT=$'%E\t%U\t%S\t%M'
    if [[ $tool == goredact ]]; then
      timing=$(
        { time taskset -c 0 env GOMAXPROCS=1 "$goredact_binary" stream \
            -profile "$goredact_profile" -input "$corpus_file" -output - >/dev/null
        } 2>&1
      )
    else
      timing=$(
        { time taskset -c 0 env GOMAXPROCS=1 "$betterleaks_binary" dir \
            "$corpus_dir" --max-decode-depth 0 --max-archive-depth 0 \
            --redact=100 --no-banner --no-color --log-level error \
            --report-format json --report-path "$report_file" --exit-code 0
        } 2>&1
      )
      rm -f "$report_file"
    fi
    # Run zero warms code and filesystem caches; measured output starts at one.
    if (( run > 0 )); then
      row_profile=$([[ $tool == goredact ]] && print $goredact_profile || print "default-rules")
      print "$tool\t$row_profile\t$scenario\t1\t$run\t$timing"
    fi
  done
done
