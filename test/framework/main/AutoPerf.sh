#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "$# parameters instead of 3 ones. Parameters should be 'machine1', 'machine2', 'result directory'"
    echo "If you use make you should use 'make s1=machine1 s2=machine2 r=result perf_testing'"
    exit 1
fi

machine1=$1
machine2=$2

directory=$3
result=_result

echo "Will test perf.json benchmarks at '$machine1' and '$machine2' machines"
echo "Directory result will be '$directory', comparable file will be '$directory$result', anticipated time 2 hours, 20 minutes"

cp perf.json temp_perf.json

sed -i 's%hostname1%'$machine1'%g' temp_perf.json
sed -i 's%hostname2%'$machine2'%g' temp_perf.json

./main -directory $directory temp_perf.json
./perf_compare $directory > $directory$result

rm temp_perf.json
