#!/bin/bash

THIS_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $THIS_DIR/..

CC_LIST=(
    "gcc"
    "clang"
)

pause() {
    echo
    read -n 1 -s -r -p "Press any key to continue..."
    echo
}

num_asm_tests=$( ls tests/*.s | wc -l )
num_c_tests=$( ls tests/*.c | wc -l )
total=$((2 * (num_asm_tests+num_c_tests)))
i=0

for CC in "${CC_LIST[@]}"; do
    for T in $( ls tests/*.s ); do
        rm -f *.elf *.disassembly.txt *.trace.txt
        if ! CC=$CC ./objcov-asm.sh $T; then
            exit 1
        fi
        i=$((i+1))
        echo
        echo "[$i/$total] Test finished with $CC, $T"
        pause
    done
    for T in $( ls tests/*.c ); do
        rm -f *.elf *.disassembly.txt *.trace.txt
        if ! CC=$CC ./objcov-c.sh $T; then
            exit 1
        fi
        i=$((i+1))
        echo
        echo "[$i/$total] Test finished with $CC, $T"
        pause
    done
done
