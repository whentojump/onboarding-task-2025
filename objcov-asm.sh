#!/bin/bash

input=${1:-"tests/jmp.s"}
symbol=$2
basename=$( basename $input | rev | cut -d '.' -f 2- | rev )

CC=${CC:-"gcc"}
CFLAGS="$CFLAGS -no-pie -nostdlib"
LDFLAGS="$LDFLAGS -no-pie -nostdlib"

DEBUG=${DEBUG:-"0"}
TRACE_ENCODING=${TRACE_ENCODING:-"text"}
BRANCH_COVERAGE=${BRANCH_COVERAGE:-"1"}

PY_FLAGS=""
if [[ $TRACE_ENCODING == "binary" ]]; then
    PY_FLAGS="$PY_FLAGS --binary-trace"
fi
if [[ $TRACE_ENCODING == "binary2" ]]; then
    PY_FLAGS="$PY_FLAGS --binary-trace2 --base-address 0"
fi
if [[ $BRANCH_COVERAGE == "1" ]]; then
    PY_FLAGS="$PY_FLAGS --branch-coverage"
fi

if [[ $CC == "clang" ]]; then
    OD=llvm-objdump
    if [[ ! -z "${symbol}" ]]; then
        ODFLAGS="-j .text --disassemble-symbols=$symbol"
    fi
else
    OD=objdump
    if [[ ! -z "${symbol}" ]]; then
        ODFLAGS="-j .text --disassemble=$symbol"
    fi
fi

Q_PREFIX=${Q_PREFIX:-"/usr"}
Q=${Q:-"qemu-x86_64"}

use_plugin=1

if [[ $Q_PREFIX == "/usr" ]]; then
    cat << EOF
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% WARNING %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

System $Q will be used. Fall back to "-d in_asm" trace, which doesn't
represent actual execution.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
EOF
    use_plugin=0
elif [[ -z $Q_PLUGIN || ! -f $Q_PLUGIN ]]; then
    cat << EOF
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% WARNING %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\$Q_PLUGIN is not set or the plugin is not found there: [$Q_PLUGIN]
Fall back to "-d in_asm" trace, which doesn't represent actual execution.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
EOF
    use_plugin=0
fi

Q="$Q_PREFIX/bin/$Q"

if [[ ! -f $Q ]]; then
    cat << EOF
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% ERROR %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

$Q not found.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
EOF
    exit 1
fi

$CC $CFLAGS $input -o $basename.elf

if [[ $OD == "llvm-objdump" ]]; then
    printf "LLVM\n" > $basename.disassembly.txt
else
    printf "GNU\n" > $basename.disassembly.txt
fi

$OD -d $basename.elf $ODFLAGS &>> $basename.disassembly.txt

if [[ $use_plugin == "0" ]]; then
    $Q -D $basename.trace.txt -d in_asm $basename.elf
else
    $Q -D $basename.trace.txt -plugin $Q_PLUGIN -d plugin $basename.elf
    $Q -plugin $Q_PLUGIN,log_mode=6,buffer_dump_file=$basename.trace.bin -d plugin $basename.elf
    $Q -plugin $Q_PLUGIN,log_mode=10,buffer_dump_file=$basename.trace.bin2 -d plugin $basename.elf
fi

./objcov-user.py $PY_FLAGS $basename || exit 1

if [[ $DEBUG == "1" ]]; then
    echo
    echo "> Cross check binary vs. text trace encoding (expecting deterministic user-space application)"
    echo

    binary_trace=$basename.trace.bin
    binary_trace2=$basename.trace.bin2
    text_trace=$basename.trace.txt

    echo "> Binary"
    echo

    first_8=0x$(xxd -p -l 8 "$binary_trace" | fold -w2 | tac | tr -d '\n')
    second_8=0x$(xxd -p -s 8 -l 8 "$binary_trace" | fold -w2 | tac | tr -d '\n')
    binary_trace_size=$(stat -c%s "$binary_trace")
    last_8=0x$(xxd -p -s $((binary_trace_size - 8)) -l 8 "$binary_trace" | fold -w2 | tac | tr -d '\n')
    second_last_8=0x$(xxd -p -s $((binary_trace_size - 16)) -l 8 "$binary_trace" | fold -w2 | tac | tr -d '\n')

    printf "Trace size:    $(du -sh $binary_trace)\n"
    printf "Number of TBs: $((binary_trace_size / 16))\n"
    printf "First TB:      ${first_8} ${second_8}\n"
    printf "Last TB:       ${second_last_8} ${last_8}\n"


    echo
    echo "> Binary 2"
    echo

    first_4=0x$(xxd -p -l 4 "$binary_trace2" | fold -w2 | tac | tr -d '\n')
    third_2=0x$(xxd -p -s 4 -l 2 "$binary_trace2" | fold -w2 | tac | tr -d '\n')
    binary_trace2_size=$(stat -c%s "$binary_trace2")
    last_2=0x$(xxd -p -s $((binary_trace2_size - 2)) -l 2 "$binary_trace2" | fold -w2 | tac | tr -d '\n')
    third_and_second_last_2=0x$(xxd -p -s $((binary_trace2_size - 6)) -l 4 "$binary_trace2" | fold -w2 | tac | tr -d '\n')

    printf "Trace size:    $(du -sh $binary_trace2)\n"
    printf "Number of TBs: $((binary_trace2_size / 6))\n"
    printf "First TB:      ${first_4} ${third_2}\n"
    printf "Last TB:       ${third_and_second_last_2} ${last_2}\n"

    echo
    echo "> Text"
    echo

    first_tb_first_insn=$(grep '^0x' $text_trace | head -n 1 | cut -d : -f 1)
    first_tb_last_insn=$(grep '^0x' $text_trace | head -n 2 | tail -n 1 | cut -d : -f 1)
    last_tb_last_insn=$(grep '^0x' $text_trace | tail -n 1 | cut -d : -f 1)
    last_tb_first_insn=$(grep '^0x' $text_trace | tail -n 2 | head -n 1 | cut -d : -f 1)

    printf "Trace size:    $(du -sh $text_trace)\n"
    printf "Number of TBs: $(grep -- "----" $text_trace | wc -l)\n"
    printf "First TB:      ${first_tb_first_insn} ${first_tb_last_insn}\n"
    printf "Last TB:       ${last_tb_first_insn} ${last_tb_last_insn}\n"

    echo
    if [[
        $first_8 == $first_tb_first_insn &&
        $second_8 == $first_tb_last_insn &&
        $last_8 == $last_tb_last_insn &&
        $second_last_8 == $last_tb_first_insn &&
        $((binary_trace_size / 16)) == $(grep -- "----" $text_trace | wc -l) &&
        $((first_4)) -eq $first_8 &&
        $((first_4 + third_2)) -eq $second_8 &&
        $((third_and_second_last_2)) -eq $second_last_8 &&
        $((third_and_second_last_2 + last_2)) -eq $last_8 &&
        $((binary_trace2_size / 6)) == $((binary_trace_size / 16))
    ]]; then
        echo Match
    else
        echo Mismatch!!!!
    fi
    echo

fi
