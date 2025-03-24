#!/usr/bin/env python3

import sys
import logging

logger = logging.getLogger()
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)-8s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr,
)

class AddressRangeSet:
    """
    ChatGPT-implemented address range data structure

    Conceptually it is a set `S` represented with single values and inclusive
    ranges:

      S = { addr1, addr2, ..., [start1, end1], [start2, end2], ... }

    It notably supports two methods `union()` and `cover()`:

      S.union(addr_new)
      S.union((start_new, end_new))
      S.cover(addr_query) => bool
    """
    def __init__(self, ranges=None):
        self.ranges = []
        if ranges:
            for item in ranges:
                self.union(item)

    def union(self, item):
        """Add a number or range to the set"""
        if isinstance(item, int):
            new_range = (item, item)
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            new_range = tuple(sorted(item))  # Ensure it's in (start, end) form
        else:
            raise ValueError("Union accepts either an int or a range as a tuple/list of (start, end)")

        self.ranges.append(new_range)
        self._merge_ranges()

    def cover(self, number):
        """Check if a number is covered by any of the ranges"""
        for start, end in self.ranges:
            if start <= number <= end:
                return True
        return False

    def _merge_ranges(self):
        """Merge overlapping or adjacent ranges"""
        self.ranges.sort()
        merged_ranges = []
        for start, end in self.ranges:
            if not merged_ranges or merged_ranges[-1][1] < start - 1:
                merged_ranges.append((start, end))
            else:
                merged_ranges[-1] = (merged_ranges[-1][0], max(merged_ranges[-1][1], end))
        self.ranges = merged_ranges

    def __repr__(self):
        return f"AddressRangeSet({self.ranges})"

# End of ChatGPT


import re
import argparse
from colorama import Fore, Back, Style

#
# QEMU (6.2.0) trace and objdump output use the same mnemonic. In practice
# suffix can somehow be different.
#
# - https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=opcodes/i386-dis.c;hb=gdb-15.2-release
# - https://github.com/qemu/qemu/blob/v6.2.0/disas/i386.c#L748
#
# Note well newer versions of QEMU has removed its builtin disassembly based on
# libopcodes but switches to capstone.
#

# TODO this may be incomplete
x86_control_flow_changes = [
    'ja', 'jae', 'jb', 'jbe', 'jcxz', 'je', 'jg', 'jge', 'jl', 'jle', 'jmp', 'jmpq',
    'jne', 'jno', 'jnp', 'jns', 'jo', 'jp', 'js',
    'call', 'callq',
    'syscall',
    'ret', 'retq'
]
# TODO this may be incomplete
x86_unconditional_jumps = [ 'jmp', 'jmpq', 'syscall', 'ret', 'retq', 'call', 'callq' ]
# TODO this may be incomplete
x86_unconditional_jumps_without_dest_addr = [ 'syscall', 'ret', 'retq' ]
# TODO this may be incomplete
x86_insns_without_operands = [ 'syscall', 'ret', 'retq', 'nop', 'hlt', 'cltq', 'lock', 'endbr64' ]

assert set(x86_unconditional_jumps) <= \
       set(x86_control_flow_changes)
assert set(x86_unconditional_jumps_without_dest_addr) <= \
       set(x86_unconditional_jumps)
assert set(x86_unconditional_jumps_without_dest_addr) <= \
       set(x86_insns_without_operands)

parser = argparse.ArgumentParser()
parser.add_argument('qemu_log')
parser.add_argument('objdump_log')
parser.add_argument('--min-address')
parser.add_argument('--max-address')
parser.add_argument('--output-filename')
args = parser.parse_args()
qemu_log = args.qemu_log
objdump_log = args.objdump_log
if args.output_filename:
    output_filename = args.output_filename
else:
    output_filename = 'report.txt'
color = False
branch_coverage = False

#
# Get the min and max address from disassemble results. As many of addresses in
# QEMU trace are not even in this range so they will be discarded to lessen the
# overhead.
#

objdump_address_pattern = re.compile(r"[0-9a-fA-F]+:")

is_objdump_llvm_flavor=False

logger.debug("Reading objdump output...")

with open(objdump_log, 'r') as f:
    is_objdump_llvm_flavor = f.readline().strip() == 'LLVM'
    objdump_output = f.read()

logger.debug("Reading objdump output... Done")

# Caveat: the assumption is objdump output is ordered by address, of which I'm
# actually not sure.

def get_objdump_minmax_address():
    objdump_addresses = objdump_address_pattern.findall(objdump_output)
    objdump_min_address = int(objdump_addresses[0][:-1], base=16)
    objdump_max_address = int(objdump_addresses[-1][:-1], base=16)
    return (objdump_min_address, objdump_max_address)

if args.min_address and args.max_address:
    try:
        objdump_min_address = int(args.min_address, base=16)
        objdump_max_address = int(args.max_address, base=16)
    except:
        logger.error("Error parsing --min-address or --max-address")
        objdump_min_address, objdump_max_address = get_objdump_minmax_address()
else:
    objdump_min_address, objdump_max_address = get_objdump_minmax_address()

#
# Construct the covered instruction set from QEMU trace
#

logger.debug("Reading trace...")

with open(qemu_log, 'r') as f:
    qemu_trace = f.read()

logger.debug("Reading trace... Done")

logger.debug("Split trace into TBs...")

tbs = qemu_trace.strip().split('----------------')
qemu_address_pattern = re.compile(r"0x[0-9a-fA-F]+:")

logger.debug("Split trace into TBs... Done")

covered_insn = AddressRangeSet()
covered_outcome: dict[int, list[bool]] = {}

def get_last_insn(text):
    lines = text.strip().splitlines()
    for line in reversed(lines):
        # Skip empty lines or anything that's not disassemble output
        if line.strip() and line.startswith('0x'):
            return line.strip()
    return None

# FIXME: what if jump destination is something unknown before runtime
def parse_assembly_in_qemu_trace(line):
    """
    This function is specifically used to parse the last instruction in each TB.
    """

    match = re.match(r"^(\S+):\s+(\S+)$", line.strip())
    if match:
        addr = match.group(1)
        mnemonic = match.group(2)
        # FIXME: for kernel it can be `mov`
        # assert mnemonic in x86_unconditional_jumps_without_dest_addr, \
        #        f"{mnemonic} found as the last instruction in TB."
        if mnemonic not in x86_unconditional_jumps_without_dest_addr:
            logger.warning(f"{mnemonic} found as the last instruction in TB.")

        return (addr, mnemonic, None)

    match = re.match(r"^(\S+):\s+(\S+)\s+(\S+)\s+\#\s(.*)", line.strip())
    if match:
        addr = match.group(1)
        mnemonic = match.group(2)
        operand = match.group(4)
        # assert mnemonic in x86_control_flow_changes, \
        #         f"{mnemonic} found as the last instruction in TB."
        if mnemonic not in x86_control_flow_changes:
            logger.warning(f"{mnemonic} found as the last instruction in TB.")
        return (addr, mnemonic, operand)

    match = re.match(r"^(\S+):\s+(\S+)\s+(.*)", line.strip())
    if match:
        addr = match.group(1)
        mnemonic = match.group(2)
        operand = match.group(3)
        # assert mnemonic in x86_control_flow_changes, \
        #         f"{mnemonic} found as the last instruction in TB."
        if mnemonic not in x86_control_flow_changes:
            logger.warning(f"{mnemonic} found as the last instruction in TB.")
        return (addr, mnemonic, operand)

src_address = None
dest_address = None

logger.debug("Processing TBs...")

i = 0
total = len(tbs)
percent = 0

for tb in tbs:

    i += 1
    prev_percent = percent
    percent = (i * 100 // total)
    if percent > prev_percent:
        logger.debug(f"Processing TBs... {percent}%")


    if tb.strip():
        tb_addresses = qemu_address_pattern.findall(tb)
        if tb_addresses:
            # Caveat: the assumption is QEMU trace of each TB is consecutive and
            # ordered by address, of which I'm actually not sure.
            tb_min_address = int(tb_addresses[0][:-1], base=16)
            tb_max_address = int(tb_addresses[-1][:-1], base=16)
            if (
                tb_min_address > objdump_max_address or
                tb_max_address < objdump_min_address
            ):
                # Outside the range of objdump output
                # FIXME print it
                continue
            covered_insn.union((tb_min_address, tb_max_address))

            if dest_address:
                if tb_min_address == dest_address:
                    # src_address->dest_address is executed (True outcome)
                    if src_address in covered_outcome:
                        if True not in covered_outcome[src_address]:
                            covered_outcome[src_address].append(True)
                    else:
                        covered_outcome[src_address] = [ True ]
                else:
                    # src_address->dest_address is not executed (False outcome)
                    if src_address in covered_outcome:
                        if False not in covered_outcome[src_address]:
                            covered_outcome[src_address].append(False)
                    else:
                        covered_outcome[src_address] = [ False ]

            last_insn = get_last_insn(tb)
            last_insn = parse_assembly_in_qemu_trace(last_insn)
            last_insn_address = last_insn[0]
            last_insn_mnemonic = last_insn[1]
            last_insn_operand = last_insn[2]
            if last_insn_operand == None:
                # For an unconditional "jump" without destination address, like
                # "ret", "syscall", as long as we see the source instruction
                # itself, we consider the True outcome is executed.
                try:
                    src_address = int(last_insn_address, base=16)
                    if (
                        src_address <= objdump_max_address and
                        src_address >= objdump_min_address
                    ):
                        covered_outcome[src_address] = [ True ]
                except:
                    pass
                dest_address = None
            else:
                # For an unconditional "jump" with destination address, like
                # "jmp <dest>", "call <dest>", we are more conservative. (1) We
                # have to see the source instruction itself (2) we will
                # check the next TB and see if the first instruction is the
                # destination address. FIXME This causes some problems e.g. the
                # destination address of "call <__libc_start_main@GLIBC_2.34>"
                # will not appear in the trace.
                #
                # For a conditional jump, we always do both (1) and (2) so that
                # we can track both its True outcome and False outcome.
                try:
                    dest_address = int(last_insn_operand, base=16)
                    src_address = int(last_insn_address, base=16)
                    if (
                        dest_address > objdump_max_address or
                        dest_address < objdump_min_address
                    ):
                        dest_address = None
                except:
                    pass

#
# Rewrite objdump output to add coverage information
#

if color:
    y = f"{Fore.GREEN}y{Style.RESET_ALL}"
    n = f"{Back.RED}n{Style.RESET_ALL}"
else:
    y = "y"
    n = "n"

def parse_assembly_in_objdump(line, is_objdump_llvm_flavor):
    # They put '\t' at different locations...
    if is_objdump_llvm_flavor:
        return parse_assembly_in_llvm_objdump(line)
    else:
        return parse_assembly_in_gnu_objdump(line)

def parse_assembly_in_llvm_objdump(line):
    mnemonic = None
    try:
        [l1, l2, l3] = line.split('\t')
        mnemonic = l2
    except ValueError:
        [l1, l2] = line.split('\t')
        mnemonic = l2
        assert mnemonic in x86_insns_without_operands, \
            f"llvm-objdump line parsing error: {line}"
    return mnemonic

def parse_assembly_in_gnu_objdump(line):
    mnemonic = None
    try:
        [l1, l2, l3] = line.split('\t')
        mnemonic = re.match(r"^(\S+)", l3.strip()).group(1)
    except ValueError:
        [l1, l2] = line.split('\t')
        # assert l2.strip() in [
        # FIXME
        # ], f"objdump line parsing error: {line}"
    return mnemonic

logger.debug("Splitting objdump output...")

lines = objdump_output.strip().split('\n')

logger.debug("Splitting objdump output... Done")

logger.debug("Processing objdump output...")

buffer = []

i = 0
total = len(lines)
percent = 0

for line in lines:

    i += 1
    prev_percent = percent
    percent = (i * 100 // total)
    if percent > prev_percent:
        logger.debug(f"Processing objdump output... {percent}%")

    insn_address = objdump_address_pattern.findall(line)
    if len(insn_address) != 1:
        buffer.append(line)
        buffer.append("\n")
    else:
        insn_address = str(insn_address[0][:-1])
        insn_address = int(insn_address, base=16)

        if not branch_coverage:
            b = ""
        else:
            mnemonic = parse_assembly_in_objdump(line, is_objdump_llvm_flavor)
            if insn_address in covered_outcome:
                # Unconditional jumps only have one outcome
                if mnemonic in x86_unconditional_jumps:
                    match sorted(covered_outcome[insn_address]):
                        case []:
                            b = f"  [{n}]"
                            assert False, \
                                "Self-contradictory results: instruction coverage is y but branch coverage is [n]."
                        case [ False ]:
                            assert False, \
                                "Self-contradictory results: unconditional jump should only have the True outcome and " + \
                                "instruction coverage is y, but branch coverage is [y n]."
                        case [ True ]:
                            b = f"  [{y}]"
                        case [ False, True ]:
                            assert False, \
                                "Self-contradictory results: unconditional jump should only have one outcome but branch coverage is [y y]."
                else:
                    match sorted(covered_outcome[insn_address]):
                        case []:
                            b = f"[{n} {n}]"
                            assert False, \
                                "Self-contradictory results: instruction coverage is y but branch coverage is [n n]."
                        case [ False ]:
                            b = f"[{y} {n}]"
                        case [ True ]:
                            b = f"[{n} {y}]"
                        case [ False, True ]:
                            b = f"[{y} {y}]"
            else:
                if mnemonic in x86_unconditional_jumps:
                    b = f"  [{n}]"
                elif mnemonic in x86_control_flow_changes:
                    b = f"[{n} {n}]"
                else:
                    b = "     "

        if (covered_insn.cover(insn_address)):
            buffer.append(f" {y} {b} |{line}\n")
        else:
            if color:
                buffer.append(f" {n} {b} |{Back.RED}{line}{Style.RESET_ALL}\n")
            else:
                buffer.append(f" {n} {b} |{line}\n")

logger.debug("Writing the report to disk...")

with open(output_filename, "w") as file:
    file.writelines(buffer)

logger.debug("Writing reports to disk... Done")
