"""
chameleon.py
author: gum3t

Main file of the Chameleon polymorphic engine.
"""
import argparse
import json
import r2pipe
import random

import tempfile
import subprocess

from typing import Dict, List
from utils.disasm import *
from mutation_patterns import *


def check_patterns_and_mutate(block: BBlock, os: str, verbose: bool) -> BBlock:
    """
    Sets the basic block to be checked against all the defined MutationPatternPools within MutationPatternPool registry.

    :param block: Basic block the be checked for patterns and mutated.
    :param os: Defined os for logic operations constants.
    :param verbose: Defined verbose level.
    :return: Mutated basic block.
    """
    for pattern_pool in mutation_pattern_pool_registry:
        block = pattern_pool.match(block, os, verbose)            

    return block


def shuffle_blocks(basic_blocks_asm: List[Tuple[int, str]]) -> List[Tuple[int, str]]:
    """
    Shuffles the contents of basic_blocks_asm.
    First block is always the same. All others are shuffled randomly.

    :param basic_blocks_asm: List that contains an assembly representation of each basic block.
    :return: Same basic_blocks_asm but shuffled.
    """
    for i in range(len(basic_blocks_asm) - 1):
        block_addr, block_asm = basic_blocks_asm[i]
    
    # first block must not change
    first_block: Tuple[int, str] = basic_blocks_asm[0]
    other_blocks: Tuple[int, str] = basic_blocks_asm[1:]
    
    # shuffle other_blocks
    random.shuffle(other_blocks)
    
    return [first_block] + other_blocks


def generate_block_asm(ops: List[Instruction], block_label: str) -> str:
    """
    Generates an asm blob that represents the Instructions of a basic block.
    If Instruction is mutated and has an opcode defined, the defined opcode is used.
    Otherwise the Instruction bytes are hardcoded into the asm blob using db.

    :param ops: List of block Instructions.
    :param block_label: Asm label to lead the block Instructions.
    :return: Blob of asm code that represents the basic block.
    """
    block_asm: str = ""
    block_asm += f"{block_label}:\n"
    
    for ins in ops:

        if ins.mutated and ins.opcode:

            block_asm += f"{ins.opcode}\n"

        else:
            # hardcode instruction as raw bytes
            # split into single bytes
            ins_bytes: List[str] = [ins.bytes[i:i + 2] for i in range(0, len(ins.bytes), 2)]
            # generate nasm friendly code
            block_asm += "db " + ", ".join(f"0x{byte}" for byte in ins_bytes)
            if not ins.mutated:
                block_asm += f" ; {ins.opcode}"
            block_asm += "\n"
    
    return block_asm


def patch_short_jump_exclusive_instruction(ins: Instruction) -> Instruction:
    """
    Checks if a control flow instruction exclusively supports short jumps.
    In this case is replaces its mnemonic to support a wider jump range to avoid later problems with injections
    of generated code.

    :param ins: Instruction to be checked.
    :return: Modified instruction if the instruction was short jump exclusive. Otherwise returns the same instruction.
    """
    if "loop" == ins.mnemonic or "loopne" == ins.mnemonic or "loopnz" == ins.mnemonic:
        ins.mnemonic = "dec rcx\njnz"
    elif "loope" == ins.mnemonic or "loopz" == ins.mnemonic:
        ins.mnemonic = "dec rcx\njz"
    elif "jcxz" == ins.mnemonic:
        ins.mnemonic = "test cx, cx\njz"
    elif "jecxz" == ins.mnemonic: 
        ins.mnemonic = "test ecx, ecx\njz"
    elif "jrcxz" == ins.mnemonic:
        ins.mnemonic = "test rcx, rcx\njz"

    return ins    


def rm_redundant_fall_through_ins(basic_blocks_asm: List[Tuple[int, str]]) -> List[Tuple[int, str]]:
    """
    Removes all redundant fall-through instructions.
    Checks if the last instruction of a block is a jmp to the immediate following block.
    If this is the case, the jmp instruction is removed to avoid redundancy.

    :param basic_blocks_asm: List that contains an assembly representation of each basic block.
    :return: Same basic_blocks_asm but without redundant fall-through instructions.
    """
    for i in range(len(basic_blocks_asm) - 1):
        block_addr, block_asm = basic_blocks_asm[i]
        next_block_addr, _ = basic_blocks_asm[i + 1]

        # split sc blob into lines
        asm_lines: List[str] = block_asm.split("\n")

        # -2 due to trailing \n
        last_asm_line: str = asm_lines[-2].strip()
        expected_label: str = f"block_{next_block_addr}"

        # if last instruction is a jmp to the following block (redundant)
        if last_asm_line.startswith("jmp") and expected_label in last_asm_line:
            asm_lines = asm_lines[:-2]
            basic_blocks_asm[i][1] = "\n".join(asm_lines) + "\n"

    return basic_blocks_asm


def generate_final_asm(basic_blocks_asm: List[Tuple[int, str]]) -> str:
    """
    Generates NASM compatible assembly code from the given assembly blocks.

    :param basic_blocks_asm: List that contains an assembly representation of each basic block.
    :return: NASM compatible assembly blob that contains the assembly of all basic blocks.
    """
    mutated_asm: str = ""
    mutated_asm += "BITS 64\n"
    mutated_asm += "default rel\n"
    mutated_asm += "global _start\n"
    mutated_asm += "section .text\n"
    mutated_asm += "_start:\n"

    for pair in basic_blocks_asm:
        mutated_asm += pair[1]
    
    return mutated_asm


def final_assemble(mutated_asm: str, output_path: str, save_asm: bool) -> None:
    """
    Assembles NASM compatible assembly code and stores the result in the defined path.

    :param mutated_asm: Mutated asm blob to be assembled.
    :param output_path: Defined path for the output shellcode file.
    :param save_asm: True if asm is meant to be saved as a file in the current directory.
    """
    with tempfile.NamedTemporaryFile(prefix = "mutated_", suffix = ".asm", dir = ".", delete = not save_asm) as asm_file: 
        
        if save_asm:
            print(f"[+] asm file saved at: {asm_file.name}")

        asm_file.write(mutated_asm.encode("utf-8"))
        asm_file.flush()
        subprocess.run(["nasm", "-f", "bin", asm_file.name, "-o", output_path], check=True)

    return


def mutate_shellcode(shellcode_path: str, base_address: int, shuffle: bool, os: str, verbose: bool) -> str:
    """
    Generates a mutated version of the given position independent shellcode.
    Disassembles the given shellcode into basic blocks with radare2.
    Patches control flow instructions with generated labels.
    Applies mutations.
    Shuffles blocks around if defined.
    Removes redundant fall-through instructions.
    Prepares a NASM compatible asm blob.

    :param shellcode_path: Path of the PI shellcode file to mutate
    :param base_address: Base address to be used for the disassembling process.
    :param shuffle: True if basic blocks are meant to be shuffled before reassembling.
    :param os: Defined os for logic operations constants.
    :param verbose: Defined verbose level.
    :return: Mutated asm blob generated from the given PI shellcode.
    """
    shellcode: bytes = b""
    r2 = r2pipe.open(f"{shellcode_path}", flags=["-n", f"-m {base_address}"])
    print("[+] program loaded into radare2")

    r2.cmd("e log.quiet=true")
    r2.cmd("e asm.arch=x86")
    r2.cmd("e asm.bits=64")
    r2.cmd("e asm.syntax=intel")

    # seek predefined virtual address
    r2.cmd(f"s {base_address}")
    # analyze
    r2.cmd("aaa")
    print("[+] program analyzed (aaa)")


    # get function offsets from aflq command.
    fcn_offsets: List[str] = r2.cmd("aflq").strip().split("\n")
    print("[+] function offsets obtained (aflq)")

    # verbose related
    if verbose:
        print(f"\t[v] {fcn_offsets = }")

    basic_blocks_data = []
    for offset in fcn_offsets:
        # get basic blocks function control flow graph in json format
        fcn_cfg = json.loads(r2.cmd(f"agfj @ {offset}"))
        # get all basic blocks from the function cfg and add them to a general pool
        fcn_bb = [bb for fcn in fcn_cfg for bb in fcn.get("blocks", [])]
        basic_blocks_data.extend(fcn_bb)

    print("[+] control flow graphs for all functions obtained in json format (agfj @ fcn_offset)")

    basic_blocks: List[BBlock] = [BBlock(block) for block in basic_blocks_data]
    # ensure block order by address
    basic_blocks.sort(key=lambda block: block.addr)

    # for easier label tracking
    labels: Dict[int, str] = {block.addr: block.label for block in basic_blocks}
    print("[+] labels generated for each basic block")

    # has the mutated code for each basic block
    basic_blocks_asm: List[Tuple[int, str]] = []

    for block in basic_blocks:
        
        for ins in block.ops:
            
            # patch control flow instructions
            if "call" == ins.type or "jmp" == ins.type or "cjmp" == ins.type:
                
                op1: int = hex(int(ins.operand_1, 16))
                if op1 not in labels:
                    print("[!] ERROR: CONTROL FLOW LABEL NOT FOUND!!")
                    exit(-1)
                
                ins = patch_short_jump_exclusive_instruction(ins)
                ins.opcode = f"{ins.mnemonic} {labels[op1]}"
                ins.mutated = True

            elif "rip" in ins.disasm or "rip" in ins.opcode:
                # TODO: check if RIP relative is computable: within size of PIC shellcode
                # might fix some self modifying or self reading code cases
                #ins.mutated = True
                print(f"[!] ERROR: UNMANAGED RIP RELATIVE INSTRUCTION:\n\t{ins}")
                exit(-1)
        
        block = check_patterns_and_mutate(block, os, verbose)

        block_asm: str = generate_block_asm(block.ops, block.label)

        # set forced jump to the next basic block (expected by fall-through)
        # this way blocks can later be shuffled without concern
        if block.fail:
            block_asm += f"jmp {labels[block.fail]}\n"
        elif block.jump and not block_asm.endswith(f"jmp {labels[block.jump]}\n"):
            block_asm += f"jmp {labels[block.jump]}\n"

        # add basic block shellcode to block shellcode pool
        basic_blocks_asm.append([block.addr, block_asm])
    

    print("[+] mutation completed for all basic blocks")
    
    # shuffle basic blocks if defined
    if shuffle:
        basic_blocks_asm = shuffle_blocks(basic_blocks_asm)
        print("[+] basic blocks shuffled")
    
    # remove fall-through redundant instructions
    basic_blocks_asm = rm_redundant_fall_through_ins(basic_blocks_asm)
    print("[+] redundant jmp instructions removed")

    # generate final asm code
    mutated_asm: str = generate_final_asm(basic_blocks_asm)
    print("[+] final assembly code generated")

    return mutated_asm


def main() -> None:
    """
    Main function.
    """
    parser: ArgumentParser = argparse.ArgumentParser(description = "chameleon.py")
    parser.add_argument("-i", "--input", required=True, help="input path (PI shellcode file to mutate)")
    parser.add_argument("-o", "--output", required=True, help="output path (mutated shellcode)")
    parser.add_argument("-b", "--base_address", required=False, default=0x1000, help="shellcode base address")
    parser.add_argument("-v", "--verbose", required=False, default=False, action="store_true", help="verbose output")
    parser.add_argument("--save-asm", required=False, default=False, action="store_true", help="save generated asm file in the current directory")
    parser.add_argument("--shuffle", required=False, default=False, action="store_true", help="shuffle basic blocks before reassembling")
    parser.add_argument("--os", choices = ["windows", "linux"], default = "windows", help = "defined os for generated logic operations constants - windows by default")
    args = parser.parse_args()
    
    mutated_asm: str = mutate_shellcode(args.input, args.base_address, args.shuffle, args.os, args.verbose)
    final_assemble(mutated_asm, args.output, args.save_asm)
    print("[+] polymorphing process finished successfully")


if __name__ == "__main__":
    main()
