"""
mutation_match_rules.py
author: gum3t

Contains the mutation match rules for the MutationPatternPool instances.
"""
from typing import List, Tuple, Callable, Dict, Any
from utils.disasm import *
from utils.regdata import *

###############
# MATCH RULES #
###############
"""
#######################
# MATCH RULE TEMPLATE #
#######################

def match_action_ALLOWED_REG_SIZES(instructions: List[Instruction]) -> List[Tuple[int, int, List[Any]]]:

    pattern_instruction_size: int = X
    matches: List[Tuple[int, int, List[Any]]] = []

    idx: int = 0
    length: int  = len(instructions) - pattern_instruction_size + 1
    while idx < length:
        # get instructions and find pattern
        if pattern:    
            
            matches.append([idx, pattern_instruction_size, [dst, src, etc]])
            idx += pattern_instruction_size - 1
        
        idx += 1

    return matches
"""


# Pattern: mov regA, regB; only for 64 and 16 bit register sizes
def match_mov_reg_reg_REG64_REG16(instructions: List[Instruction]) -> List[Tuple[int, int, List[Any]]]:
    
    pattern_instruction_size: int = 1
    matches: List[Tuple[int, int, List[Any]]] = []

    idx: int = 0
    length: int = len(instructions)
    while idx < length:
        ins1: Instruction = instructions[idx]
        if "mov" == ins1.mnemonic: 
            # if operands are registers, reg sizes will be obtained; 0 otherwise
            # in this case we want to match only with 64 and 16 bit registers, the only ones
            # compatible with push/pop in 64 bit
            op1_reg_sz: int = reg_sizes_map.get(ins1.operand_1, 0)
            op2_reg_sz: int = reg_sizes_map.get(ins1.operand_2, 0)

            if op1_reg_sz & (REG_64 | REG_16) and op2_reg_sz & (REG_64 | REG_16):

                matches.append([idx, pattern_instruction_size, [ins1.operand_1, ins1.operand_2]])
        
        idx += 1

    return matches


# Pattern: push regB, pop regA; push and pop only support 64 and 16 bit registers 
def match_push_pop_reg_REG64_REG16(instructions: List[Instruction]) -> List[Tuple[int, int, List[Any]]]:

    pattern_instruction_size: int = 2
    matches: List[Tuple[int, int, List[Any]]] = []

    idx: int = 0
    length: int = len(instructions) - pattern_instruction_size + 1
    while idx < length:
        ins1: Instruction = instructions[idx]
        if "push" == ins1.mnemonic:
            # if operand is a register, reg size will be obtained; 0 otherwise
            ins1_op1_reg_sz: int = reg_sizes_map.get(ins1.operand_1, 0)
            if ins1_op1_reg_sz:
                # get next instruction for next check
                ins2: Instruction = instructions[idx + 1]
                if "pop" == ins2.mnemonic:
                    
                    matches.append([idx, pattern_instruction_size, [ins2.operand_1, ins1.operand_1]])
                    idx += pattern_instruction_size - 1
        
        idx += 1

    return matches


# Pattern: mov regA, 0; no cjmp
def match_mov_reg_0_REGALL(instructions: List[Instruction]) -> List[Tuple[int, int, List[Any]]]:
    
    pattern_instruction_size: int = 1
    matches: List[Tuple[int, int, List[Any]]] = []

    idx: int = 0
    # -1 for cjmp check
    length: int = len(instructions) - 1
    while idx < length:
        ins1: Instruction = instructions[idx]
        if "mov" == ins1.mnemonic: 
            # if operand_1 is a register and operand_2 is 0
            if reg_sizes_map.get(ins1.operand_1, 0) and "0" == ins1.operand_2:
                # get next instruction for next check
                ins2: Instruction = instructions[idx + 1]
                if "cjmp" != ins2.type:
                
                    matches.append([idx, pattern_instruction_size, [ins1.operand_1]])
                    idx += 1
        
        idx += 1

    return matches


# Pattern: and regA, 0; no cjmp
def match_and_reg_0_REGALL(instructions: List[Instruction]) -> List[Tuple[int, int, List[Any]]]:
    
    pattern_instruction_size: int = 1
    matches: List[Tuple[int, int, List[Any]]] = []

    idx: int = 0
    # -1 for cjmp check
    length: int = len(instructions) - 1
    while idx < length:
        ins1: Instruction = instructions[idx]
        if "mov" == ins1.mnemonic: 
            # if operand_1 is a register and operand_2 is 0
            if reg_sizes_map.get(ins1.operand_1, 0) and "0" == ins1.operand_2:
                # get next instruction for next check
                ins2: Instruction = instructions[idx + 1]
                if "cjmp" != ins2.type:
                
                    matches.append([idx, pattern_instruction_size, [ins1.operand_1]])
                    idx += 1
        
        idx += 1

    return matches


# Pattern: xor regA, regA; no cjmp
def match_xor_reg_reg_REGALL(instructions: List[Instruction]) -> List[Tuple[int, int, List[Any]]]:

    pattern_instruction_size: int = 1
    matches: List[Tuple[int, int, List[Any]]] = []

    idx: int = 0
    # -1 for cjmp check
    length: int = len(instructions) - 1
    while idx < length:
        ins1: Instruction = instructions[idx]
        if "xor" == ins1.mnemonic:
            # if operand_1 is a register and operand_1 is equal to operand_2
            if reg_sizes_map.get(ins1.operand_1, 0) and ins1.operand_1 == ins1.operand_2:
                # get next instruction for next check
                ins2: Instruction = instructions[idx + 1]
                if "cjmp" != ins2.type:
                    
                    matches.append([idx, pattern_instruction_size, [ins1.operand_1]])
                    idx += 1
        
        idx += 1

    return matches