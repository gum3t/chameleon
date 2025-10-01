"""
mutation_generators.py
author: gum3t

Contains the mutation generators for the MutationPatternPool instances.
"""
import random
from typing import List, Tuple, Callable, Dict, Any
from utils.disasm import *
from shellcode_generator import *

##############
# GENERATORS #
##############
"""
######################
# GENERATOR TEMPLATE #
######################

def generator_action_ALLOWED_REG_SIZES(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    # parse operands_and_data and generate instruction info

    # create new instructions
    new_ins: Dict[str, Any] = ins_skel.copy()
    # at least one of the following fields must be set
    # opcode has preference during the asm generation process
    new_ins["opcode"] = opcode (must follow intel nasm syntax)
    new_ins["bytes"] = str_hex_bytes (ex: "7704")
    instructions.append(Instruction(new_ins))

    return instructions
"""


### mov_reg_value_to_reg ###

# generates mov regA, regB instruction from dst, src
def generator_mov_reg_reg_REG64_REG16(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str    = operands_and_data[0]
    src: str    = operands_and_data[1]
    opcode: str = f"mov {dst}, {src}"

    mov_reg_reg: Dict[str, Any] = ins_skel.copy()
    mov_reg_reg["opcode"]       = opcode

    instructions.append(Instruction(mov_reg_reg))

    return instructions


# generates push regB; pop regA instructions from dst, src
def generator_push_reg_pop_reg_REG64_REG16(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str        = operands_and_data[0]
    src: str        = operands_and_data[1]
    opcode_1: str   = f"push {src}"
    opcode_2: str   = f"pop {dst}"

    push_reg: Dict[str, Any]    = ins_skel.copy()
    push_reg["opcode"]          = opcode_1
    
    pop_reg: Dict[str, Any]     = ins_skel.copy()
    pop_reg["opcode"]           = opcode_2

    instructions.append(Instruction(push_reg))
    instructions.append(Instruction(pop_reg))

    return instructions


# generates mov regA, regB; junk_code instructions from dst, src
def generator_mov_reg_reg_extra_code_REG64_REG16(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str            = operands_and_data[0]
    src: str            = operands_and_data[1]
    opcode: str         = f"mov {dst}, {src}"
    sc_size: int        = int( max(50, min(500, random.normalvariate(275, 75))) )
    generated_sc: str   = f"{generate_shellcode(sc_size, os).hex()}"

    mov_reg_reg: Dict[str, Any] = ins_skel.copy()
    mov_reg_reg["opcode"]       = opcode

    junk_code: Dict[str, Any]   = ins_skel.copy()
    junk_code["bytes"]          = generated_sc

    instructions.append(Instruction(mov_reg_reg))
    instructions.append(Instruction(junk_code))

    return instructions


# generates junk_code; mov regA, regB instructions from dst, src
def generator_extra_code_mov_reg_reg_REG64_REG16(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str            = operands_and_data[0]
    src: str            = operands_and_data[1]
    opcode: str         = f"mov {dst}, {src}"
    sc_size: int        = int( max(50, min(500, random.normalvariate(275, 75))) )
    generated_sc: str   = f"{generate_shellcode(sc_size, os).hex()}"

    mov_reg_reg: Dict[str, Any] = ins_skel.copy()
    mov_reg_reg["opcode"]       = opcode

    junk_code: Dict[str, Any]   = ins_skel.copy()
    junk_code["bytes"]          = generated_sc

    instructions.append(Instruction(junk_code))
    instructions.append(Instruction(mov_reg_reg))

    return instructions


# generates push regB; junk_code; pop regA instructions from dst, src
def generator_push_reg_extra_code_pop_reg_REG64_REG16(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str            = operands_and_data[0]
    src: str            = operands_and_data[1]
    opcode_1: str       = f"push {src}"
    opcode_2: str       = f"pop {dst}"
    sc_size: int        = int( max(50, min(500, random.normalvariate(275, 75))) )
    generated_sc: str   = f"{generate_shellcode(sc_size, os).hex()}"

    push_reg: Dict[str, Any]    = ins_skel.copy()
    push_reg["opcode"]          = opcode_1

    junk_code: Dict[str, Any]   = ins_skel.copy()
    junk_code["bytes"]          = generated_sc

    pop_reg: Dict[str, Any]     = ins_skel.copy()
    pop_reg["opcode"]           = opcode_2


    instructions.append(Instruction(push_reg))
    instructions.append(Instruction(junk_code))
    instructions.append(Instruction(pop_reg))

    return instructions



### mov_reg_value_to_reg ###

# generates mov regA, 0 instruction from dst
def generator_mov_reg_0_REGALL(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str    = operands_and_data[0]
    opcode: str = f"mov {dst}, 0"

    mov_reg_0: Dict[str, Any] = ins_skel.copy()
    mov_reg_0["opcode"]       = opcode
    
    instructions.append(Instruction(mov_reg_0))

    return instructions


# generates and regA, 0 instruction from dst
def generator_and_reg_0_REGALL(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str    = operands_and_data[0]
    opcode: str = f"and {dst}, 0"

    and_reg_0: Dict[str, Any] = ins_skel.copy()
    and_reg_0["opcode"]       = opcode
    
    instructions.append(Instruction(and_reg_0))

    return instructions


# generates xor regA, regA instruction from dst
def generator_xor_reg_reg_REGALL(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str    = operands_and_data[0]
    opcode: str = f"xor {dst}, {dst}"

    xor_reg_reg: Dict[str, Any] = ins_skel.copy()
    xor_reg_reg["opcode"]       = opcode
    
    instructions.append(Instruction(xor_reg_reg))

    return instructions


# generates mov regA, 0; junk_code instructions from dst
def generator_mov_reg_0_extra_code_REGALL(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str            = operands_and_data[0]
    opcode: str         = f"mov {dst}, 0"
    sc_size: int        = int( max(50, min(500, random.normalvariate(275, 75))) )
    generated_sc: str   = f"{generate_shellcode(sc_size, os).hex()}"

    mov_reg_0: Dict[str, Any] = ins_skel.copy()
    mov_reg_0["opcode"]       = opcode
    
    junk_code: Dict[str, Any]   = ins_skel.copy()
    junk_code["bytes"]          = generated_sc

    instructions.append(Instruction(mov_reg_0))
    instructions.append(Instruction(junk_code))

    return instructions


# generates and regA, 0; junk_code instructions from dst
def generator_and_reg_0_extra_code_REGALL(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str            = operands_and_data[0]
    opcode: str         = f"and {dst}, 0"
    sc_size: int        = int( max(50, min(500, random.normalvariate(275, 75))) )
    generated_sc: str   = f"{generate_shellcode(sc_size, os).hex()}"

    and_reg_0: Dict[str, Any] = ins_skel.copy()
    and_reg_0["opcode"]       = opcode
    
    junk_code: Dict[str, Any]   = ins_skel.copy()
    junk_code["bytes"]          = generated_sc

    instructions.append(Instruction(and_reg_0))
    instructions.append(Instruction(junk_code))

    return instructions


# generates xor regA, regA; junk_code instructions from dst
def generator_xor_reg_reg_extra_code_REGALL(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str            = operands_and_data[0]
    opcode: str         = f"xor {dst}, {dst}"
    sc_size: int        = int( max(50, min(500, random.normalvariate(275, 75))) )
    generated_sc: str   = f"{generate_shellcode(sc_size, os).hex()}"

    xor_reg_reg: Dict[str, Any] = ins_skel.copy()
    xor_reg_reg["opcode"]       = opcode
    
    junk_code: Dict[str, Any]   = ins_skel.copy()
    junk_code["bytes"]          = generated_sc

    instructions.append(Instruction(xor_reg_reg))
    instructions.append(Instruction(junk_code))

    return instructions


# generates junk_code; mov regA, 0 instructions from dst
def generator_extra_code_mov_reg_0_REGALL(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str            = operands_and_data[0]
    opcode: str         = f"mov {dst}, 0"
    sc_size: int        = int( max(50, min(500, random.normalvariate(275, 75))) )
    generated_sc: str   = f"{generate_shellcode(sc_size, os).hex()}"

    mov_reg_0: Dict[str, Any] = ins_skel.copy()
    mov_reg_0["opcode"]       = opcode
    
    junk_code: Dict[str, Any]   = ins_skel.copy()
    junk_code["bytes"]          = generated_sc

    instructions.append(Instruction(junk_code))
    instructions.append(Instruction(mov_reg_0))

    return instructions


# generates junk_code; and regA, 0 instructions from dst
def generator_extra_code_and_reg_0_REGALL(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str            = operands_and_data[0]
    opcode: str         = f"and {dst}, 0"
    sc_size: int        = int( max(50, min(500, random.normalvariate(275, 75))) )
    generated_sc: str   = f"{generate_shellcode(sc_size, os).hex()}"

    and_reg_0: Dict[str, Any] = ins_skel.copy()
    and_reg_0["opcode"]       = opcode
    
    junk_code: Dict[str, Any]   = ins_skel.copy()
    junk_code["bytes"]          = generated_sc

    instructions.append(Instruction(junk_code))
    instructions.append(Instruction(and_reg_0))

    return instructions


# generates junk_code; xor regA, regA instructions from dst
def generator_extra_code_xor_reg_reg_REGALL(operands_and_data: List[Any], os: str) -> List[Instruction]:

    instructions: List[Instruction] = []
    ins_skel: Dict[str, Any] = {"mutated": True}

    dst: str            = operands_and_data[0]
    opcode: str         = f"xor {dst}, {dst}"
    sc_size: int        = int( max(50, min(500, random.normalvariate(275, 75))) )
    generated_sc: str   = f"{generate_shellcode(sc_size, os).hex()}"

    xor_reg_reg: Dict[str, Any] = ins_skel.copy()
    xor_reg_reg["opcode"]       = opcode
    
    junk_code: Dict[str, Any]   = ins_skel.copy()
    junk_code["bytes"]          = generated_sc

    instructions.append(Instruction(junk_code))
    instructions.append(Instruction(xor_reg_reg))

    return instructions