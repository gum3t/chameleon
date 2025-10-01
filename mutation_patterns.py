"""
mutation_patterns.py
author: gum3t

Contains the mutation pattern pools to mutate shellcode.
"""
import random
from typing import List, Tuple, Callable, Dict, Any
from utils.disasm import *
from mutation_match_rules import *
from mutation_generators import *


class MutationPatternPool:
    """
    Each instance of this class detects specific patterns of Instructions and replaces them with equivalent Instructions.
    """
    
    def __init__(self, name: str, match_rules: List[Callable], generators: List[Tuple[Callable, int]], mutation_probability: int) -> None:
        """
        Initializes a MutationPatternPool.
        
        :param name: Name of the MutationPatternPool
        :param match_rules: List of matching rules. See mutation_match_rules.py for more information about matching rules.
        :param generators: List of Tuples made of generators and its weight. See mutation_generators.py for more information about generators.
        :param mutation_probability: Probability to apply a mutation once a pattern is matched. Out of 100, it is a percentage (%). 
        
        self.name stores the name of the MutationPatternPool.
        self.match_rules stores the list of matching rules.
        self.generators stores the list of generators + weights.
        self.mutation_probability stores the mutation probability.
        """
        self.name: str                              = name
        self.match_rules: List[Callable]            = match_rules
        self.generators: List[Tuple[Callable, int]] = generators
        self.mutation_probability: int              = mutation_probability 
    

    def match(self, block: BBlock, os: str, verbose: bool) -> BBlock:
        """
        Looks for rule matches within a basic block.
        In the case of a match, calls to mutate after checking mutation_probability.
        
        :param block: BBlock instance to analyze.
        :param os: Defined os for logic operations constants.
        :param verbose: Defined verbose level.
        :return: Mutated BBlock.
        """
        for rule in self.match_rules:

            verbose_msg: bool = False
            # Tuple list of [first_instruction_that_matches_index, number_of_instructions_of_the_match, list_of_operands_&_case_specific_data]
            matches: List[Tuple[int, int, List[Any]]] = []
            matches = rule(block.ops)

            for match in reversed(matches):
                # Apply mutation probability
                if random.randint(0, 100) <= self.mutation_probability:
                    
                    # verbose related
                    if verbose and not verbose_msg:
                        print(f"[v] mutations for {block.label}:")
                        verbose_msg = True

                    # Do mutation
                    block = self.mutate(block, match[0], match[1], match[2], os, verbose)
            
        return block

    
    def mutate(self, block: BBlock, ins_idx: int, n_match_ins: int, operands_and_data: List[Any], os: str, verbose: bool) -> BBlock:
        """
        Selects a generator based on the defined weights and replaces the found pattern with the newly created Instructions.
        
        :param block: BBlock instance to mutate.
        :param ins_idx: Index of the first Instruction of the previously matched pattern.
        :param n_match_ins: Number of Instructions of the matched pattern.
        :param operands_and_data: List that can contain any useful information for the pattern generation. Ex: src and dst.
        :param os: Defined os for logic operations constants.
        :param verbose: Defined verbose level.
        :return: Mutated BBlock.
        """
        
        # unpack self.generators before zip
        mutation_generators, weights = zip(*self.generators)
        # select mutation generator
        selected_generator = random.choices(mutation_generators, weights = weights, k = 1)[0]

        new_instructions: List[Instruction] = selected_generator(operands_and_data, os)

        # verbose related
        if verbose:
            self.print_mutations(block.ops[ins_idx:ins_idx+n_match_ins], new_instructions) 

        # inject new Instruction objects
        block.ops[ins_idx:ins_idx + n_match_ins] = new_instructions
        
        return block
    
    
    def print_mutations(self, old_instructions: List[Instruction], new_instructions: List[Instruction]) -> None:
        """
        Prints the differences between the old code and the new code of a certain mutation.

        :param old_instructions: List of the erased instructions that are part of a pattern defined by a match rule.
        :param new_instructions: List of instructions from a generator that replace the old instructions.
        """
        mutation_addr: int = old_instructions[0].addr
        old_opcodes: List[str] = [ins.opcode for ins in old_instructions]
        new_opcodes: List[str] = []

        # parse instruction opcode/bytes
        for ins in new_instructions:            

            ins_repr: str = getattr(ins, "opcode", None)
            if ins_repr is not None:
                new_opcodes.append([ins_repr])

            else:
                ins_repr = getattr(ins, "bytes", None)
                # wrap bytes
                new_opcodes.append([ins_repr[i:i+35] for i in range(0, len(ins_repr), 35)])


        # print mutation data
        print(f"[v] mutation at {mutation_addr}:")
        print("{:<35} | {:<35}".format("old", "new"))
        print("-" * 75)

        max_len = max(len(old_opcodes), len(new_opcodes))
        for i in range(max_len):
   
            old = old_opcodes[i] if i < len(old_opcodes) else ""
            new = new_opcodes[i] if i < len(new_opcodes) else [""]
   
            print("{:<35} | {:<35}".format(old, new[0]))
   
            # add extra lines for large byte sequences cases
            for line in new[1:]:
                print("{:<35} | {:<35}".format("", line))



# General MutationPatternPool Registry
mutation_pattern_pool_registry: List[MutationPatternPool] = []


# MutationPatterPool that contains instructions and gadgets that move a register value into another register
mov_reg_value_to_reg: MutationPatternPool = MutationPatternPool(
    "mov_reg_value_to_reg",                             # name
    [                                                   # match rules
        match_mov_reg_reg_REG64_REG16,
        match_push_pop_reg_REG64_REG16
    ],
    [                                                   # (generator, weight)
        (generator_mov_reg_reg_REG64_REG16, 1),
        (generator_push_reg_pop_reg_REG64_REG16, 1), # TOFIX
        (generator_mov_reg_reg_extra_code_REG64_REG16, 1),
        (generator_extra_code_mov_reg_reg_REG64_REG16, 1), 
        (generator_push_reg_extra_code_pop_reg_REG64_REG16, 4) 
    ],
    100                                                  # mutation probability (%)
)
# Add MutationPatternPool to registry
mutation_pattern_pool_registry.append(mov_reg_value_to_reg)

# MutationPatterPool that contains instructions and gadgets that set a register to 0
set_reg_to_0: MutationPatternPool = MutationPatternPool(
    "set_reg_to_0",                                     # name
    [                                                   # match rules
        match_mov_reg_0_REGALL,
        match_and_reg_0_REGALL,
        match_xor_reg_reg_REGALL
    ],
    [                                                   # (generator, weight)
        (generator_mov_reg_0_REGALL, 10),
        (generator_and_reg_0_REGALL, 10),
        (generator_xor_reg_reg_REGALL, 10),
        (generator_mov_reg_0_extra_code_REGALL, 2),
        (generator_and_reg_0_extra_code_REGALL, 2),
        (generator_xor_reg_reg_extra_code_REGALL, 2),
        (generator_extra_code_mov_reg_0_REGALL, 2),
        (generator_extra_code_and_reg_0_REGALL, 2),
        (generator_extra_code_xor_reg_reg_REGALL, 2)
    ],
    100                                                  # mutation probability (%)
)
# Add MutationPatternPool to registry
mutation_pattern_pool_registry.append(set_reg_to_0)