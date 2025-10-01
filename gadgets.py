"""
gadgets.py
author: gum3t

Provides templates and presets for pseudo instruction and gadget generation.
"""
import random
from typing import List, Tuple, Callable, Dict
from utils.regdata import *
from utils.winflags import winflags
from utils.linflags import linflags


class Gadgets:
    """
    This class contains the necessary information to be able to generate the desired gadgets.
    """

    def br_check_alignment(self, reg: str, sec_reg: str) -> str:
        """
        Branch case for alignment checking.
        Gets value from stack or sec_reg, if aligned: jump, else align it.  
        
        :param reg: Primary register for gadget generation.
        :param sec_reg: Secondary register for gadget generation.
        :return: Gadget that checks and sets the alignment of the primary register value.
        """
        gadget: str         = ""
        label: str          = self.get_asm_label()
        alignment: int      = random.choice([0x1, 0x3, 0x7, 0xf, 0xff, 0xfff])
        mask: int           = 0xffffffffffffffff ^ alignment
        choices: List[str]  = [
            f"{sec_reg}",
            f"[rsp + {random.randint(0x0, self.stack_depth - 1) * 8}]"
        ] 
        
        gadget += f"mov {reg}, {random.choice(choices)};"
        gadget += f"test {reg}, {alignment};"
        gadget += f"jz {label};"
        gadget += f"and {reg}, {mask};"
        gadget += f"{label}:"
        return gadget

    
    def br_check_and_set_0(self, reg: str, sec_reg: str) -> str:
        """
        Branch case for checking and setting to 0.
        Gets value from stack or sec_reg, if 0: jump, else set to 0.
        
        :param reg: Primary register for gadget generation.
        :param sec_reg: Secondary register for gadget generation.
        :return: Gadget that checks and sets the value of the primary register value to 0 if it isn't already.
        """
        gadget: str         = ""
        label: str          = self.get_asm_label()
        choices: List[str]  = [
            f"{sec_reg}",
            f"[rsp + {random.randint(0x0, self.stack_depth - 1) * 8}]"
        ] 

        gadget += f"mov {reg}, {random.choice(choices)};"
        gadget += f"test {reg}, {reg};"
        gadget += f"jz {label};"
        gadget += f"xor {reg}, {reg};"
        gadget += f"{label}:"
        return gadget


    def br_check_flags(self, reg: str, sec_reg: str) -> str:
        """
        Branch case for flag checking.
        Gets flag from defined os flag pool and checks if it is present in the register.
        
        :param reg: Primary register for gadget generation.
        :param sec_reg: Secondary register for gadget generation.
        :return: Gadget that checks if a specific os flag is present in a register and branches accordingly.
        """
        gadget: str = ""
        flag: int   = random.choice(self.logic_flags_pool)
        label: str  = self.get_asm_label()
        
        # handle special case:
        # if flag is over 0x7fffffff, test cannot be used as it does not
        # support this kind of imm
        # must ensure and instruction uses a 32bit register for a similar reason
        if flag > 0x7fffffff:
            sec_reg_tmp: str = reg_map[sec_reg][1] if sec_reg in reg_map else reg
            gadget += f"mov {sec_reg}, {reg};"
            gadget += f"and {sec_reg_tmp}, {flag};"
        else:            
            gadget += f"test {reg}, {flag};"
        
        gadget += f"jnz {label};"
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(1,4))
        gadget += f"{label}:"
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(1,2))
        return gadget


    def br_check_regs(self, reg: str, sec_reg: str) -> str:
        """
        Branch case for register comparations.
        
        :param reg: Primary register for gadget generation.
        :param sec_reg: Secondary register for gadget generation.
        :return: Gadget that compares two registers and branches if condition is met.
        """
        gadget: str = ""
        label: str  = self.get_asm_label()

        # select pseudo random jump gadget
        gadget_keys: Tuple[str]     = tuple(self.jump_gadgets.keys())
        gadget_weights: List[int]   = [self.jump_gadgets[key][1] for key in gadget_keys]
        selected_gadget_key: str    = random.choices(gadget_keys, weights = gadget_weights, k = 1)[0]

        gadget += f"cmp {reg}, {sec_reg};"
        gadget += self.jump_gadgets[selected_gadget_key][0](label)
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(1,4))
        gadget += f"{label}:"
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(0,4))
        return gadget


    def lo_to_0(self, reg: str, sec_reg: str) -> str:
        """
        Loop case from n to 0.
        
        :param reg: Primary register for gadget generation.
        :param sec_reg: Secondary register for gadget generation.
        :return: Gadget that loops a certain number of pseudo random instructions/gadgets. 
        """
        gadget: str         = ""
        label: str          = self.get_asm_label()
        pushed_cnt: bool    = False
        set_in_loop: bool   = False

        # check if regs are compatible for loop generation
        if "" == self.cnt_reg or reg in reg_map[self.cnt_reg] or sec_reg in reg_map[self.cnt_reg]:
            return ""
        
        # check if it is an inner loop
        # in this case push cnt_reg
        if self.in_loop:
            gadget += f"push {self.cnt_reg};"
            pushed_cnt = True
        else:
            self.in_loop = True
            set_in_loop = True

        gadget += f"mov {self.cnt_reg}, {random.randint(0x3, 0x80)};"
        gadget += f"{label}:"
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(1,6))
        gadget += f"dec {self.cnt_reg};"
        gadget += f"cmp {self.cnt_reg}, 0;"
        gadget += f"jne {label};"

        # pop cnt_reg if it was previously pushed
        if pushed_cnt:
            gadget += f"pop {self.cnt_reg};"

        # restore in_loop value to false if it is the outer loop
        if set_in_loop:
            self.in_loop = False

        return gadget


    # TODO: Create incremental counter so collision risk drops to 0 
    def get_asm_label(self) -> str:
        """
        Returns a random label for an asm gadget.
        Avoids KS_ERR_ASM_SYMBOL_REDEFINED in nested cases.
        
        :return: Random generated label for branch purposes in gadget generation.
        """
        hash: int = random.getrandbits(256)
        return "_" + str(hash)


    def get_subreg_gadgets(self, subreg: str) -> Tuple[Tuple[str], List[int]]:
        """
        Returns a pool of gadgets that support a certain register size.
        
        :param subreg: Subregister of a certain size (64bit, 32bit, 16bit, 8hbit, 8lbit)
        :return: Tuple made of gadgets and gadget weights that support subreg register size.
        """
        # get subreg flags related to the given subreg        
        subreg_flags: int = reg_sizes_map[subreg]
        
        # get gadget related data
        gadget_keys: Tuple[str]     = tuple(self.operate_gadgets.keys())
        gadget_weights: List[int]   = [self.operate_gadgets[key][2] for key in gadget_keys]
        gadget_flags: List[int]     = [self.operate_gadgets[key][1] for key in gadget_keys]

        # zero gadget weights for the gadgets that do not support the given subreg
        updated_gadget_weights: List[int] = [
            weight if 0 != (flags & subreg_flags) else 0
            for weight, flags in zip(gadget_weights, gadget_flags)
        ]

        return (gadget_keys, updated_gadget_weights)


    def get_n_junk_ins(self, reg: str, sec_reg: str, n: int) -> str:
        """
        Returns a gadget made of n pseudo random instructions/gadgets.
        Can be indirectly recursive.
        
        :param reg: Primary register for gadget generation.
        :param sec_reg: Secondary register for gadget generation.
        :param n: Amount of instructions/gadgets to be generated.
        :return: Gadget made of n pseudo random instructions/gadgets.
        """
        gadget: str                 = ""
        gadget_keys: Tuple[str]
        gadget_weights: List[int]
        gadget_keys, gadget_weights = self.get_subreg_gadgets(reg)

        # generate gadget for each iteration
        for i in range(n):
            tmp_gadget: str = ""
            # ensure loop gadgets are correctly generated
            while "" == tmp_gadget:
                selected_gadget_key: str    = random.choices(gadget_keys, weights = gadget_weights, k = 1)[0]
                selected_gadget: Callable   = self.operate_gadgets[selected_gadget_key][0]
                tmp_gadget = selected_gadget(reg, sec_reg)
            gadget += tmp_gadget
        
        return gadget

    def set_cnt_reg(self, reg: str) -> None:
        """
        Updates self.cnt_reg value for loop related gadgets.
        
        :param reg: New self.cnt_reg value.
        """
        self.cnt_reg = reg


    def __init__(self, os: str) -> None:
        """
        Initializes the necessary templates, presets and data for pseudo instruction and gadget generation.

        :param os: Defined os for logic operations constants.

        self.logic_flags_pool stores an os defined flag pool.
        self.stack_depth tracks the current stack depth to ensure operations remain within bounds.
        self.cnt_reg defines the register used as counter in loop gadgets.
        self.in_loop tracks if instruction/gadget generation is happening inside a loop.
        self.stack_gadgets defines a pool of instruction/gadget pairs to store and restore registers from the stack.
        self.jump_gadgets defines a pool of jump related instructions/gadgets.
        self.operate_gadgets defines a pool of generic operation instructions/gadgets.
        """
        self.logic_flags_pool: List[int] = []
        if "windows" == os:
            self.logic_flags_pool = winflags
        elif "linux" == os:
            self.logic_flags_pool = linflags
        else:
            print("os not supported yet")
            exit(0)

        # tracks stack depth for stack access related gadgets
        self.stack_depth: int = 0

        # reg used as counter for loop gadgets
        self.cnt_reg: str = ""
        # tracks if instructions are being generated within a loop
        self.in_loop: bool = False

        # set of stack related gadgets. These gadgets modify the stack
        # last value of each tuple is the weight of the gadget
        self.stack_gadgets: Dict[str, Tuple[Callable, Callable, int]] = {
            "push reg;"                     : ( lambda reg: f"push {reg};", lambda reg: f"pop {reg};", 1 ),
            "sub rsp, 8; mov[rsp], reg;"    : ( lambda reg: f"sub rsp, 8; mov [rsp], {reg};", lambda reg: f"mov {reg}, [rsp]; add rsp, 8;", 1 ),
        }
        
        # set of jump related gadgets. These gadgets do not modify the stack
        # last value of each tuple is the weight of the gadget
        self.jump_gadgets: Dict[str, Tuple[Callable, int]] = {
            "jz"    : (lambda label: f"jz {label};", 1 ),
            "jnz"   : (lambda label: f"jnz {label};", 1 ),
            "jg"    : (lambda label: f"jg {label};", 1 ),
            "jge"   : (lambda label: f"jge {label};", 1 ),
            "jl"    : (lambda label: f"jl {label};", 1 ),
            "jle"   : (lambda label: f"jle {label};", 1 ),
            "ja"    : (lambda label: f"ja {label};", 1 ),
            "jae"   : (lambda label: f"jae {label};", 1 ),
            "jb"    : (lambda label: f"jb {label};", 1 ),
            "jbe"   : (lambda label: f"jbe {label};", 1 ),
        }

        # set of gadgets used to operate. These gadgets do not modify the stack
        # last value of each tuple is the weight of the gadget
        self.operate_gadgets: Dict[str, Tuple[Callable, int, int]] = {
            
            # DATA
            # mov
            "mov reg, sec_reg;"     : ( lambda reg, sec_reg: f"mov {reg}, {sec_reg};", REG_ALL, 30 ),
            "mov reg, rsp;"         : ( lambda reg, sec_reg: f"mov {reg}, rsp;", REG_64, 30 ),
            "mov reg, [rsp + x];"   : ( lambda reg, sec_reg: f"mov {reg}, [rsp + {random.randint(0x0, self.stack_depth - 1) * 8}];", REG_ALL, 30 ),
            "mov reg, imm32;"       : ( lambda reg, sec_reg: f"mov {reg}, {random.randint(0x0, 0xffffffff)};", REG_64 | REG_32, 5 ),
            "mov reg, imm16;"       : ( lambda reg, sec_reg: f"mov {reg}, {random.randint(0x0, 0xffff)};", REG_64 | REG_32 | REG_16, 15 ),
            "mov reg, imm8;"        : ( lambda reg, sec_reg: f"mov {reg}, {random.randint(0x0, 0xff)};", REG_ALL, 20 ),
        

            # BINARY ARITHMETIC    
            # add
            "add reg, sec_reg;"     : ( lambda reg, sec_reg: f"add {reg}, {sec_reg};", REG_ALL, 5 ),
            "add reg, [rsp + x];"   : ( lambda reg, sec_reg: f"add {reg}, [rsp + {random.randint(0x0, self.stack_depth - 1) * 8}];", REG_ALL, 10 ),
            # interested in adding negative numbers?
            "add reg64, imm32;"     : ( lambda reg, sec_reg: f"add {reg}, {random.randint(-0x80000000, 0x7fffffff)};", REG_ALL, 5 ),
            "add reg, imm32;"       : ( lambda reg, sec_reg: f"add {reg}, {random.randint(0x0, 0xffffffff)};", REG_32 | REG_16 | REG_8H | REG_8L, 5 ),
            
            # sub
            "sub reg, sec_reg;"     : ( lambda reg, sec_reg: f"sub {reg}, {sec_reg};", REG_ALL, 5 ),
            "sub reg, [rsp + x];"   : ( lambda reg, sec_reg: f"sub {reg}, [rsp + {random.randint(0x0, self.stack_depth - 1) * 8}];", REG_ALL, 10 ),
            "sub reg64, imm32;"     : ( lambda reg, sec_reg: f"sub {reg}, {random.randint(-0x80000000, 0x7fffffff)};", REG_ALL, 5 ),
            "sub reg, imm32;"       : ( lambda reg, sec_reg: f"sub {reg}, {random.randint(0x0, 0xffffffff)};", REG_32 | REG_16 | REG_8H | REG_8L, 5 ),
            
            # inc
            "inc reg;"  : ( lambda reg, sec_reg: f"inc {reg};", REG_ALL, 5 ),
            
            # dec
            "dec reg;"  : ( lambda reg, sec_reg: f"dec {reg};", REG_ALL, 5 ),
                    
        
            # MISC
            # lea
            "lea reg, [sec_reg];"               : ( lambda reg, sec_reg: f"lea {reg}, [{sec_reg}];", REG_64 | REG_32, 5 ),
            "lea reg, [rsp + x];"               : ( lambda reg, sec_reg: f"lea {reg}, [rsp + {random.randint(0x0, self.stack_depth - 1) * 8}];", REG_64 | REG_32, 5 ),
            "lea reg, [rbp - x];"               : ( lambda reg, sec_reg: f"lea {reg}, [rbp - {random.randint(0x0, self.stack_depth - 1) * 8}];", REG_64 | REG_32, 5 ),
            "lea reg, [reg + sec_reg];"         : ( lambda reg, sec_reg: f"lea {reg}, [{reg} + {sec_reg}];", REG_64 | REG_32, 5 ),
            "lea reg, [rsp + reg];"             : ( lambda reg, sec_reg: f"lea {reg}, [rsp + {reg} + {random.randint(0x0, self.stack_depth - 1) * 8}];", REG_64, 5 ),
            "lea reg, [rsp + sec_reg];"         : ( lambda reg, sec_reg: f"lea {reg}, [rsp + {sec_reg} + {random.randint(0x0, self.stack_depth - 1) * 8}];", REG_64, 5 ),
            "lea reg, [reg + 8];"               : ( lambda reg, sec_reg: f"lea {reg}, [{reg} + 8];", REG_64 | REG_32, 5 ),
            "lea reg, [sec_reg + 8];"           : ( lambda reg, sec_reg: f"lea {reg}, [{sec_reg} + 8];", REG_64 | REG_32, 5 ),
            #MAX_VALUES#"lea reg, [reg + imm];" : ( lambda reg, sec_reg: f"lea {reg}, [{reg} + {random.randint(-0x80000000, 0x7fffffff)}];", REG_64 | REG_32, 1 ),
            #MAX_VALUES#"lea reg, [sec_reg + imm];" : ( lambda reg, sec_reg: f"lea {reg}, [{sec_reg} + {random.randint(-0x80000000, 0x7fffffff)}];", REG_64 | REG_32, 1 ),
            "lea reg, [reg + imm];"             : ( lambda reg, sec_reg: f"lea {reg}, [{reg} + {random.randrange(2, 0x101, 2)}];", REG_64 | REG_32, 5 ),
            "lea reg, [sec_reg + imm];"         : ( lambda reg, sec_reg: f"lea {reg}, [{sec_reg} + {random.randrange(2, 0x101, 2)}];", REG_64 | REG_32, 5 ),
            "lea reg, [reg + reg*2];"           : ( lambda reg, sec_reg: f"lea {reg}, [{reg} + {reg}*2];", REG_64 | REG_32, 10 ),
            "lea reg, [sec_reg + sec_reg*2];"   : ( lambda reg, sec_reg: f"lea {reg}, [{sec_reg} + {sec_reg}*2];", REG_64 | REG_32, 10 ),
            "lea reg, [reg + sec_reg*4];"       : ( lambda reg, sec_reg: f"lea {reg}, [{reg} + {sec_reg}*4];", REG_64 | REG_32, 5 ),
        
            # nop
            "nop;"  : ( lambda reg, sec_reg: f"nop;", REG_ALL, 1 ),  
        
        
            # LOGICAL
            # xor
            "xor reg, reg;"         : ( lambda reg, sec_reg: f"xor {reg}, {reg};", REG_ALL, 5 ),
            "xor reg, sec_reg;"     : ( lambda reg, sec_reg: f"xor {reg}, {sec_reg};", REG_ALL, 5 ),
            "xor reg, [rsp + x];"   : ( lambda reg, sec_reg: f"xor {reg}, [rsp + {random.randint(0x0, self.stack_depth - 1) * 8}];", REG_ALL, 5 ),
            "xor reg64, imm32;"     : ( lambda reg, sec_reg: f"xor {reg}, {random.randint(-0x80000000, 0x7fffffff)};", REG_ALL, 5 ),
            "xor reg, imm32;"       : ( lambda reg, sec_reg: f"xor {reg}, {random.randint(0x0, 0xffffffff)};", REG_32 | REG_16 | REG_8H | REG_8L, 5 ),
            "xor reg, flag;"        : ( lambda reg, sec_reg: f"xor {reg}, {random.choice(self.logic_flags_pool)};", REG_32 | REG_16 | REG_8H | REG_8L, 10 ),
        
            # and
            "and reg, 0x0;"         : ( lambda reg, sec_reg: f"and {reg}, 0x0;", REG_ALL, 5 ),
            "and reg, sec_reg;"     : ( lambda reg, sec_reg: f"and {reg}, {sec_reg};", REG_ALL, 5 ),
            "and reg, [rsp + x];"   : ( lambda reg, sec_reg: f"and {reg}, [rsp + {random.randint(0x0, self.stack_depth - 1) * 8}];", REG_ALL, 5 ),
            "and reg64, imm32;"     : ( lambda reg, sec_reg: f"and {reg}, {random.randint(-0x80000000, 0x7fffffff)};", REG_ALL, 5 ),
            "and reg, imm32;"       : ( lambda reg, sec_reg: f"and {reg}, {random.randint(0x0, 0xffffffff)};", REG_32 | REG_16 | REG_8H | REG_8L, 5 ),
            "and reg, flag;"        : ( lambda reg, sec_reg: f"and {reg}, {random.choice(self.logic_flags_pool)};", REG_32 | REG_16 | REG_8H | REG_8L, 10 ),
        
            # or
            "or reg, 0xff..ff;"     : ( lambda reg, sec_reg: f"or {reg}, 0xffffffffffffffff;", REG_ALL, 5 ),
            "or reg, sec_reg;"      : ( lambda reg, sec_reg: f"or {reg}, {sec_reg};", REG_ALL, 5 ),
            "or reg, [rsp + x];"    : ( lambda reg, sec_reg: f"or {reg}, [rsp + {random.randint(0x0, self.stack_depth - 1) * 8}];", REG_ALL, 5 ),
            "or reg64, imm32;"      : ( lambda reg, sec_reg: f"or {reg}, {random.randint(-0x80000000, 0x7fffffff)};", REG_ALL, 5 ),
            "or reg, imm32;"        : ( lambda reg, sec_reg: f"or {reg}, {random.randint(0x0, 0xffffffff)};", REG_32 | REG_16 | REG_8H | REG_8L, 5 ),
            "or reg, flag;"         : ( lambda reg, sec_reg: f"or {reg}, {random.choice(self.logic_flags_pool)};", REG_32 | REG_16 | REG_8H | REG_8L, 10 ),
        
        
            # SHIFT AND ROTATE
            # rol
            "rol reg, 1;"   : ( lambda reg, sec_reg: f"rol {reg}, 1;", REG_ALL, 3 ),
            "rol reg, 2;"   : ( lambda reg, sec_reg: f"rol {reg}, 2;", REG_ALL, 3 ),
            "rol reg, 4;"   : ( lambda reg, sec_reg: f"rol {reg}, 4;", REG_ALL, 3 ),
            "rol reg, 8;"   : ( lambda reg, sec_reg: f"rol {reg}, 8;", REG_64 | REG_32 | REG_16, 3 ),
        
            # sar
            "sar reg, 1;"   : ( lambda reg, sec_reg: f"sar {reg}, 1;", REG_ALL, 3 ),
            "sar reg, 2;"   : ( lambda reg, sec_reg: f"sar {reg}, 2;", REG_ALL, 3 ),
            "sar reg, 4;"   : ( lambda reg, sec_reg: f"sar {reg}, 4;", REG_ALL, 3 ),
            "sar reg, 8;"   : ( lambda reg, sec_reg: f"sar {reg}, 8;", REG_64 | REG_32 | REG_16, 3 ),
        
            # shr
            "shr reg, 1;"   : ( lambda reg, sec_reg: f"shr {reg}, 1;", REG_ALL, 5 ),
            "shr reg, 2;"   : ( lambda reg, sec_reg: f"shr {reg}, 2;", REG_ALL, 5 ),
            "shr reg, 4;"   : ( lambda reg, sec_reg: f"shr {reg}, 4;", REG_ALL, 5 ),
            "shr reg, 8;"   : ( lambda reg, sec_reg: f"shr {reg}, 8;", REG_64 | REG_32 | REG_16, 5 ),
        
            # shl
            "shl reg, 1;"   : ( lambda reg, sec_reg: f"shl {reg}, 1;", REG_ALL, 5 ),
            "shl reg, 2;"   : ( lambda reg, sec_reg: f"shl {reg}, 2;", REG_ALL, 5 ),
            "shl reg, 3;"   : ( lambda reg, sec_reg: f"shl {reg}, 3;", REG_ALL, 5 ),
            "shl reg, 4;"   : ( lambda reg, sec_reg: f"shl {reg}, 4;", REG_ALL, 5 ),
            "shl reg, 8;"   : ( lambda reg, sec_reg: f"shl {reg}, 8;", REG_64 | REG_32 | REG_16, 5 ),


            # BRANCHES
            "check_alignment reg"   : ( self.br_check_alignment, REG_ALL, 10 ),
            "check_and_set_0 reg"   : ( self.br_check_and_set_0, REG_ALL, 10 ),
            "check_regs"            : ( self.br_check_regs, REG_ALL, 10 ),
            "check_flags"           : ( self.br_check_flags, REG_ALL, 10 ),


            # LOOPS
            "loop_to_0"             : ( self.lo_to_0, REG_ALL, 10 ), 
        }