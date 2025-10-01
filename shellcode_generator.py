"""
shellcode_generator.py
author: gum3t

Manages the generation of semantically neutral junk shellcode.
"""
import argparse
import random
from typing import List, Tuple, Callable, Dict
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError
from gadgets import *
from regtracker import *
from utils.regdata import *


gadgets: Gadgets = None
reg_tracker: RegTracker = RegTracker()
ks: Ks = Ks(KS_ARCH_X86, KS_MODE_64)


def get_reg_choice_data() -> Tuple[List[str], List[int]]:
    """
    Returns general purpose register names and weights.

    :return: Tuple made of general purpose register names and weights.
    """
    reg_names: List[str] = list(reg_map.keys())
    reg_weights: List[int] = [entry[0] for entry in reg_weights_map]

    return (reg_names, reg_weights)


def get_subreg_choice_data(reg: str) -> Tuple[Tuple[str, ...], Tuple[int, ...]]:
    """
    Returns sub general purpose register names and weights.
    Example given reg == rax:
               (("rax",         "eax",      "ax",       "ah",       "al"),
                (rax_weight,    eax_weight, ax_weight,  ah_weight,  al_weight))

    :param reg: General purpose register to retrieve data from.
    :return: Tuple made of sub general purpose register names and weights.
    """
    subreg_names: Tuple[str, ...] = reg_map[reg] 
    subreg_weights: Tuple[int, ...] = reg_weights_map[list(reg_map.keys()).index(reg)][1]
    
    return (subreg_names, subreg_weights)


def get_secondary_reg(primary_reg: str) -> str:
    """
    Returns a secondary register for instruction generation. 
    Only returns primary register as secondary register if there is no other option.

    :param primary_reg: The main register of the instruction/gadget to be generated.
    :return: The secondary register to be used in instruction generation.
    """
    sec_reg: str = primary_reg

    # there should always be at least one stored register if reached these instructions
    stored_regs: List[str] = reg_tracker.get_stored_registers()
    reg_names, reg_weights = get_reg_choice_data()
    reg_weight_map: Dict[str, int] = dict(zip(reg_names, reg_weights))
    
    # set primary_reg weight to 0
    stored_reg_weights: List[int] = [0 if entry == primary_reg else reg_weight_map[entry] for entry in stored_regs]
    
    # select secondary register
    # avoid using all zero as weights
    if {0} != set(stored_reg_weights):
        sec_reg = random.choices(stored_regs, weights = stored_reg_weights, k = 1)[0]
   
    return sec_reg


def assemble_gadget(gadget: str) -> Tuple[bytes, int]:
    """
    Assembles and returns an asm instruction or gadget.

    :param gadget: The instruction/gadget to be assembled.
    :return: Tuple of the assembled bytes and size of the junk instruction or gadget.
    """
    try:
        encoding, count = ks.asm(gadget)
    except KsError as e:
        print(f"[!] error: {e}")

    return (encoding, count)


def store_reg(reg: str) -> Tuple[bytes, int]:
    """
    Monitors the saving of a register onto the stack.
    Gets a pseudo random couple of junk asm instructions or gadgets to store and restore a register onto the stack.
    Stores assembled pseudo random instruction or gadget to restore a register.
    Returns assembled pseudo random instruction or gadget to store a register and its size.

    :param reg: Register to be stored onto the stack.
    :return: Tuple of the assembled bytes and size of the junk instruction or gadget.
    """
    # select and get pseudo random stack gadget
    gadget_keys: Tuple[str] = tuple(gadgets.stack_gadgets.keys())
    gadget_weights: List[int] = [gadgets.stack_gadgets[key][2] for key in gadget_keys]
    selected_gadget_key: str = random.choices(gadget_keys, weights = gadget_weights, k = 1)[0]
    store_gadget: str = gadgets.stack_gadgets[selected_gadget_key][0](reg)
    restore_gadget: str = gadgets.stack_gadgets[selected_gadget_key][1](reg)

    # assemble store and restore gadgets
    ass_store_gadget, _ = assemble_gadget(store_gadget)
    ass_restore_gadget, _ = assemble_gadget(restore_gadget)

    reg_tracker.store_register(reg, bytes(ass_restore_gadget))

    # update gadgets stack_depth variable for stack pointing related gadgets
    gadgets.stack_depth = reg_tracker.get_stack_depth()

    return bytes(ass_store_gadget), len(bytes(ass_store_gadget))


def restore_reg() -> bytes:
    """
    Monitors the restoration of a register from the stack.
    Returns stored assembled pseudo random instruction or gadget to restore a register.

    :return: Bytes of the stored instruction/gadget.
    """
    top_stack: Tuple[str, bytes] = reg_tracker.get_top_stack_register()
    gadget = top_stack[1]
    if "" != top_stack[0]:
        reg_tracker.restore_register(top_stack[0])
    
    # update gadgets stack_depth variable for stack pointing related gadgets
    gadgets.stack_depth = reg_tracker.get_stack_depth()
    
    return gadget


def get_junk_ins(reg: str) -> Tuple[bytes, int]:
    """
    Gets a pseudo random junk asm instruction or gadget and returns its assembled bytes and size.

    :param reg: The main register of the instruction/gadget to be generated.
    :return: Tuple of the assembled bytes and size of the junk instruction or gadget.
    """
    # get secondary register
    sec_reg = get_secondary_reg(reg)

    # select and get pseudo random operate gadget
    gadget_keys: Tuple[str] = tuple(gadgets.operate_gadgets.keys())
    gadget_weights: List[int] = [gadgets.operate_gadgets[key][2] for key in gadget_keys]
    selected_gadget_key: str = random.choices(gadget_keys, weights = gadget_weights, k = 1)[0]
    selected_gadget: Tuple[Callable, int, int] = gadgets.operate_gadgets[selected_gadget_key]

    # extract flags field from operate gadget
    gadget_reg_flags: int = selected_gadget[1]

    # get subregister names and weights
    subreg_names, subreg_weights = get_subreg_choice_data(reg)
    sec_subreg_names, _ = get_subreg_choice_data(sec_reg)
    # update subregister weights according to instruction compatibility
    updated_subreg_weights: List[int] = [weight if (gadget_reg_flags >> i) & 1 else 0 for i, weight in enumerate(subreg_weights)]
    # select and get pseudo random subregister
    subreg: str = random.choices(subreg_names, weights = updated_subreg_weights, k = 1)[0]

    # get corresponding secondary subregister
    sec_subreg: str | None = sec_subreg_names[subreg_names.index(subreg)]
    
    # handle special case:
    # None means subreg is "ah", "bh", "ch" or "dh"
    # these legacy high subregisters are NOT compatible with
    # REX-prefixed registers "sil", "dil", "r8b" - "r15b"
    # in this case, use legacy low subreg as sec_subreg
    if sec_subreg is None:
        sec_subreg: str = subreg_names[4]

    # get updated gadget from gadget lambda/function
    operate_gadget: str = selected_gadget[0](subreg, sec_subreg)
    # update cnt_reg for loop related gadgets
    gadgets.set_cnt_reg(sec_reg)
    
    #print(f"{operate_gadget = }")
    # assemble operate gadget
    ass_operate_gadget, _ = assemble_gadget(operate_gadget)
    # Avoid loop generation error. TODO: Improve the way this is handled
    if ass_operate_gadget is None:
        ass_operate_gadget = b""

    return bytes(ass_operate_gadget), len(bytes(ass_operate_gadget))


def generate_shellcode(given_sz: int, os: str) -> bytes:
    """
    Generates junk shellcode of a certain size.

    :param given_sz: The size of the shellcode to be generated.
    :param os: Defined os for logic operations constants.
    :return: Junk shellcode of given_sz size.
    """
    shellcode: bytes = b""
    gadget: bytes = b""
    available_space: int = given_sz

    global gadgets
    gadgets = Gadgets(os)

    # generate junk shellcode and store regs if required
    while available_space > 0:
        reg_names, reg_weights = get_reg_choice_data()
        reg: str = random.choices(reg_names, weights = reg_weights, k = 1)[0]
        
        # store reg if not stored
        if not reg_tracker.is_stored(reg):
            
            if available_space <= 16: # Max gadget size * 2. TODO: Standarize value
                continue

            gadget, gadget_sz = store_reg(reg)
            available_space -= gadget_sz + len(reg_tracker.get_top_stack_register()[1])
            shellcode += gadget

        # add junk instructions
        # TODO: make pop instructions available within the instruction pool? Might need to refactor available_space
        if available_space > 0:
            ins, ins_sz = get_junk_ins(reg)

            while available_space - ins_sz < 0:
                ins, ins_sz = get_junk_ins(reg)
            
            available_space -= ins_sz
            shellcode += ins

    # restore regs
    gadget: bytes = restore_reg()
    while gadget != b"":
        shellcode += gadget
        gadget: bytes = restore_reg()

    return shellcode


def main() -> None:
    """
    Main function is left here only for testing purposes.
    """
    parser: ArgumentParser = argparse.ArgumentParser(description = "shellcode_generator.py")
    parser.add_argument(
        "--os",
        choices = ["windows", "linux"],
        default = "windows",
        help = "specify os for logic operations constants"
    )
    args = parser.parse_args()
    print(f"[+] selected os for logic operations constants: {args.os}")

    sc: bytes = generate_shellcode(512, args.os)
    print(f"{len(sc) = }")
    print(f"{sc.hex() = }")


if __name__ == "__main__":
    main()