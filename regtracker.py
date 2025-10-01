"""
regtracker.py
author: gum3t

Tracks the state of the defined general purpose registers.
"""
from typing import List, Tuple, Dict

class RegTracker:
    """
    This class tracks the state of the defined general purpose registers.
    """
    
    def __init__(self) -> None:
        """
        Initializes the registry state tracker system.

        self.registers stores whether the registers are stored or not in the stack.
        self.stack emulates the stack order and stores the gadgets that will be used to restore the registers. 
        """
    
        # stores the state of the following registers
        # True  ->  register is stored in the stack
        # False ->  register is not stored in the stack
        self.registers: Dict[str, bool] = {
            "rax": False, "rbx": False, "rcx": False, "rdx": False,
            "rsi": False, "rdi": False, "r8": False, "r9": False,
            "r10": False, "r11": False, "r12": False, "r13": False,
            "r14": False, "r15": False
        }
        # stores the order of the registers within the stack and the gadgets to restore the registers 
        self.stack: List[Tuple[str, bytes]] = []
    

    def store_register(self, reg: str, restore_gadget: bytes) -> None:
        """
        Tracks the event of storing a register onto the stack.
        
        :param reg: Register to be stored onto the stack.
        :param restore_gadget: Gadget to be used in the future to restore the register value.
        """
        if reg in self.registers and False == self.registers[reg]:
            self.stack.append((reg, restore_gadget))
            self.registers[reg] = True
                
        else:
            raise ValueError(f"Invalid or already saved register: {reg}")
    

    def restore_register(self, reg: str) -> None:
        """
        Tracks the event of restoring a register from the stack.
        
        :param reg: Register to be restored from the stack.
        """
        if reg in self.registers and True == self.registers[reg]:
            
            if self.stack[-1][0] == reg:
                self.stack.pop()
                self.registers[reg] = False

            else:
                raise ValueError(f"Register {reg} is not at the top of the stack")

        else:
            raise ValueError(f"Invalid or not saved register: {reg}")
    

    def is_stored(self, reg: str) -> bool:
        """
        Checks if a register's original value is stored on the stack.
        
        :param reg: Register to be checked.
        :return: True if the register's value is stored onto the stack. False otherwise.
        """
        if reg in self.registers:
            return self.registers[reg]
    
        else:
            raise ValueError(f"Invalid register: {reg}")
    

    def get_top_stack_register(self) -> Tuple[str, bytes]:
        """
        Returns the register whose saved value is at the top of the stack, and the gadget to restore it.
        
        :return: Tuple made of the register whose saved value is at the tof of the stack and the gadget to restore it.
        """
        if not self.stack:
            return ("", b"")
        
        else:
            return self.stack[-1]
    
    
    def get_stored_registers(self) -> List[str]:
        """
        Returns all registers whose values have been saved to the stack.
        
        :return: List made of all registers whose values have been saved to the stack.
        """
        return [x[0] for x in self.stack]
    

    def get_stack_depth(self) -> int:
        """
        Returns the depth of the current stack.
        
        :return: Stack depth value.
        """
        return len(self.stack)