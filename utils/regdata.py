"""
regdata.py
author: gum3t

Contains register-related data necessary for shellcode generation.
"""
from typing import List, Tuple, Dict

# register type flags (bitmask constants)
REG_64: int = 1 << 0  # 64-bit registers (e.g., rax, rbx)
REG_32: int = 1 << 1  # 32-bit registers (e.g., eax, ebx)
REG_16: int = 1 << 2  # 16-bit registers (e.g., ax, bx)
REG_8H: int = 1 << 3  # 8-bit high registers (e.g., ah, bh)
REG_8L: int = 1 << 4  # 8-bit low registers (e.g., al, bl)

# use REG_ALL to specify all kind of registers
REG_ALL: int = REG_64 | REG_32 | REG_16 | REG_8H | REG_8L

# registers available for instruction generation
reg_map: Dict[str, Tuple[str, ...]] = {
    "rax": ("rax", "eax", "ax", "ah", "al"),
    "rbx": ("rbx", "ebx", "bx", "bh", "bl"),
    "rcx": ("rcx", "ecx", "cx", "ch", "cl"),
    "rdx": ("rdx", "edx", "dx", "dh", "dl"),
    "rsi": ("rsi", "esi", "si", None, "sil"),
    "rdi": ("rdi", "edi", "di", None, "dil"),
    "r8" : ("r8", "r8d", "r8w", None, "r8b"),
    "r9" : ("r9", "r9d", "r9w", None, "r9b"),
    "r10": ("r10", "r10d", "r10w", None, "r10b"),
    "r11": ("r11", "r11d", "r11w", None, "r11b"),
    "r12": ("r12", "r12d", "r12w", None, "r12b"),
    "r13": ("r13", "r13d", "r13w", None, "r13b"),
    "r14": ("r14", "r14d", "r14w", None, "r14b"),
    "r15": ("r15", "r15d", "r15w", None, "r15b")
}


# register weights related to instruction generation
reg_weights_map: List[Tuple[int, Tuple[int, ...]]] = (
    (22, (50, 30, 10, 3, 7)),
    (13, (40, 30, 15, 5, 10)),
    (13, (45, 30, 10, 5, 10)),
    (12, (45, 30, 10, 5, 10)),
    (8,  (60, 25, 10, 0, 5)),
    (8,  (60, 25, 10, 0, 5)),
    (3,  (50, 30, 10, 0, 10)),
    (3,  (50, 30, 10, 0, 10)),
    (3,  (50, 30, 10, 0, 10)),
    (3,  (50, 30, 10, 0, 10)),
    (3,  (50, 30, 10, 0, 10)),
    (3,  (50, 30, 10, 0, 10)),
    (3,  (50, 30, 10, 0, 10)),
    (3,  (50, 30, 10, 0, 10))
)

# reg and subreg names related to size flags
# used for recursive instruction generation
reg_sizes_map: Dict[str, int] = {
    "rax" : REG_64,
    "eax" : REG_32,
    "ax"  : REG_16,
    "ah"  : REG_8H,
    "al"  : REG_8L,
    "rbx" : REG_64,
    "ebx" : REG_32,
    "bx"  : REG_16,
    "bh"  : REG_8H,
    "bl"  : REG_8L,
    "rcx" : REG_64,
    "ecx" : REG_32,
    "cx"  : REG_16,
    "ch"  : REG_8H,
    "cl"  : REG_8L,
    "rdx" : REG_64,
    "edx" : REG_32,
    "dx"  : REG_16,
    "dh"  : REG_8H,
    "dl"  : REG_8L,
    "rsi" : REG_64,
    "esi" : REG_32,
    "si"  : REG_16,
    "sil" : REG_8L,
    "rdi" : REG_64,
    "edi" : REG_32,
    "di"  : REG_16,
    "dil" : REG_8L,
    "r8"  : REG_64,
    "r8d" : REG_32,
    "r8w" : REG_16,
    "r8b" : REG_8L,
    "r9"  : REG_64,
    "r9d" : REG_32,
    "r9w" : REG_16,
    "r9b" : REG_8L,
    "r10" : REG_64,
    "r10d": REG_32,
    "r10w": REG_16,
    "r10b": REG_8L,
    "r11" : REG_64,
    "r11d": REG_32,
    "r11w": REG_16,
    "r11b": REG_8L,
    "r12" : REG_64,
    "r12d": REG_32,
    "r12w": REG_16,
    "r12b": REG_8L,
    "r13" : REG_64,
    "r13d": REG_32,
    "r13w": REG_16,
    "r13b": REG_8L,
    "r14" : REG_64,
    "r14d": REG_32,
    "r14w": REG_16,
    "r14b": REG_8L,
    "r15" : REG_64,
    "r15d": REG_32,
    "r15w": REG_16,
    "r15b": REG_8L,
}