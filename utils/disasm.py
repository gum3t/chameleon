"""
disasm.py
author: gum3t

Contains necessary classes for r2 output parsing.
"""
from typing import Dict, List

class Ref:
    """
    This class contains the necessary info to parse refs and xrefs.
    """

    def __init__(self, ref) -> None:
        """
        Initializes ref or xref.
        
        :param ref: Json object or dictionary that contains ref/xref data.
        
        r2 defaults:
        self.addr
        self.types
        self.perm
        """
        self.addr: int = hex(ref.get("addr", None))
        self.type: str = ref.get("type", None)
        self.perm: str = ref.get("perm", None)


    def __repr__(self) -> str:
        """
        Printable representation of the Ref class.
        """
        repr: str = ""
        repr += f"addr: {self.addr}\ttype: {self.type}\tperm: {self.perm}\n"

        return repr


class Instruction:
    """
    This class contains the necessary info to parse instructions.
    """

    def __init__(self, ins) -> None:
        """
        Initializes an instruction.
        
        :param ins: Json object or dictionary that contains instruction data.

        r2 defaults:
        self.addr 
        self.esil 
        self.refptr 
        self.fcn_addr
        self.fcn_last
        self.size
        self.opcode
        self.disasm
        self.bytes
        self.family
        self.type
        self.reloc
        self.type_num
        self.type2_num
        self.jump
        self.flags
        self.refs
        self.xrefs

        custom:
        self.mutated False by default. True when the instruction has been modified or doesn't follow r2 default structure.
        self.mnemonic stores the mnemonic of the instruction.
        self.operand_1 stores the first operand of the instruction if present.
        self.operand_2 stores the second operand of the instruction if present.
        self.operand_3 stores the third operand of the instruction if present.
        """
        # r2 defaults
        self.addr: int          = hex(ins.get("addr", None))        if ins.get("addr", None) is not None else None
        self.esil: str          = ins.get("esil", None)
        self.refptr: int        = hex(ins.get("refptr", None))      if ins.get("refptr", None) is not None else None
        self.fcn_addr: int      = hex(ins.get("fcn_addr", None))    if ins.get("fcn_addr", None) is not None else None
        self.fcn_last: int      = hex(ins.get("fcn_last", None))    if ins.get("fcn_last", None) is not None else None
        self.size: int          = hex(ins.get("size", None))        if ins.get("size", None) is not None else None
        self.opcode: str        = ins.get("opcode", None)
        self.disasm: str        = ins.get("disasm", None)
        self.bytes: str         = ins.get("bytes", None)
        self.family: str        = ins.get("family", None)
        self.type: str          = ins.get("type", None)
        self.reloc: bool        = ins.get("reloc", None)
        self.type_num: int      = hex(ins.get("type_num", None))    if ins.get("type_num", None) is not None else None
        self.type2_num: int     = hex(ins.get("type2_num", None))   if ins.get("type2_num", None) is not None else None
        self.jump: int          = hex(ins.get("jump", None))        if ins.get("jump", None) is not None else None
        self.flags: List[str]   = ins.get("flags", [])
        self.refs: List[Ref]    = []
        self.xrefs: List[Ref]   = []

        refs_data = ins.get("refs", [])
        for ref in refs_data:
            self.refs.append(Ref(ref))

        xrefs_data = ins.get("xrefs", [])
        for ref in xrefs_data:
            self.xrefs.append(Ref(ref))

        # custom
        self.mutated: bool      = ins.get("mutated", False)
        
        self.mnemonic: str      = None
        self.operand_1: str     = None
        self.operand_2: str     = None
        self.operand_3: str     = None

        # only if ingested directly from radare2
        # this allows to create "Instruction instances" that contain a raw blob of bytes from generate_shellcode
        if not self.mutated:

            opcode_parts: List[str] = self.opcode.split(maxsplit = 1) 
            splitted_operands: List[str] = []
    
            if len(opcode_parts) > 1:
                splitted_operands = opcode_parts[1].split(", ")
    
            self.mnemonic   = opcode_parts[0]
            self.operand_1  = splitted_operands[0] if len(splitted_operands) > 0 else None
            self.operand_2  = splitted_operands[1] if len(splitted_operands) > 1 else None
            self.operand_3  = splitted_operands[2] if len(splitted_operands) > 2 else None


    def __repr__(self) -> str:
        """
        Printable representation of the Instruction class.
        """
        repr: str = ""
        repr += f"\naddr: {self.addr}\tesil: {self.esil}\n"
        repr += f"refptr: {self.refptr}\tfcn_addr: {self.fcn_addr}\tfcn_last: {self.fcn_last}\n"
        repr += f"size: {self.size}\n"
        repr += f"opcode: {self.opcode}\n"
        repr += f"mnemonic: {self.mnemonic}\top1: {self.operand_1}\top2: {self.operand_2}\top3: {self.operand_3}\n"
        repr += f"disasm: {self.disasm}\n"
        repr += f"bytes: {self.bytes}\n"
        repr += f"mutated: {self.mutated}\n"
        repr += f"family: {self.family}\ttype: {self.type}\treloc: {self.reloc}\n"
        repr += f"type_num: {self.type_num}\ttype2_num: {self.type2_num}\tjump: {self.jump}\n"
        
        if self.flags:
            repr += "flags:"
            for flag in self.flags:
                repr += f" {flag}"
            repr += "\n"
        
        if self.refs:
            repr += "refs:\n"
            for ref in self.refs:
                repr += f"\t{ref}"

        if self.xrefs:
            repr += "xrefs:\n"
            for xref in self.xrefs:
                repr += f"\t{xref}"
            
        return repr


class BBlock:
    """
    This class contains the necessary info to parse basic blocks.
    """

    def __init__(self, block) -> None:
        """
        Initializes BBlock (Basic Block).
        
        :param block: Json object or dictionary that contains BBlock data.
        
        r2 defaults:
        self.addr
        self.size
        self.jump
        self.fail
        self.ops

        custom:
        self.label stores the defined label for the basic block.
        """
        self.addr: int = hex(block.get("addr", None))
        self.size: int = hex(block.get("size", None))
        self.jump: int = hex(block.get("jump", None)) if block.get("jump", None) is not None else None 
        self.fail: int = hex(block.get("fail", None)) if block.get("fail", None) is not None else None
        
        self.label: str         = f"block_{self.addr}"

        self.ops: List[Instruction] = []
        ops_data = block.get("ops", [])
        for ins in ops_data:
            self.ops.append(Instruction(ins))


    def __repr__(self) -> str:
        """
        Printable representation of the BBlock class.
        """
        repr: str = ""
        repr += f"\n{self.label}\n"
        repr += f"size: {self.size}\tjump: {self.jump}\tfail: {self.fail}\n"

        if self.ops:
            repr += "ops:\n"
            for ins in self.ops:
                repr += f"{ins}"

        return repr