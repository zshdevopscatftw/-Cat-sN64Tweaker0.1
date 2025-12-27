#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          CAT'S UNIVERSAL SM64 DECOMPILER 1.0                                 ║
║          A Ghidra-like N64 ROM Decompiler with Visual Studio Style GUI       ║
║          Supports: z64, n64, v64, ROM formats                                ║
║          (C) 2025 Flames Co. / Team Flames                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font
import struct
import os
import re
import json
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum, auto
from collections import defaultdict
import hashlib

# ═══════════════════════════════════════════════════════════════════════════════
# THEME SYSTEM - Visual Studio Style
# ═══════════════════════════════════════════════════════════════════════════════

class ThemeMode(Enum):
    DARK = auto()
    LIGHT = auto()
    SYSTEM = auto()

THEMES = {
    "dark": {
        "name": "Dark (Visual Studio)",
        "bg": "#1e1e1e",
        "bg_secondary": "#252526",
        "bg_tertiary": "#2d2d30",
        "bg_input": "#3c3c3c",
        "fg": "#d4d4d4",
        "fg_secondary": "#808080",
        "fg_muted": "#6a6a6a",
        "accent": "#007acc",
        "accent_hover": "#1c97ea",
        "border": "#3c3c3c",
        "selection": "#264f78",
        "line_number_bg": "#1e1e1e",
        "line_number_fg": "#858585",
        "scrollbar_bg": "#3c3c3c",
        "scrollbar_fg": "#686868",
        "menu_bg": "#2d2d30",
        "menu_fg": "#cccccc",
        "status_bg": "#007acc",
        "status_fg": "#ffffff",
        "tree_select": "#094771",
        "error": "#f44747",
        "warning": "#cca700",
        "success": "#4ec9b0",
        "keyword": "#569cd6",
        "type": "#4ec9b0",
        "string": "#ce9178",
        "number": "#b5cea8",
        "comment": "#6a9955",
        "function": "#dcdcaa",
        "variable": "#9cdcfe",
        "register": "#c586c0",
        "address": "#d7ba7d",
        "instruction": "#569cd6",
        "label": "#4fc1ff",
    },
    "light": {
        "name": "Light (Visual Studio)",
        "bg": "#ffffff",
        "bg_secondary": "#f3f3f3",
        "bg_tertiary": "#eaeaea",
        "bg_input": "#ffffff",
        "fg": "#1e1e1e",
        "fg_secondary": "#6e6e6e",
        "fg_muted": "#999999",
        "accent": "#0078d4",
        "accent_hover": "#106ebe",
        "border": "#cccccc",
        "selection": "#add6ff",
        "line_number_bg": "#f3f3f3",
        "line_number_fg": "#6e6e6e",
        "scrollbar_bg": "#e3e3e3",
        "scrollbar_fg": "#c1c1c1",
        "menu_bg": "#f3f3f3",
        "menu_fg": "#1e1e1e",
        "status_bg": "#0078d4",
        "status_fg": "#ffffff",
        "tree_select": "#cce5ff",
        "error": "#d32f2f",
        "warning": "#f9a825",
        "success": "#2e7d32",
        "keyword": "#0000ff",
        "type": "#267f99",
        "string": "#a31515",
        "number": "#098658",
        "comment": "#008000",
        "function": "#795e26",
        "variable": "#001080",
        "register": "#af00db",
        "address": "#795e26",
        "instruction": "#0000ff",
        "label": "#0070c1",
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MIPS R4300 DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

MIPS_REGISTERS = [
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra"
]

MIPS_FP_REGISTERS = [f"$f{i}" for i in range(32)]

COP0_REGISTERS = [
    "Index", "Random", "EntryLo0", "EntryLo1", "Context", "PageMask", 
    "Wired", "Reserved7", "BadVAddr", "Count", "EntryHi", "Compare",
    "Status", "Cause", "EPC", "PRId", "Config", "LLAddr", "WatchLo",
    "WatchHi", "XContext", "Reserved21", "Reserved22", "Reserved23",
    "Reserved24", "Reserved25", "PErr", "CacheErr", "TagLo", "TagHi",
    "ErrorEPC", "Reserved31"
]

# R-Type instruction opcodes (opcode = 0x00)
R_TYPE_FUNCTS = {
    0x00: ("sll", "d,t,<"),      0x02: ("srl", "d,t,<"),
    0x03: ("sra", "d,t,<"),      0x04: ("sllv", "d,t,s"),
    0x06: ("srlv", "d,t,s"),     0x07: ("srav", "d,t,s"),
    0x08: ("jr", "s"),           0x09: ("jalr", "d,s"),
    0x0c: ("syscall", ""),       0x0d: ("break", ""),
    0x0f: ("sync", ""),          0x10: ("mfhi", "d"),
    0x11: ("mthi", "s"),         0x12: ("mflo", "d"),
    0x13: ("mtlo", "s"),         0x14: ("dsllv", "d,t,s"),
    0x16: ("dsrlv", "d,t,s"),    0x17: ("dsrav", "d,t,s"),
    0x18: ("mult", "s,t"),       0x19: ("multu", "s,t"),
    0x1a: ("div", "s,t"),        0x1b: ("divu", "s,t"),
    0x1c: ("dmult", "s,t"),      0x1d: ("dmultu", "s,t"),
    0x1e: ("ddiv", "s,t"),       0x1f: ("ddivu", "s,t"),
    0x20: ("add", "d,s,t"),      0x21: ("addu", "d,s,t"),
    0x22: ("sub", "d,s,t"),      0x23: ("subu", "d,s,t"),
    0x24: ("and", "d,s,t"),      0x25: ("or", "d,s,t"),
    0x26: ("xor", "d,s,t"),      0x27: ("nor", "d,s,t"),
    0x2a: ("slt", "d,s,t"),      0x2b: ("sltu", "d,s,t"),
    0x2c: ("dadd", "d,s,t"),     0x2d: ("daddu", "d,s,t"),
    0x2e: ("dsub", "d,s,t"),     0x2f: ("dsubu", "d,s,t"),
    0x30: ("tge", "s,t"),        0x31: ("tgeu", "s,t"),
    0x32: ("tlt", "s,t"),        0x33: ("tltu", "s,t"),
    0x34: ("teq", "s,t"),        0x36: ("tne", "s,t"),
    0x38: ("dsll", "d,t,<"),     0x3a: ("dsrl", "d,t,<"),
    0x3b: ("dsra", "d,t,<"),     0x3c: ("dsll32", "d,t,<"),
    0x3e: ("dsrl32", "d,t,<"),   0x3f: ("dsra32", "d,t,<"),
}

# I-Type and J-Type opcodes
I_J_OPCODES = {
    0x01: ("regimm", ""),        0x02: ("j", "J"),
    0x03: ("jal", "J"),          0x04: ("beq", "s,t,B"),
    0x05: ("bne", "s,t,B"),      0x06: ("blez", "s,B"),
    0x07: ("bgtz", "s,B"),       0x08: ("addi", "t,s,i"),
    0x09: ("addiu", "t,s,i"),    0x0a: ("slti", "t,s,i"),
    0x0b: ("sltiu", "t,s,i"),    0x0c: ("andi", "t,s,I"),
    0x0d: ("ori", "t,s,I"),      0x0e: ("xori", "t,s,I"),
    0x0f: ("lui", "t,I"),        0x10: ("cop0", ""),
    0x11: ("cop1", ""),          0x12: ("cop2", ""),
    0x14: ("beql", "s,t,B"),     0x15: ("bnel", "s,t,B"),
    0x16: ("blezl", "s,B"),      0x17: ("bgtzl", "s,B"),
    0x18: ("daddi", "t,s,i"),    0x19: ("daddiu", "t,s,i"),
    0x1a: ("ldl", "t,o(s)"),     0x1b: ("ldr", "t,o(s)"),
    0x20: ("lb", "t,o(s)"),      0x21: ("lh", "t,o(s)"),
    0x22: ("lwl", "t,o(s)"),     0x23: ("lw", "t,o(s)"),
    0x24: ("lbu", "t,o(s)"),     0x25: ("lhu", "t,o(s)"),
    0x26: ("lwr", "t,o(s)"),     0x27: ("lwu", "t,o(s)"),
    0x28: ("sb", "t,o(s)"),      0x29: ("sh", "t,o(s)"),
    0x2a: ("swl", "t,o(s)"),     0x2b: ("sw", "t,o(s)"),
    0x2c: ("sdl", "t,o(s)"),     0x2d: ("sdr", "t,o(s)"),
    0x2e: ("swr", "t,o(s)"),     0x2f: ("cache", ""),
    0x30: ("ll", "t,o(s)"),      0x31: ("lwc1", "T,o(s)"),
    0x34: ("lld", "t,o(s)"),     0x35: ("ldc1", "T,o(s)"),
    0x37: ("ld", "t,o(s)"),      0x38: ("sc", "t,o(s)"),
    0x39: ("swc1", "T,o(s)"),    0x3c: ("scd", "t,o(s)"),
    0x3d: ("sdc1", "T,o(s)"),    0x3f: ("sd", "t,o(s)"),
}

# REGIMM opcodes (opcode = 0x01)
REGIMM_OPCODES = {
    0x00: ("bltz", "s,B"),       0x01: ("bgez", "s,B"),
    0x02: ("bltzl", "s,B"),      0x03: ("bgezl", "s,B"),
    0x08: ("tgei", "s,i"),       0x09: ("tgeiu", "s,i"),
    0x0a: ("tlti", "s,i"),       0x0b: ("tltiu", "s,i"),
    0x0c: ("teqi", "s,i"),       0x0e: ("tnei", "s,i"),
    0x10: ("bltzal", "s,B"),     0x11: ("bgezal", "s,B"),
    0x12: ("bltzall", "s,B"),    0x13: ("bgezall", "s,B"),
}

# COP1 (FPU) opcodes
COP1_FUNCTS = {
    0x00: ("add", "D,S,T"),      0x01: ("sub", "D,S,T"),
    0x02: ("mul", "D,S,T"),      0x03: ("div", "D,S,T"),
    0x04: ("sqrt", "D,S"),       0x05: ("abs", "D,S"),
    0x06: ("mov", "D,S"),        0x07: ("neg", "D,S"),
    0x08: ("round.l", "D,S"),    0x09: ("trunc.l", "D,S"),
    0x0a: ("ceil.l", "D,S"),     0x0b: ("floor.l", "D,S"),
    0x0c: ("round.w", "D,S"),    0x0d: ("trunc.w", "D,S"),
    0x0e: ("ceil.w", "D,S"),     0x0f: ("floor.w", "D,S"),
    0x20: ("cvt.s", "D,S"),      0x21: ("cvt.d", "D,S"),
    0x24: ("cvt.w", "D,S"),      0x25: ("cvt.l", "D,S"),
    0x30: ("c.f", "S,T"),        0x31: ("c.un", "S,T"),
    0x32: ("c.eq", "S,T"),       0x33: ("c.ueq", "S,T"),
    0x34: ("c.olt", "S,T"),      0x35: ("c.ult", "S,T"),
    0x36: ("c.ole", "S,T"),      0x37: ("c.ule", "S,T"),
    0x38: ("c.sf", "S,T"),       0x39: ("c.ngle", "S,T"),
    0x3a: ("c.seq", "S,T"),      0x3b: ("c.ngl", "S,T"),
    0x3c: ("c.lt", "S,T"),       0x3d: ("c.nge", "S,T"),
    0x3e: ("c.le", "S,T"),       0x3f: ("c.ngt", "S,T"),
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class N64ROMHeader:
    """N64 ROM header structure"""
    pi_settings: int = 0
    clock_rate: int = 0
    program_counter: int = 0
    release_address: int = 0
    crc1: int = 0
    crc2: int = 0
    reserved1: bytes = b''
    name: str = ""
    reserved2: bytes = b''
    media_format: int = 0
    cartridge_id: str = ""
    country_code: str = ""
    version: int = 0
    boot_code: bytes = b''

@dataclass
class DisassembledInstruction:
    """A disassembled MIPS instruction"""
    address: int
    raw: int
    mnemonic: str
    operands: str
    comment: str = ""
    is_branch_target: bool = False
    is_function_start: bool = False
    label: str = ""

@dataclass
class Function:
    """Represents a detected function"""
    name: str
    start_address: int
    end_address: int
    instructions: List[DisassembledInstruction] = field(default_factory=list)
    calls: Set[int] = field(default_factory=set)
    called_by: Set[int] = field(default_factory=set)
    local_vars: Dict[int, str] = field(default_factory=dict)
    is_leaf: bool = True

@dataclass
class Symbol:
    """Symbol table entry"""
    name: str
    address: int
    size: int
    sym_type: str  # "function", "data", "label"

# ═══════════════════════════════════════════════════════════════════════════════
# N64 ROM PARSER
# ═══════════════════════════════════════════════════════════════════════════════

class N64ROM:
    """N64 ROM file parser with format detection and byte swapping"""
    
    ROM_SIGNATURES = {
        b'\x80\x37\x12\x40': 'z64',  # Big-endian (native)
        b'\x37\x80\x40\x12': 'n64',  # Byte-swapped
        b'\x40\x12\x37\x80': 'v64',  # Little-endian
    }
    
    COUNTRY_CODES = {
        0x00: "Demo", 0x37: "Beta", 0x41: "Asian (NTSC)",
        0x42: "Brazilian", 0x43: "Chinese", 0x44: "German",
        0x45: "North American", 0x46: "French", 0x47: "Gateway 64",
        0x48: "Dutch", 0x49: "Italian", 0x4A: "Japanese",
        0x4B: "Korean", 0x4C: "Gateway 64 (PAL)", 0x4E: "Canadian",
        0x50: "European", 0x53: "Spanish", 0x55: "Australian",
        0x57: "Scandinavian", 0x58: "European", 0x59: "European",
    }
    
    def __init__(self):
        self.data: bytes = b''
        self.format: str = ""
        self.header: N64ROMHeader = N64ROMHeader()
        self.filepath: str = ""
        
    def load(self, filepath: str) -> bool:
        """Load and parse an N64 ROM file"""
        try:
            with open(filepath, 'rb') as f:
                raw_data = f.read()
            
            self.filepath = filepath
            self.format = self._detect_format(raw_data[:4])
            self.data = self._convert_to_z64(raw_data)
            self._parse_header()
            return True
        except Exception as e:
            raise ValueError(f"Failed to load ROM: {e}")
    
    def _detect_format(self, signature: bytes) -> str:
        """Detect ROM format from signature"""
        if signature in self.ROM_SIGNATURES:
            return self.ROM_SIGNATURES[signature]
        raise ValueError(f"Unknown ROM format: {signature.hex()}")
    
    def _convert_to_z64(self, data: bytes) -> bytes:
        """Convert ROM to big-endian (z64) format"""
        if self.format == 'z64':
            return data
        elif self.format == 'n64':
            # Byte-swap pairs
            result = bytearray(len(data))
            for i in range(0, len(data), 2):
                if i + 1 < len(data):
                    result[i] = data[i + 1]
                    result[i + 1] = data[i]
            return bytes(result)
        elif self.format == 'v64':
            # Word-swap
            result = bytearray(len(data))
            for i in range(0, len(data), 4):
                if i + 3 < len(data):
                    result[i] = data[i + 3]
                    result[i + 1] = data[i + 2]
                    result[i + 2] = data[i + 1]
                    result[i + 3] = data[i]
            return bytes(result)
        return data
    
    def _parse_header(self):
        """Parse the N64 ROM header"""
        if len(self.data) < 0x40:
            raise ValueError("ROM too small for header")
        
        self.header.pi_settings = struct.unpack('>I', self.data[0x00:0x04])[0]
        self.header.clock_rate = struct.unpack('>I', self.data[0x04:0x08])[0]
        self.header.program_counter = struct.unpack('>I', self.data[0x08:0x0C])[0]
        self.header.release_address = struct.unpack('>I', self.data[0x0C:0x10])[0]
        self.header.crc1 = struct.unpack('>I', self.data[0x10:0x14])[0]
        self.header.crc2 = struct.unpack('>I', self.data[0x14:0x18])[0]
        self.header.reserved1 = self.data[0x18:0x20]
        self.header.name = self.data[0x20:0x34].decode('ascii', errors='replace').strip('\x00 ')
        self.header.reserved2 = self.data[0x34:0x38]
        self.header.media_format = struct.unpack('>I', self.data[0x38:0x3C])[0]
        self.header.cartridge_id = self.data[0x3C:0x3E].decode('ascii', errors='replace')
        self.header.country_code = chr(self.data[0x3E])
        self.header.version = self.data[0x3F]
        
        if len(self.data) >= 0x1000:
            self.header.boot_code = self.data[0x40:0x1000]
    
    def read_word(self, address: int) -> int:
        """Read a 32-bit word from the ROM"""
        offset = address & 0x00FFFFFF
        if offset + 4 <= len(self.data):
            return struct.unpack('>I', self.data[offset:offset+4])[0]
        return 0
    
    def read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes from the ROM"""
        offset = address & 0x00FFFFFF
        if offset + size <= len(self.data):
            return self.data[offset:offset+size]
        return b'\x00' * size
    
    def get_country_name(self) -> str:
        """Get human-readable country name"""
        code = ord(self.header.country_code) if self.header.country_code else 0
        return self.COUNTRY_CODES.get(code, f"Unknown ({code})")

# ═══════════════════════════════════════════════════════════════════════════════
# MIPS R4300 DISASSEMBLER
# ═══════════════════════════════════════════════════════════════════════════════

class MIPSDisassembler:
    """MIPS R4300 instruction disassembler"""
    
    def __init__(self, rom: N64ROM):
        self.rom = rom
        self.symbols: Dict[int, Symbol] = {}
        self.labels: Dict[int, str] = {}
        self.branch_targets: Set[int] = set()
        
    def add_symbol(self, address: int, name: str, sym_type: str = "label", size: int = 0):
        """Add a symbol to the symbol table"""
        self.symbols[address] = Symbol(name, address, size, sym_type)
        self.labels[address] = name
    
    def disassemble_instruction(self, address: int) -> DisassembledInstruction:
        """Disassemble a single instruction at the given address"""
        raw = self.rom.read_word(address)
        opcode = (raw >> 26) & 0x3F
        
        mnemonic = "???"
        operands = f"0x{raw:08X}"
        comment = ""
        
        if raw == 0x00000000:
            mnemonic = "nop"
            operands = ""
        elif opcode == 0x00:  # R-Type
            mnemonic, operands, comment = self._disassemble_r_type(raw, address)
        elif opcode == 0x01:  # REGIMM
            mnemonic, operands, comment = self._disassemble_regimm(raw, address)
        elif opcode == 0x10:  # COP0
            mnemonic, operands, comment = self._disassemble_cop0(raw)
        elif opcode == 0x11:  # COP1 (FPU)
            mnemonic, operands, comment = self._disassemble_cop1(raw, address)
        else:  # I-Type or J-Type
            mnemonic, operands, comment = self._disassemble_i_j_type(raw, address, opcode)
        
        return DisassembledInstruction(
            address=address,
            raw=raw,
            mnemonic=mnemonic,
            operands=operands,
            comment=comment,
            is_branch_target=address in self.branch_targets,
            label=self.labels.get(address, "")
        )
    
    def _disassemble_r_type(self, raw: int, address: int) -> Tuple[str, str, str]:
        """Disassemble R-Type instruction"""
        rs = (raw >> 21) & 0x1F
        rt = (raw >> 16) & 0x1F
        rd = (raw >> 11) & 0x1F
        sa = (raw >> 6) & 0x1F
        funct = raw & 0x3F
        
        if funct not in R_TYPE_FUNCTS:
            return "???", f"0x{raw:08X}", ""
        
        mnemonic, fmt = R_TYPE_FUNCTS[funct]
        operands = self._format_operands(fmt, rs, rt, rd, sa, 0, address)
        
        comment = ""
        if mnemonic in ("jr", "jalr") and rs == 31:
            comment = "return"
        
        return mnemonic, operands, comment
    
    def _disassemble_regimm(self, raw: int, address: int) -> Tuple[str, str, str]:
        """Disassemble REGIMM instruction"""
        rs = (raw >> 21) & 0x1F
        rt = (raw >> 16) & 0x1F
        imm = raw & 0xFFFF
        
        if rt not in REGIMM_OPCODES:
            return "???", f"0x{raw:08X}", ""
        
        mnemonic, fmt = REGIMM_OPCODES[rt]
        
        if 'B' in fmt:
            offset = self._sign_extend(imm, 16) << 2
            target = (address + 4) + offset
            self.branch_targets.add(target)
            operands = self._format_operands(fmt, rs, rt, 0, 0, imm, address)
        else:
            operands = self._format_operands(fmt, rs, rt, 0, 0, imm, address)
        
        return mnemonic, operands, ""
    
    def _disassemble_cop0(self, raw: int) -> Tuple[str, str, str]:
        """Disassemble COP0 instruction"""
        rs = (raw >> 21) & 0x1F
        rt = (raw >> 16) & 0x1F
        rd = (raw >> 11) & 0x1F
        funct = raw & 0x3F
        
        if rs == 0x00:  # MFC0
            reg_name = COP0_REGISTERS[rd] if rd < len(COP0_REGISTERS) else f"${rd}"
            return "mfc0", f"{MIPS_REGISTERS[rt]}, {reg_name}", ""
        elif rs == 0x04:  # MTC0
            reg_name = COP0_REGISTERS[rd] if rd < len(COP0_REGISTERS) else f"${rd}"
            return "mtc0", f"{MIPS_REGISTERS[rt]}, {reg_name}", ""
        elif rs == 0x10:  # TLB operations
            if funct == 0x01:
                return "tlbr", "", ""
            elif funct == 0x02:
                return "tlbwi", "", ""
            elif funct == 0x06:
                return "tlbwr", "", ""
            elif funct == 0x08:
                return "tlbp", "", ""
            elif funct == 0x18:
                return "eret", "", ""
        
        return "cop0", f"0x{raw:08X}", ""
    
    def _disassemble_cop1(self, raw: int, address: int) -> Tuple[str, str, str]:
        """Disassemble COP1 (FPU) instruction"""
        rs = (raw >> 21) & 0x1F
        rt = (raw >> 16) & 0x1F
        rd = (raw >> 11) & 0x1F
        fs = (raw >> 11) & 0x1F
        ft = (raw >> 16) & 0x1F
        fd = (raw >> 6) & 0x1F
        funct = raw & 0x3F
        
        fmt_type = rs & 0x1F
        
        if rs == 0x00:  # MFC1
            return "mfc1", f"{MIPS_REGISTERS[rt]}, {MIPS_FP_REGISTERS[fs]}", ""
        elif rs == 0x01:  # DMFC1
            return "dmfc1", f"{MIPS_REGISTERS[rt]}, {MIPS_FP_REGISTERS[fs]}", ""
        elif rs == 0x02:  # CFC1
            return "cfc1", f"{MIPS_REGISTERS[rt]}, ${fs}", ""
        elif rs == 0x04:  # MTC1
            return "mtc1", f"{MIPS_REGISTERS[rt]}, {MIPS_FP_REGISTERS[fs]}", ""
        elif rs == 0x05:  # DMTC1
            return "dmtc1", f"{MIPS_REGISTERS[rt]}, {MIPS_FP_REGISTERS[fs]}", ""
        elif rs == 0x06:  # CTC1
            return "ctc1", f"{MIPS_REGISTERS[rt]}, ${fs}", ""
        elif rs == 0x08:  # BC1
            imm = raw & 0xFFFF
            offset = self._sign_extend(imm, 16) << 2
            target = (address + 4) + offset
            self.branch_targets.add(target)
            if rt == 0x00:
                return "bc1f", f"0x{target:08X}", ""
            elif rt == 0x01:
                return "bc1t", f"0x{target:08X}", ""
            elif rt == 0x02:
                return "bc1fl", f"0x{target:08X}", ""
            elif rt == 0x03:
                return "bc1tl", f"0x{target:08X}", ""
        elif fmt_type in (0x10, 0x11):  # Single or Double precision
            fmt_suffix = ".s" if fmt_type == 0x10 else ".d"
            if funct in COP1_FUNCTS:
                base_mnemonic, operand_fmt = COP1_FUNCTS[funct]
                mnemonic = base_mnemonic + fmt_suffix
                operands = self._format_fp_operands(operand_fmt, fd, fs, ft)
                return mnemonic, operands, ""
        elif fmt_type == 0x14:  # Word
            if funct in COP1_FUNCTS:
                base_mnemonic, operand_fmt = COP1_FUNCTS[funct]
                mnemonic = base_mnemonic + ".w"
                operands = self._format_fp_operands(operand_fmt, fd, fs, ft)
                return mnemonic, operands, ""
        elif fmt_type == 0x15:  # Long
            if funct in COP1_FUNCTS:
                base_mnemonic, operand_fmt = COP1_FUNCTS[funct]
                mnemonic = base_mnemonic + ".l"
                operands = self._format_fp_operands(operand_fmt, fd, fs, ft)
                return mnemonic, operands, ""
        
        return "cop1", f"0x{raw:08X}", ""
    
    def _disassemble_i_j_type(self, raw: int, address: int, opcode: int) -> Tuple[str, str, str]:
        """Disassemble I-Type or J-Type instruction"""
        rs = (raw >> 21) & 0x1F
        rt = (raw >> 16) & 0x1F
        imm = raw & 0xFFFF
        target = raw & 0x03FFFFFF
        
        if opcode not in I_J_OPCODES:
            return "???", f"0x{raw:08X}", ""
        
        mnemonic, fmt = I_J_OPCODES[opcode]
        comment = ""
        
        if fmt == "J":
            target_addr = ((address + 4) & 0xF0000000) | (target << 2)
            if target_addr in self.labels:
                operands = self.labels[target_addr]
            else:
                operands = f"0x{target_addr:08X}"
            if mnemonic == "jal":
                self.branch_targets.add(target_addr)
                comment = "function call"
        elif 'B' in fmt:
            offset = self._sign_extend(imm, 16) << 2
            target_addr = (address + 4) + offset
            self.branch_targets.add(target_addr)
            operands = self._format_operands(fmt, rs, rt, 0, 0, imm, address)
        else:
            operands = self._format_operands(fmt, rs, rt, 0, 0, imm, address)
        
        # Add comments for common patterns
        if mnemonic == "lui":
            comment = f"upper 16 bits = 0x{imm:04X}"
        elif mnemonic == "addiu" and rs == 29:  # Stack operations
            signed_imm = self._sign_extend(imm, 16)
            if signed_imm < 0:
                comment = f"allocate {-signed_imm} bytes on stack"
            else:
                comment = f"deallocate {signed_imm} bytes from stack"
        
        return mnemonic, operands, comment
    
    def _format_operands(self, fmt: str, rs: int, rt: int, rd: int, sa: int, 
                         imm: int, address: int) -> str:
        """Format instruction operands based on format string"""
        result = fmt
        result = result.replace('s', MIPS_REGISTERS[rs])
        result = result.replace('t', MIPS_REGISTERS[rt])
        result = result.replace('d', MIPS_REGISTERS[rd])
        result = result.replace('<', str(sa))
        
        if 'o' in result:
            signed_offset = self._sign_extend(imm, 16)
            result = result.replace('o', str(signed_offset))
        if 'i' in result:
            signed_imm = self._sign_extend(imm, 16)
            result = result.replace('i', str(signed_imm))
        if 'I' in result:
            result = result.replace('I', f"0x{imm:04X}")
        if 'B' in result:
            offset = self._sign_extend(imm, 16) << 2
            target = (address + 4) + offset
            if target in self.labels:
                result = result.replace('B', self.labels[target])
            else:
                result = result.replace('B', f"0x{target:08X}")
        if 'T' in result:
            result = result.replace('T', MIPS_FP_REGISTERS[rt])
        
        return result
    
    def _format_fp_operands(self, fmt: str, fd: int, fs: int, ft: int) -> str:
        """Format FPU instruction operands"""
        result = fmt
        result = result.replace('D', MIPS_FP_REGISTERS[fd])
        result = result.replace('S', MIPS_FP_REGISTERS[fs])
        result = result.replace('T', MIPS_FP_REGISTERS[ft])
        return result
    
    def _sign_extend(self, value: int, bits: int) -> int:
        """Sign-extend a value"""
        sign_bit = 1 << (bits - 1)
        return (value & (sign_bit - 1)) - (value & sign_bit)
    
    def disassemble_range(self, start: int, end: int) -> List[DisassembledInstruction]:
        """Disassemble a range of addresses"""
        instructions = []
        address = start
        while address < end:
            inst = self.disassemble_instruction(address)
            instructions.append(inst)
            address += 4
        return instructions

# ═══════════════════════════════════════════════════════════════════════════════
# DECOMPILER - MIPS TO C
# ═══════════════════════════════════════════════════════════════════════════════

class MIPSDecompiler:
    """Converts MIPS assembly to C-like pseudocode"""
    
    def __init__(self, disassembler: MIPSDisassembler):
        self.disasm = disassembler
        self.functions: Dict[int, Function] = {}
        self.pending_hi16: Dict[int, int] = {}  # Track LUI values
        
    def detect_functions(self, start: int, end: int) -> List[Function]:
        """Detect function boundaries in a range"""
        functions = []
        current_func = None
        instructions = self.disasm.disassemble_range(start, end)
        
        # First pass: find JAL targets (function starts)
        func_starts = set()
        for inst in instructions:
            if inst.mnemonic == "jal":
                try:
                    target = int(inst.operands.replace("0x", ""), 16)
                    func_starts.add(target)
                except:
                    pass
        
        # Add entry point
        entry = self.disasm.rom.header.program_counter
        if start <= entry < end:
            func_starts.add(entry)
        
        func_starts.add(start)  # Start of range is also a function
        
        # Sort function starts
        sorted_starts = sorted(func_starts)
        
        # Create function objects
        for i, func_start in enumerate(sorted_starts):
            if func_start < start or func_start >= end:
                continue
            
            # Find end of function (next function start or JR $RA)
            func_end = end
            if i + 1 < len(sorted_starts) and sorted_starts[i + 1] < end:
                func_end = sorted_starts[i + 1]
            
            # Check for early return
            for inst in instructions:
                if inst.address >= func_start and inst.address < func_end:
                    if inst.mnemonic == "jr" and "$ra" in inst.operands:
                        # Include delay slot
                        potential_end = inst.address + 8
                        if potential_end < func_end:
                            func_end = potential_end
                        break
            
            name = self.disasm.labels.get(func_start, f"func_{func_start:08X}")
            func = Function(
                name=name,
                start_address=func_start,
                end_address=func_end
            )
            
            # Add instructions to function
            for inst in instructions:
                if inst.address >= func_start and inst.address < func_end:
                    func.instructions.append(inst)
            
            functions.append(func)
            self.functions[func_start] = func
            self.disasm.add_symbol(func_start, name, "function", func_end - func_start)
        
        return functions
    
    def decompile_function(self, func: Function) -> str:
        """Decompile a function to C-like pseudocode"""
        lines = []
        lines.append(f"// Function: {func.name}")
        lines.append(f"// Address: 0x{func.start_address:08X} - 0x{func.end_address:08X}")
        lines.append(f"// Size: {func.end_address - func.start_address} bytes")
        lines.append("")
        
        # Analyze stack frame
        stack_size = self._analyze_stack(func)
        local_vars = self._analyze_locals(func)
        
        # Generate function signature
        params = self._analyze_parameters(func)
        return_type = self._analyze_return_type(func)
        
        param_str = ", ".join(params) if params else "void"
        lines.append(f"{return_type} {func.name}({param_str}) {{")
        
        # Local variable declarations
        if local_vars:
            lines.append("    // Local variables")
            for offset, var_type in local_vars.items():
                lines.append(f"    {var_type} var_{abs(offset):X};")
            lines.append("")
        
        # Decompile body
        body_lines = self._decompile_body(func)
        for line in body_lines:
            lines.append(f"    {line}")
        
        lines.append("}")
        return "\n".join(lines)
    
    def _analyze_stack(self, func: Function) -> int:
        """Analyze stack frame size"""
        stack_size = 0
        for inst in func.instructions:
            if inst.mnemonic == "addiu" and "$sp" in inst.operands:
                match = re.search(r'-?\d+', inst.operands.split(',')[-1])
                if match:
                    val = int(match.group())
                    if val < 0:
                        stack_size = max(stack_size, -val)
        return stack_size
    
    def _analyze_locals(self, func: Function) -> Dict[int, str]:
        """Analyze local variables on stack"""
        locals_map = {}
        for inst in func.instructions:
            if inst.mnemonic in ("lw", "sw", "lh", "sh", "lb", "sb", "ld", "sd"):
                match = re.search(r'(-?\d+)\(\$sp\)', inst.operands)
                if match:
                    offset = int(match.group(1))
                    if offset < 0:
                        if inst.mnemonic in ("lw", "sw"):
                            locals_map[offset] = "s32"
                        elif inst.mnemonic in ("lh", "sh"):
                            locals_map[offset] = "s16"
                        elif inst.mnemonic in ("lb", "sb"):
                            locals_map[offset] = "s8"
                        elif inst.mnemonic in ("ld", "sd"):
                            locals_map[offset] = "s64"
        return locals_map
    
    def _analyze_parameters(self, func: Function) -> List[str]:
        """Analyze function parameters"""
        params = []
        used_args = set()
        
        for inst in func.instructions[:20]:  # Check first few instructions
            ops = inst.operands
            for i, reg in enumerate(["$a0", "$a1", "$a2", "$a3"]):
                if reg in ops and reg not in inst.mnemonic:
                    # Check if it's being read, not written
                    parts = ops.split(',')
                    if len(parts) > 1 and reg in parts[1]:
                        used_args.add(i)
        
        for i in sorted(used_args):
            params.append(f"s32 a{i}")
        
        return params
    
    def _analyze_return_type(self, func: Function) -> str:
        """Analyze return type"""
        # Check if $v0 is set before return
        for inst in reversed(func.instructions):
            if inst.mnemonic == "jr" and "$ra" in inst.operands:
                continue
            if "$v0" in inst.operands:
                parts = inst.operands.split(',')
                if len(parts) > 0 and "$v0" in parts[0]:
                    return "s32"
                break
        
        # Check for FP return
        for inst in reversed(func.instructions[-10:]):
            if "$f0" in inst.operands:
                return "f32"
        
        return "void"
    
    def _decompile_body(self, func: Function) -> List[str]:
        """Decompile function body to C statements"""
        lines = []
        i = 0
        instructions = func.instructions
        
        while i < len(instructions):
            inst = instructions[i]
            
            # Skip NOPs
            if inst.mnemonic == "nop":
                i += 1
                continue
            
            # Add label if branch target
            if inst.is_branch_target or inst.label:
                label = inst.label or f"loc_{inst.address:08X}"
                lines.append(f"{label}:")
            
            # Convert instruction to C
            c_line = self._instruction_to_c(inst, instructions, i)
            if c_line:
                lines.append(c_line)
            
            i += 1
        
        return lines
    
    def _instruction_to_c(self, inst: DisassembledInstruction, 
                          all_insts: List[DisassembledInstruction], idx: int) -> str:
        """Convert a single instruction to C code"""
        mnemonic = inst.mnemonic
        ops = inst.operands
        
        # Parse operands
        operand_list = [o.strip() for o in ops.split(',')] if ops else []
        
        # Arithmetic operations
        if mnemonic in ("add", "addu", "dadd", "daddu"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = {self._reg_to_var(operand_list[1])} + {self._reg_to_var(operand_list[2])};"
        
        if mnemonic in ("addi", "addiu", "daddi", "daddiu"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = {self._reg_to_var(operand_list[1])} + {operand_list[2]};"
        
        if mnemonic in ("sub", "subu", "dsub", "dsubu"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = {self._reg_to_var(operand_list[1])} - {self._reg_to_var(operand_list[2])};"
        
        if mnemonic in ("and", "andi"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = {self._reg_to_var(operand_list[1])} & {operand_list[2]};"
        
        if mnemonic in ("or", "ori"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = {self._reg_to_var(operand_list[1])} | {operand_list[2]};"
        
        if mnemonic in ("xor", "xori"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = {self._reg_to_var(operand_list[1])} ^ {operand_list[2]};"
        
        if mnemonic == "nor":
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = ~({self._reg_to_var(operand_list[1])} | {self._reg_to_var(operand_list[2])});"
        
        # Shifts
        if mnemonic in ("sll", "dsll", "dsll32"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = {self._reg_to_var(operand_list[1])} << {operand_list[2]};"
        
        if mnemonic in ("srl", "dsrl", "dsrl32"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = (u32){self._reg_to_var(operand_list[1])} >> {operand_list[2]};"
        
        if mnemonic in ("sra", "dsra", "dsra32"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = (s32){self._reg_to_var(operand_list[1])} >> {operand_list[2]};"
        
        # Load upper immediate
        if mnemonic == "lui":
            if len(operand_list) >= 2:
                return f"{self._reg_to_var(operand_list[0])} = {operand_list[1]} << 16;  // LUI"
        
        # Memory operations
        if mnemonic in ("lw", "lh", "lhu", "lb", "lbu", "ld", "lwu"):
            match = re.match(r'(\$\w+),\s*(-?\d+)\((\$\w+)\)', ops)
            if match:
                dest, offset, base = match.groups()
                type_map = {"lw": "s32", "lh": "s16", "lhu": "u16", 
                           "lb": "s8", "lbu": "u8", "ld": "s64", "lwu": "u32"}
                cast = type_map.get(mnemonic, "s32")
                return f"{self._reg_to_var(dest)} = *({cast}*)({self._reg_to_var(base)} + {offset});"
        
        if mnemonic in ("sw", "sh", "sb", "sd"):
            match = re.match(r'(\$\w+),\s*(-?\d+)\((\$\w+)\)', ops)
            if match:
                src, offset, base = match.groups()
                type_map = {"sw": "s32", "sh": "s16", "sb": "s8", "sd": "s64"}
                cast = type_map.get(mnemonic, "s32")
                return f"*({cast}*)({self._reg_to_var(base)} + {offset}) = {self._reg_to_var(src)};"
        
        # Branches
        if mnemonic in ("beq", "beql"):
            if len(operand_list) >= 3:
                return f"if ({self._reg_to_var(operand_list[0])} == {self._reg_to_var(operand_list[1])}) goto {operand_list[2]};"
        
        if mnemonic in ("bne", "bnel"):
            if len(operand_list) >= 3:
                return f"if ({self._reg_to_var(operand_list[0])} != {self._reg_to_var(operand_list[1])}) goto {operand_list[2]};"
        
        if mnemonic in ("bgtz", "bgtzl"):
            if len(operand_list) >= 2:
                return f"if ({self._reg_to_var(operand_list[0])} > 0) goto {operand_list[1]};"
        
        if mnemonic in ("blez", "blezl"):
            if len(operand_list) >= 2:
                return f"if ({self._reg_to_var(operand_list[0])} <= 0) goto {operand_list[1]};"
        
        if mnemonic in ("bltz", "bltzl"):
            if len(operand_list) >= 2:
                return f"if ({self._reg_to_var(operand_list[0])} < 0) goto {operand_list[1]};"
        
        if mnemonic in ("bgez", "bgezl"):
            if len(operand_list) >= 2:
                return f"if ({self._reg_to_var(operand_list[0])} >= 0) goto {operand_list[1]};"
        
        # Jumps
        if mnemonic == "j":
            return f"goto {ops};"
        
        if mnemonic == "jal":
            return f"func_{ops.replace('0x', '')}();  // JAL"
        
        if mnemonic == "jr":
            if "$ra" in ops:
                return "return;"
            return f"goto *{self._reg_to_var(ops)};"
        
        if mnemonic == "jalr":
            return f"(*{self._reg_to_var(operand_list[-1])})();  // JALR"
        
        # Set on less than
        if mnemonic in ("slt", "sltu"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = ({self._reg_to_var(operand_list[1])} < {self._reg_to_var(operand_list[2])}) ? 1 : 0;"
        
        if mnemonic in ("slti", "sltiu"):
            if len(operand_list) >= 3:
                return f"{self._reg_to_var(operand_list[0])} = ({self._reg_to_var(operand_list[1])} < {operand_list[2]}) ? 1 : 0;"
        
        # Multiply/Divide
        if mnemonic in ("mult", "multu", "dmult", "dmultu"):
            if len(operand_list) >= 2:
                return f"__mult({self._reg_to_var(operand_list[0])}, {self._reg_to_var(operand_list[1])});  // HI:LO = result"
        
        if mnemonic in ("div", "divu", "ddiv", "ddivu"):
            if len(operand_list) >= 2:
                return f"__div({self._reg_to_var(operand_list[0])}, {self._reg_to_var(operand_list[1])});  // LO = quotient, HI = remainder"
        
        if mnemonic == "mflo":
            return f"{self._reg_to_var(operand_list[0])} = __LO;"
        
        if mnemonic == "mfhi":
            return f"{self._reg_to_var(operand_list[0])} = __HI;"
        
        if mnemonic == "mtlo":
            return f"__LO = {self._reg_to_var(operand_list[0])};"
        
        if mnemonic == "mthi":
            return f"__HI = {self._reg_to_var(operand_list[0])};"
        
        # FPU operations
        if mnemonic.startswith("add."):
            if len(operand_list) >= 3:
                return f"{self._fp_to_var(operand_list[0])} = {self._fp_to_var(operand_list[1])} + {self._fp_to_var(operand_list[2])};"
        
        if mnemonic.startswith("sub."):
            if len(operand_list) >= 3:
                return f"{self._fp_to_var(operand_list[0])} = {self._fp_to_var(operand_list[1])} - {self._fp_to_var(operand_list[2])};"
        
        if mnemonic.startswith("mul."):
            if len(operand_list) >= 3:
                return f"{self._fp_to_var(operand_list[0])} = {self._fp_to_var(operand_list[1])} * {self._fp_to_var(operand_list[2])};"
        
        if mnemonic.startswith("div."):
            if len(operand_list) >= 3:
                return f"{self._fp_to_var(operand_list[0])} = {self._fp_to_var(operand_list[1])} / {self._fp_to_var(operand_list[2])};"
        
        if mnemonic.startswith("mov."):
            if len(operand_list) >= 2:
                return f"{self._fp_to_var(operand_list[0])} = {self._fp_to_var(operand_list[1])};"
        
        if mnemonic.startswith("neg."):
            if len(operand_list) >= 2:
                return f"{self._fp_to_var(operand_list[0])} = -{self._fp_to_var(operand_list[1])};"
        
        if mnemonic.startswith("abs."):
            if len(operand_list) >= 2:
                return f"{self._fp_to_var(operand_list[0])} = fabsf({self._fp_to_var(operand_list[1])});"
        
        if mnemonic.startswith("sqrt."):
            if len(operand_list) >= 2:
                return f"{self._fp_to_var(operand_list[0])} = sqrtf({self._fp_to_var(operand_list[1])});"
        
        # FPU load/store
        if mnemonic == "lwc1":
            match = re.match(r'(\$f\d+),\s*(-?\d+)\((\$\w+)\)', ops)
            if match:
                dest, offset, base = match.groups()
                return f"{self._fp_to_var(dest)} = *(f32*)({self._reg_to_var(base)} + {offset});"
        
        if mnemonic == "swc1":
            match = re.match(r'(\$f\d+),\s*(-?\d+)\((\$\w+)\)', ops)
            if match:
                src, offset, base = match.groups()
                return f"*(f32*)({self._reg_to_var(base)} + {offset}) = {self._fp_to_var(src)};"
        
        if mnemonic == "ldc1":
            match = re.match(r'(\$f\d+),\s*(-?\d+)\((\$\w+)\)', ops)
            if match:
                dest, offset, base = match.groups()
                return f"{self._fp_to_var(dest)} = *(f64*)({self._reg_to_var(base)} + {offset});"
        
        if mnemonic == "sdc1":
            match = re.match(r'(\$f\d+),\s*(-?\d+)\((\$\w+)\)', ops)
            if match:
                src, offset, base = match.groups()
                return f"*(f64*)({self._reg_to_var(base)} + {offset}) = {self._fp_to_var(src)};"
        
        if mnemonic == "mtc1":
            if len(operand_list) >= 2:
                return f"{self._fp_to_var(operand_list[1])} = (f32){self._reg_to_var(operand_list[0])};"
        
        if mnemonic == "mfc1":
            if len(operand_list) >= 2:
                return f"{self._reg_to_var(operand_list[0])} = (s32){self._fp_to_var(operand_list[1])};"
        
        # Conversion operations
        if mnemonic.startswith("cvt."):
            if len(operand_list) >= 2:
                return f"{self._fp_to_var(operand_list[0])} = ({self._get_cvt_type(mnemonic)}){self._fp_to_var(operand_list[1])};"
        
        if mnemonic.startswith("trunc."):
            if len(operand_list) >= 2:
                return f"{self._fp_to_var(operand_list[0])} = (s32){self._fp_to_var(operand_list[1])};"
        
        # System instructions
        if mnemonic == "syscall":
            return "__syscall();"
        
        if mnemonic == "break":
            return "__break();"
        
        if mnemonic == "sync":
            return "__sync();  // Memory barrier"
        
        if mnemonic == "eret":
            return "__eret();  // Return from exception"
        
        # COP0 operations
        if mnemonic == "mfc0":
            if len(operand_list) >= 2:
                return f"{self._reg_to_var(operand_list[0])} = __mfc0({operand_list[1]});"
        
        if mnemonic == "mtc0":
            if len(operand_list) >= 2:
                return f"__mtc0({operand_list[1]}, {self._reg_to_var(operand_list[0])});"
        
        # Default: output as comment
        return f"// {mnemonic} {ops}"
    
    def _reg_to_var(self, reg: str) -> str:
        """Convert register name to variable name"""
        reg = reg.strip()
        
        # Special registers
        reg_map = {
            "$zero": "0",
            "$at": "at",
            "$v0": "v0", "$v1": "v1",
            "$a0": "a0", "$a1": "a1", "$a2": "a2", "$a3": "a3",
            "$t0": "t0", "$t1": "t1", "$t2": "t2", "$t3": "t3",
            "$t4": "t4", "$t5": "t5", "$t6": "t6", "$t7": "t7",
            "$s0": "s0", "$s1": "s1", "$s2": "s2", "$s3": "s3",
            "$s4": "s4", "$s5": "s5", "$s6": "s6", "$s7": "s7",
            "$t8": "t8", "$t9": "t9",
            "$k0": "k0", "$k1": "k1",
            "$gp": "gp",
            "$sp": "sp",
            "$fp": "fp",
            "$ra": "ra",
        }
        
        return reg_map.get(reg, reg.replace("$", ""))
    
    def _fp_to_var(self, reg: str) -> str:
        """Convert FP register to variable name"""
        reg = reg.strip()
        if reg.startswith("$f"):
            return f"f{reg[2:]}"
        return reg
    
    def _get_cvt_type(self, mnemonic: str) -> str:
        """Get C type from CVT instruction"""
        if ".s" in mnemonic:
            return "f32"
        elif ".d" in mnemonic:
            return "f64"
        elif ".w" in mnemonic:
            return "s32"
        elif ".l" in mnemonic:
            return "s64"
        return "f32"

# ═══════════════════════════════════════════════════════════════════════════════
# GUI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

class CatsDecompilerApp:
    """Main application class for Cat's Universal SM64 Decompiler"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Cat's Universal SM64 Decompiler 1.0")
        self.root.geometry("1600x900")
        self.root.minsize(1200, 700)
        
        # State
        self.rom: Optional[N64ROM] = None
        self.disasm: Optional[MIPSDisassembler] = None
        self.decompiler: Optional[MIPSDecompiler] = None
        self.current_theme = "dark"
        self.theme_mode = ThemeMode.DARK
        self.fonts = {}
        
        # Initialize
        self._setup_fonts()
        self._create_styles()
        self._create_ui()
        self._apply_theme()
        self._bind_events()
        
        # Configure icon (if available)
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass
    
    def _setup_fonts(self):
        """Setup application fonts"""
        self.fonts = {
            'ui': font.Font(family="Segoe UI", size=10),
            'ui_bold': font.Font(family="Segoe UI", size=10, weight="bold"),
            'code': font.Font(family="Consolas", size=11),
            'code_bold': font.Font(family="Consolas", size=11, weight="bold"),
            'title': font.Font(family="Segoe UI", size=12, weight="bold"),
            'small': font.Font(family="Segoe UI", size=9),
        }
    
    def _create_styles(self):
        """Create ttk styles"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
    
    def _update_styles(self):
        """Update ttk styles for current theme"""
        theme = THEMES[self.current_theme]
        
        # Treeview
        self.style.configure("Treeview",
            background=theme['bg_secondary'],
            foreground=theme['fg'],
            fieldbackground=theme['bg_secondary'],
            borderwidth=0,
            font=self.fonts['ui']
        )
        self.style.configure("Treeview.Heading",
            background=theme['bg_tertiary'],
            foreground=theme['fg'],
            borderwidth=0,
            font=self.fonts['ui_bold']
        )
        self.style.map("Treeview",
            background=[('selected', theme['tree_select'])],
            foreground=[('selected', theme['fg'])]
        )
        
        # Notebook (tabs)
        self.style.configure("TNotebook",
            background=theme['bg'],
            borderwidth=0
        )
        self.style.configure("TNotebook.Tab",
            background=theme['bg_tertiary'],
            foreground=theme['fg'],
            padding=[12, 4],
            font=self.fonts['ui']
        )
        self.style.map("TNotebook.Tab",
            background=[('selected', theme['bg_secondary'])],
            foreground=[('selected', theme['fg'])]
        )
        
        # Buttons
        self.style.configure("TButton",
            background=theme['bg_tertiary'],
            foreground=theme['fg'],
            borderwidth=1,
            focuscolor=theme['accent'],
            font=self.fonts['ui']
        )
        self.style.map("TButton",
            background=[('active', theme['accent_hover']), ('pressed', theme['accent'])]
        )
        
        # Accent button
        self.style.configure("Accent.TButton",
            background=theme['accent'],
            foreground="#ffffff",
            font=self.fonts['ui_bold']
        )
        self.style.map("Accent.TButton",
            background=[('active', theme['accent_hover'])]
        )
        
        # Scrollbar
        self.style.configure("Vertical.TScrollbar",
            background=theme['scrollbar_bg'],
            troughcolor=theme['bg_secondary'],
            borderwidth=0,
            arrowsize=12
        )
        self.style.configure("Horizontal.TScrollbar",
            background=theme['scrollbar_bg'],
            troughcolor=theme['bg_secondary'],
            borderwidth=0,
            arrowsize=12
        )
        
        # Entry
        self.style.configure("TEntry",
            fieldbackground=theme['bg_input'],
            foreground=theme['fg'],
            borderwidth=1,
            insertcolor=theme['fg']
        )
        
        # Frame
        self.style.configure("TFrame",
            background=theme['bg']
        )
        
        # Label
        self.style.configure("TLabel",
            background=theme['bg'],
            foreground=theme['fg'],
            font=self.fonts['ui']
        )
        
        # Panedwindow
        self.style.configure("TPanedwindow",
            background=theme['border']
        )
    
    def _create_ui(self):
        """Create the main UI"""
        theme = THEMES[self.current_theme]
        
        # Main container
        self.main_frame = tk.Frame(self.root, bg=theme['bg'])
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create menu bar
        self._create_menu()
        
        # Create toolbar
        self._create_toolbar()
        
        # Create main content area with panes
        self._create_content_area()
        
        # Create status bar
        self._create_status_bar()
    
    def _create_menu(self):
        """Create menu bar"""
        theme = THEMES[self.current_theme]
        
        self.menubar = tk.Menu(self.root, bg=theme['menu_bg'], fg=theme['menu_fg'],
                               activebackground=theme['accent'], activeforeground='white',
                               borderwidth=0, relief=tk.FLAT)
        
        # File menu
        file_menu = tk.Menu(self.menubar, tearoff=0, bg=theme['menu_bg'], 
                           fg=theme['menu_fg'], activebackground=theme['accent'],
                           activeforeground='white')
        file_menu.add_command(label="Open ROM...", command=self.open_rom, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Export Disassembly...", command=self.export_disassembly)
        file_menu.add_command(label="Export C Code...", command=self.export_c_code)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Alt+F4")
        self.menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(self.menubar, tearoff=0, bg=theme['menu_bg'],
                           fg=theme['menu_fg'], activebackground=theme['accent'],
                           activeforeground='white')
        
        # Theme submenu
        theme_menu = tk.Menu(view_menu, tearoff=0, bg=theme['menu_bg'],
                            fg=theme['menu_fg'], activebackground=theme['accent'],
                            activeforeground='white')
        self.theme_var = tk.StringVar(value="dark")
        theme_menu.add_radiobutton(label="Dark Mode", variable=self.theme_var, 
                                  value="dark", command=lambda: self.set_theme("dark"))
        theme_menu.add_radiobutton(label="Light Mode", variable=self.theme_var,
                                  value="light", command=lambda: self.set_theme("light"))
        theme_menu.add_separator()
        theme_menu.add_radiobutton(label="System", variable=self.theme_var,
                                  value="system", command=lambda: self.set_theme("system"))
        view_menu.add_cascade(label="Theme", menu=theme_menu)
        
        view_menu.add_separator()
        view_menu.add_command(label="Go to Address...", command=self.goto_address, accelerator="Ctrl+G")
        view_menu.add_command(label="Find...", command=self.find_text, accelerator="Ctrl+F")
        self.menubar.add_cascade(label="View", menu=view_menu)
        
        # Analysis menu
        analysis_menu = tk.Menu(self.menubar, tearoff=0, bg=theme['menu_bg'],
                               fg=theme['menu_fg'], activebackground=theme['accent'],
                               activeforeground='white')
        analysis_menu.add_command(label="Auto-detect Functions", command=self.auto_detect_functions)
        analysis_menu.add_command(label="Decompile Selection", command=self.decompile_selection)
        analysis_menu.add_separator()
        analysis_menu.add_command(label="Add Symbol...", command=self.add_symbol)
        analysis_menu.add_command(label="Load Symbols...", command=self.load_symbols)
        analysis_menu.add_command(label="Save Symbols...", command=self.save_symbols)
        self.menubar.add_cascade(label="Analysis", menu=analysis_menu)
        
        # Help menu
        help_menu = tk.Menu(self.menubar, tearoff=0, bg=theme['menu_bg'],
                           fg=theme['menu_fg'], activebackground=theme['accent'],
                           activeforeground='white')
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.show_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        self.menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=self.menubar)
    
    def _create_toolbar(self):
        """Create toolbar"""
        theme = THEMES[self.current_theme]
        
        self.toolbar = tk.Frame(self.main_frame, bg=theme['bg_tertiary'], height=40)
        self.toolbar.pack(fill=tk.X, padx=0, pady=0)
        self.toolbar.pack_propagate(False)
        
        # Toolbar buttons
        btn_frame = tk.Frame(self.toolbar, bg=theme['bg_tertiary'])
        btn_frame.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.btn_open = tk.Button(btn_frame, text="📂 Open ROM", command=self.open_rom,
                                  bg=theme['bg_tertiary'], fg=theme['fg'],
                                  relief=tk.FLAT, padx=10, pady=2,
                                  activebackground=theme['accent'], activeforeground='white',
                                  font=self.fonts['ui'])
        self.btn_open.pack(side=tk.LEFT, padx=2)
        
        self.btn_analyze = tk.Button(btn_frame, text="🔍 Analyze", command=self.auto_detect_functions,
                                     bg=theme['bg_tertiary'], fg=theme['fg'],
                                     relief=tk.FLAT, padx=10, pady=2,
                                     activebackground=theme['accent'], activeforeground='white',
                                     font=self.fonts['ui'], state=tk.DISABLED)
        self.btn_analyze.pack(side=tk.LEFT, padx=2)
        
        self.btn_decompile = tk.Button(btn_frame, text="⚙️ Decompile", command=self.decompile_selection,
                                       bg=theme['bg_tertiary'], fg=theme['fg'],
                                       relief=tk.FLAT, padx=10, pady=2,
                                       activebackground=theme['accent'], activeforeground='white',
                                       font=self.fonts['ui'], state=tk.DISABLED)
        self.btn_decompile.pack(side=tk.LEFT, padx=2)
        
        # Separator
        sep = tk.Frame(btn_frame, width=2, height=20, bg=theme['border'])
        sep.pack(side=tk.LEFT, padx=10)
        
        # Address entry
        tk.Label(btn_frame, text="Address:", bg=theme['bg_tertiary'], fg=theme['fg'],
                font=self.fonts['ui']).pack(side=tk.LEFT, padx=5)
        
        self.addr_entry = tk.Entry(btn_frame, width=12, bg=theme['bg_input'], fg=theme['fg'],
                                   insertbackground=theme['fg'], relief=tk.FLAT,
                                   font=self.fonts['code'])
        self.addr_entry.pack(side=tk.LEFT, padx=2)
        self.addr_entry.insert(0, "0x80000000")
        
        self.btn_goto = tk.Button(btn_frame, text="Go", command=self.goto_address,
                                  bg=theme['accent'], fg='white',
                                  relief=tk.FLAT, padx=10, pady=2,
                                  activebackground=theme['accent_hover'], activeforeground='white',
                                  font=self.fonts['ui'])
        self.btn_goto.pack(side=tk.LEFT, padx=2)
        
        # Theme toggle on right
        theme_frame = tk.Frame(self.toolbar, bg=theme['bg_tertiary'])
        theme_frame.pack(side=tk.RIGHT, padx=10, pady=5)
        
        self.theme_btn = tk.Button(theme_frame, text="🌙 Dark", command=self.toggle_theme,
                                   bg=theme['bg_tertiary'], fg=theme['fg'],
                                   relief=tk.FLAT, padx=10, pady=2,
                                   activebackground=theme['accent'], activeforeground='white',
                                   font=self.fonts['ui'])
        self.theme_btn.pack(side=tk.LEFT)
    
    def _create_content_area(self):
        """Create main content area with panes"""
        theme = THEMES[self.current_theme]
        
        # Main paned window (horizontal)
        self.h_paned = tk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL,
                                       bg=theme['border'], sashwidth=4,
                                       sashrelief=tk.FLAT)
        self.h_paned.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Left panel - Function/Symbol tree
        self._create_left_panel()
        
        # Center panel - Disassembly view
        self._create_center_panel()
        
        # Right panel - Decompiled C code
        self._create_right_panel()
    
    def _create_left_panel(self):
        """Create left panel with function tree"""
        theme = THEMES[self.current_theme]
        
        left_frame = tk.Frame(self.h_paned, bg=theme['bg_secondary'])
        self.h_paned.add(left_frame, minsize=200, width=280)
        
        # Header
        header = tk.Frame(left_frame, bg=theme['bg_tertiary'], height=30)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        tk.Label(header, text="Functions", bg=theme['bg_tertiary'], fg=theme['fg'],
                font=self.fonts['ui_bold']).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Search box
        search_frame = tk.Frame(left_frame, bg=theme['bg_secondary'])
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.func_search = tk.Entry(search_frame, bg=theme['bg_input'], fg=theme['fg'],
                                    insertbackground=theme['fg'], relief=tk.FLAT,
                                    font=self.fonts['ui'])
        self.func_search.pack(fill=tk.X, padx=2)
        self.func_search.insert(0, "Search functions...")
        self.func_search.bind('<FocusIn>', lambda e: self._clear_placeholder(e, "Search functions..."))
        self.func_search.bind('<FocusOut>', lambda e: self._restore_placeholder(e, "Search functions..."))
        self.func_search.bind('<KeyRelease>', self._filter_functions)
        
        # Treeview
        tree_frame = tk.Frame(left_frame, bg=theme['bg_secondary'])
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.func_tree = ttk.Treeview(tree_frame, show='tree headings', selectmode='browse')
        self.func_tree['columns'] = ('address', 'size')
        self.func_tree.heading('#0', text='Name')
        self.func_tree.heading('address', text='Address')
        self.func_tree.heading('size', text='Size')
        self.func_tree.column('#0', width=120)
        self.func_tree.column('address', width=80)
        self.func_tree.column('size', width=50)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.func_tree.yview)
        self.func_tree.configure(yscrollcommand=scrollbar.set)
        
        self.func_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.func_tree.bind('<<TreeviewSelect>>', self._on_function_select)
        self.func_tree.bind('<Double-1>', self._on_function_double_click)
    
    def _create_center_panel(self):
        """Create center panel with disassembly view"""
        theme = THEMES[self.current_theme]
        
        center_frame = tk.Frame(self.h_paned, bg=theme['bg'])
        self.h_paned.add(center_frame, minsize=400, width=600)
        
        # Notebook for tabs
        self.center_notebook = ttk.Notebook(center_frame)
        self.center_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Disassembly tab
        disasm_frame = tk.Frame(self.center_notebook, bg=theme['bg'])
        self.center_notebook.add(disasm_frame, text="Disassembly")
        
        # Create text widget with line numbers
        text_frame = tk.Frame(disasm_frame, bg=theme['bg'])
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        # Line numbers
        self.line_numbers = tk.Text(text_frame, width=12, bg=theme['line_number_bg'],
                                     fg=theme['line_number_fg'], relief=tk.FLAT,
                                     font=self.fonts['code'], state=tk.DISABLED,
                                     cursor="arrow")
        self.line_numbers.pack(side=tk.LEFT, fill=tk.Y)
        
        # Main text widget
        self.disasm_text = tk.Text(text_frame, wrap=tk.NONE, bg=theme['bg'],
                                    fg=theme['fg'], relief=tk.FLAT,
                                    font=self.fonts['code'],
                                    insertbackground=theme['fg'],
                                    selectbackground=theme['selection'],
                                    selectforeground=theme['fg'])
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, 
                                 command=self._sync_scroll)
        h_scroll = ttk.Scrollbar(disasm_frame, orient=tk.HORIZONTAL,
                                 command=self.disasm_text.xview)
        
        self.disasm_text.configure(yscrollcommand=v_scroll.set, 
                                   xscrollcommand=h_scroll.set)
        
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.disasm_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        h_scroll.pack(fill=tk.X)
        
        # Configure syntax highlighting tags
        self._configure_syntax_tags()
        
        # Hex dump tab
        hex_frame = tk.Frame(self.center_notebook, bg=theme['bg'])
        self.center_notebook.add(hex_frame, text="Hex Dump")
        
        self.hex_text = tk.Text(hex_frame, wrap=tk.NONE, bg=theme['bg'],
                                fg=theme['fg'], relief=tk.FLAT,
                                font=self.fonts['code'],
                                state=tk.DISABLED)
        hex_scroll = ttk.Scrollbar(hex_frame, orient=tk.VERTICAL, 
                                   command=self.hex_text.yview)
        self.hex_text.configure(yscrollcommand=hex_scroll.set)
        hex_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        
        # ROM Info tab
        info_frame = tk.Frame(self.center_notebook, bg=theme['bg'])
        self.center_notebook.add(info_frame, text="ROM Info")
        
        self.info_text = tk.Text(info_frame, wrap=tk.WORD, bg=theme['bg'],
                                 fg=theme['fg'], relief=tk.FLAT,
                                 font=self.fonts['code'],
                                 state=tk.DISABLED)
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _create_right_panel(self):
        """Create right panel with decompiled C code"""
        theme = THEMES[self.current_theme]
        
        right_frame = tk.Frame(self.h_paned, bg=theme['bg'])
        self.h_paned.add(right_frame, minsize=300, width=450)
        
        # Header
        header = tk.Frame(right_frame, bg=theme['bg_tertiary'], height=30)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        tk.Label(header, text="Decompiled Output", bg=theme['bg_tertiary'], fg=theme['fg'],
                font=self.fonts['ui_bold']).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Copy button
        self.btn_copy = tk.Button(header, text="📋 Copy", command=self.copy_decompiled,
                                  bg=theme['bg_tertiary'], fg=theme['fg'],
                                  relief=tk.FLAT, padx=8, pady=1,
                                  activebackground=theme['accent'], activeforeground='white',
                                  font=self.fonts['small'])
        self.btn_copy.pack(side=tk.RIGHT, padx=5)
        
        # Text widget
        text_frame = tk.Frame(right_frame, bg=theme['bg'])
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.decompile_text = tk.Text(text_frame, wrap=tk.NONE, bg=theme['bg'],
                                       fg=theme['fg'], relief=tk.FLAT,
                                       font=self.fonts['code'],
                                       insertbackground=theme['fg'],
                                       selectbackground=theme['selection'])
        
        v_scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL,
                                 command=self.decompile_text.yview)
        h_scroll = ttk.Scrollbar(right_frame, orient=tk.HORIZONTAL,
                                 command=self.decompile_text.xview)
        
        self.decompile_text.configure(yscrollcommand=v_scroll.set,
                                      xscrollcommand=h_scroll.set)
        
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.decompile_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        h_scroll.pack(fill=tk.X)
        
        # Configure C syntax highlighting
        self._configure_c_syntax_tags()
    
    def _create_status_bar(self):
        """Create status bar"""
        theme = THEMES[self.current_theme]
        
        self.status_bar = tk.Frame(self.main_frame, bg=theme['status_bg'], height=25)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_bar.pack_propagate(False)
        
        self.status_label = tk.Label(self.status_bar, text="Ready - No ROM loaded",
                                     bg=theme['status_bg'], fg=theme['status_fg'],
                                     font=self.fonts['small'])
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.progress_label = tk.Label(self.status_bar, text="",
                                       bg=theme['status_bg'], fg=theme['status_fg'],
                                       font=self.fonts['small'])
        self.progress_label.pack(side=tk.RIGHT, padx=10)
    
    def _configure_syntax_tags(self):
        """Configure syntax highlighting tags for disassembly"""
        theme = THEMES[self.current_theme]
        
        self.disasm_text.tag_configure('address', foreground=theme['address'])
        self.disasm_text.tag_configure('instruction', foreground=theme['instruction'])
        self.disasm_text.tag_configure('register', foreground=theme['register'])
        self.disasm_text.tag_configure('number', foreground=theme['number'])
        self.disasm_text.tag_configure('label', foreground=theme['label'], font=self.fonts['code_bold'])
        self.disasm_text.tag_configure('comment', foreground=theme['comment'])
        self.disasm_text.tag_configure('function', foreground=theme['function'], font=self.fonts['code_bold'])
        self.disasm_text.tag_configure('bytes', foreground=theme['fg_muted'])
    
    def _configure_c_syntax_tags(self):
        """Configure syntax highlighting tags for C code"""
        theme = THEMES[self.current_theme]
        
        self.decompile_text.tag_configure('keyword', foreground=theme['keyword'])
        self.decompile_text.tag_configure('type', foreground=theme['type'])
        self.decompile_text.tag_configure('string', foreground=theme['string'])
        self.decompile_text.tag_configure('number', foreground=theme['number'])
        self.decompile_text.tag_configure('comment', foreground=theme['comment'])
        self.decompile_text.tag_configure('function', foreground=theme['function'])
        self.decompile_text.tag_configure('variable', foreground=theme['variable'])
    
    def _apply_theme(self):
        """Apply current theme to all widgets"""
        theme = THEMES[self.current_theme]
        
        # Update ttk styles
        self._update_styles()
        
        # Update main frame
        self.main_frame.configure(bg=theme['bg'])
        
        # Update toolbar
        self.toolbar.configure(bg=theme['bg_tertiary'])
        for child in self.toolbar.winfo_children():
            self._apply_theme_to_widget(child, theme)
        
        # Update status bar
        self.status_bar.configure(bg=theme['status_bg'])
        self.status_label.configure(bg=theme['status_bg'], fg=theme['status_fg'])
        self.progress_label.configure(bg=theme['status_bg'], fg=theme['status_fg'])
        
        # Update paned window
        self.h_paned.configure(bg=theme['border'])
        
        # Update all frames
        for child in self.h_paned.winfo_children():
            self._apply_theme_to_frame(child, theme)
        
        # Update text widgets
        self.disasm_text.configure(bg=theme['bg'], fg=theme['fg'],
                                   selectbackground=theme['selection'])
        self.decompile_text.configure(bg=theme['bg'], fg=theme['fg'],
                                      selectbackground=theme['selection'])
        self.hex_text.configure(bg=theme['bg'], fg=theme['fg'])
        self.info_text.configure(bg=theme['bg'], fg=theme['fg'])
        self.line_numbers.configure(bg=theme['line_number_bg'], fg=theme['line_number_fg'])
        
        # Update syntax highlighting
        self._configure_syntax_tags()
        self._configure_c_syntax_tags()
        
        # Update theme button text
        if self.current_theme == "dark":
            self.theme_btn.configure(text="🌙 Dark")
        else:
            self.theme_btn.configure(text="☀️ Light")
        
        # Update menu colors
        self._update_menu_theme()
    
    def _apply_theme_to_widget(self, widget, theme):
        """Recursively apply theme to a widget"""
        try:
            if isinstance(widget, tk.Frame):
                widget.configure(bg=theme['bg_tertiary'])
            elif isinstance(widget, tk.Button):
                widget.configure(bg=theme['bg_tertiary'], fg=theme['fg'],
                               activebackground=theme['accent'], activeforeground='white')
            elif isinstance(widget, tk.Label):
                widget.configure(bg=theme['bg_tertiary'], fg=theme['fg'])
            elif isinstance(widget, tk.Entry):
                widget.configure(bg=theme['bg_input'], fg=theme['fg'],
                               insertbackground=theme['fg'])
        except:
            pass
        
        for child in widget.winfo_children():
            self._apply_theme_to_widget(child, theme)
    
    def _apply_theme_to_frame(self, widget, theme):
        """Apply theme to frame and children"""
        try:
            if isinstance(widget, tk.Frame):
                widget.configure(bg=theme['bg_secondary'])
        except:
            pass
        
        for child in widget.winfo_children():
            try:
                if isinstance(child, tk.Frame):
                    if 'header' in str(child).lower() or child.winfo_height() == 30:
                        child.configure(bg=theme['bg_tertiary'])
                    else:
                        child.configure(bg=theme['bg_secondary'])
                elif isinstance(child, tk.Label):
                    parent_bg = child.master.cget('bg')
                    child.configure(bg=parent_bg, fg=theme['fg'])
                elif isinstance(child, tk.Entry):
                    child.configure(bg=theme['bg_input'], fg=theme['fg'],
                                  insertbackground=theme['fg'])
                elif isinstance(child, tk.Button):
                    parent_bg = child.master.cget('bg')
                    child.configure(bg=parent_bg, fg=theme['fg'],
                                  activebackground=theme['accent'], activeforeground='white')
            except:
                pass
            
            self._apply_theme_to_frame(child, theme)
    
    def _update_menu_theme(self):
        """Update menu colors"""
        theme = THEMES[self.current_theme]
        
        self.menubar.configure(bg=theme['menu_bg'], fg=theme['menu_fg'],
                              activebackground=theme['accent'])
        
        for i in range(self.menubar.index('end') + 1):
            try:
                menu = self.menubar.nametowidget(self.menubar.entrycget(i, 'menu'))
                menu.configure(bg=theme['menu_bg'], fg=theme['menu_fg'],
                             activebackground=theme['accent'], activeforeground='white')
            except:
                pass
    
    def _bind_events(self):
        """Bind keyboard shortcuts and events"""
        self.root.bind('<Control-o>', lambda e: self.open_rom())
        self.root.bind('<Control-g>', lambda e: self.goto_address())
        self.root.bind('<Control-f>', lambda e: self.find_text())
        self.root.bind('<F5>', lambda e: self.auto_detect_functions())
        self.addr_entry.bind('<Return>', lambda e: self.goto_address())
    
    def _sync_scroll(self, *args):
        """Synchronize line numbers with main text"""
        self.disasm_text.yview(*args)
        self.line_numbers.yview(*args)
    
    def _clear_placeholder(self, event, placeholder):
        """Clear placeholder text on focus"""
        if event.widget.get() == placeholder:
            event.widget.delete(0, tk.END)
    
    def _restore_placeholder(self, event, placeholder):
        """Restore placeholder if empty"""
        if not event.widget.get():
            event.widget.insert(0, placeholder)
    
    def _filter_functions(self, event):
        """Filter function list based on search"""
        search = self.func_search.get().lower()
        if search == "search functions...":
            return
        
        # Clear and repopulate tree
        for item in self.func_tree.get_children():
            self.func_tree.delete(item)
        
        if not self.decompiler:
            return
        
        for addr, func in sorted(self.decompiler.functions.items()):
            if search in func.name.lower() or search in f"{addr:08x}":
                self.func_tree.insert('', 'end', text=func.name,
                                      values=(f"0x{addr:08X}", 
                                             f"{func.end_address - func.start_address}"))
    
    def _on_function_select(self, event):
        """Handle function selection in tree"""
        selection = self.func_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        addr_str = self.func_tree.item(item)['values'][0]
        
        try:
            addr = int(addr_str, 16)
            self._goto_address(addr)
        except:
            pass
    
    def _on_function_double_click(self, event):
        """Handle double-click on function to decompile"""
        selection = self.func_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        addr_str = self.func_tree.item(item)['values'][0]
        
        try:
            addr = int(addr_str, 16)
            if addr in self.decompiler.functions:
                func = self.decompiler.functions[addr]
                self._display_decompiled(func)
        except:
            pass
    
    def set_theme(self, theme: str):
        """Set the current theme"""
        if theme == "system":
            # Detect system theme (simplified - defaults to dark on failure)
            self.current_theme = "dark"
            self.theme_mode = ThemeMode.SYSTEM
        else:
            self.current_theme = theme
            self.theme_mode = ThemeMode.DARK if theme == "dark" else ThemeMode.LIGHT
        
        self._apply_theme()
    
    def toggle_theme(self):
        """Toggle between dark and light themes"""
        if self.current_theme == "dark":
            self.set_theme("light")
            self.theme_var.set("light")
        else:
            self.set_theme("dark")
            self.theme_var.set("dark")
    
    def open_rom(self):
        """Open an N64 ROM file"""
        filetypes = [
            ("N64 ROM files", "*.z64 *.n64 *.v64 *.rom"),
            ("All files", "*.*")
        ]
        
        filepath = filedialog.askopenfilename(
            title="Open N64 ROM",
            filetypes=filetypes
        )
        
        if not filepath:
            return
        
        try:
            self.status_label.configure(text=f"Loading ROM: {os.path.basename(filepath)}...")
            self.root.update()
            
            self.rom = N64ROM()
            self.rom.load(filepath)
            
            self.disasm = MIPSDisassembler(self.rom)
            self.decompiler = MIPSDecompiler(self.disasm)
            
            # Enable toolbar buttons
            self.btn_analyze.configure(state=tk.NORMAL)
            self.btn_decompile.configure(state=tk.NORMAL)
            
            # Display ROM info
            self._display_rom_info()
            
            # Disassemble from entry point
            entry = self.rom.header.program_counter
            self._disassemble_at(entry, 0x1000)
            
            self.status_label.configure(
                text=f"Loaded: {self.rom.header.name} - {os.path.basename(filepath)} ({self.rom.format.upper()})"
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load ROM:\n{str(e)}")
            self.status_label.configure(text="Failed to load ROM")
    
    def _display_rom_info(self):
        """Display ROM information"""
        self.info_text.configure(state=tk.NORMAL)
        self.info_text.delete('1.0', tk.END)
        
        info = f"""╔══════════════════════════════════════════════════════════════════╗
║                        ROM INFORMATION                           ║
╚══════════════════════════════════════════════════════════════════╝

File:             {os.path.basename(self.rom.filepath)}
Format:           {self.rom.format.upper()} ({"Big-endian" if self.rom.format == 'z64' else "Byte-swapped" if self.rom.format == 'n64' else "Little-endian"})
Size:             {len(self.rom.data):,} bytes ({len(self.rom.data) // (1024*1024):.1f} MB)

╔══════════════════════════════════════════════════════════════════╗
║                        HEADER DATA                               ║
╚══════════════════════════════════════════════════════════════════╝

Name:             {self.rom.header.name}
Cartridge ID:     {self.rom.header.cartridge_id}
Country:          {self.rom.get_country_name()} ({self.rom.header.country_code})
Version:          1.{self.rom.header.version}

Entry Point:      0x{self.rom.header.program_counter:08X}
Release Address:  0x{self.rom.header.release_address:08X}
Clock Rate:       {self.rom.header.clock_rate:,} Hz

CRC1:             0x{self.rom.header.crc1:08X}
CRC2:             0x{self.rom.header.crc2:08X}

PI Settings:      0x{self.rom.header.pi_settings:08X}
Media Format:     0x{self.rom.header.media_format:08X}

╔══════════════════════════════════════════════════════════════════╗
║                        CHECKSUMS                                 ║
╚══════════════════════════════════════════════════════════════════╝

MD5:              {hashlib.md5(self.rom.data).hexdigest()}
SHA1:             {hashlib.sha1(self.rom.data).hexdigest()}
"""
        
        self.info_text.insert('1.0', info)
        self.info_text.configure(state=tk.DISABLED)
    
    def _disassemble_at(self, address: int, size: int = 0x400):
        """Disassemble code at address"""
        if not self.disasm:
            return
        
        self.disasm_text.configure(state=tk.NORMAL)
        self.disasm_text.delete('1.0', tk.END)
        self.line_numbers.configure(state=tk.NORMAL)
        self.line_numbers.delete('1.0', tk.END)
        
        # Disassemble range
        end = min(address + size, 0x80000000 + len(self.rom.data))
        instructions = self.disasm.disassemble_range(address, end)
        
        line_num = 1
        for inst in instructions:
            # Address
            addr_str = f"0x{inst.address:08X}"
            
            # Raw bytes
            bytes_str = f"{inst.raw:08X}"
            
            # Label
            if inst.label:
                self.disasm_text.insert(tk.END, f"\n{inst.label}:\n", 'label')
                self.line_numbers.insert(tk.END, f"\n\n")
                line_num += 2
            
            # Line: address bytes instruction operands ; comment
            self.disasm_text.insert(tk.END, f"{addr_str}  ", 'address')
            self.disasm_text.insert(tk.END, f"{bytes_str}  ", 'bytes')
            self.disasm_text.insert(tk.END, f"{inst.mnemonic:8s}", 'instruction')
            
            # Colorize operands
            self._insert_colored_operands(inst.operands)
            
            if inst.comment:
                self.disasm_text.insert(tk.END, f"  ; {inst.comment}", 'comment')
            
            self.disasm_text.insert(tk.END, "\n")
            self.line_numbers.insert(tk.END, f"{line_num:6d}\n")
            line_num += 1
        
        self.disasm_text.configure(state=tk.DISABLED)
        self.line_numbers.configure(state=tk.DISABLED)
        
        # Update hex dump
        self._update_hex_dump(address, size)
    
    def _insert_colored_operands(self, operands: str):
        """Insert operands with syntax highlighting"""
        if not operands:
            return
        
        # Simple tokenization
        tokens = re.split(r'(\$\w+|0x[0-9A-Fa-f]+|-?\d+|\(|\)|,)', operands)
        
        for token in tokens:
            if not token:
                continue
            elif token.startswith('$'):
                self.disasm_text.insert(tk.END, token, 'register')
            elif token.startswith('0x') or re.match(r'^-?\d+$', token):
                self.disasm_text.insert(tk.END, token, 'number')
            else:
                self.disasm_text.insert(tk.END, token)
    
    def _update_hex_dump(self, address: int, size: int):
        """Update hex dump view"""
        self.hex_text.configure(state=tk.NORMAL)
        self.hex_text.delete('1.0', tk.END)
        
        offset = address & 0x00FFFFFF
        end_offset = min(offset + size, len(self.rom.data))
        
        addr = address
        for i in range(offset, end_offset, 16):
            # Address
            line = f"0x{addr:08X}  "
            
            # Hex bytes
            hex_part = ""
            ascii_part = ""
            for j in range(16):
                if i + j < end_offset:
                    byte = self.rom.data[i + j]
                    hex_part += f"{byte:02X} "
                    ascii_part += chr(byte) if 32 <= byte < 127 else "."
                else:
                    hex_part += "   "
                    ascii_part += " "
                
                if j == 7:
                    hex_part += " "
            
            line += hex_part + " |" + ascii_part + "|\n"
            self.hex_text.insert(tk.END, line)
            addr += 16
        
        self.hex_text.configure(state=tk.DISABLED)
    
    def _goto_address(self, address: int):
        """Go to a specific address"""
        if not self.rom:
            return
        
        # Validate address
        if address < 0x80000000:
            address |= 0x80000000
        
        offset = address & 0x00FFFFFF
        if offset >= len(self.rom.data):
            messagebox.showwarning("Warning", "Address out of ROM range")
            return
        
        self._disassemble_at(address, 0x1000)
        self.addr_entry.delete(0, tk.END)
        self.addr_entry.insert(0, f"0x{address:08X}")
    
    def goto_address(self):
        """Go to address from entry field"""
        addr_str = self.addr_entry.get().strip()
        
        try:
            if addr_str.startswith("0x") or addr_str.startswith("0X"):
                address = int(addr_str, 16)
            else:
                address = int(addr_str)
            
            self._goto_address(address)
        except:
            messagebox.showwarning("Warning", "Invalid address format")
    
    def auto_detect_functions(self):
        """Auto-detect functions in ROM"""
        if not self.decompiler:
            return
        
        self.status_label.configure(text="Analyzing ROM... Detecting functions...")
        self.root.update()
        
        # Clear function tree
        for item in self.func_tree.get_children():
            self.func_tree.delete(item)
        
        # Detect functions from entry point
        entry = self.rom.header.program_counter
        end = 0x80000000 + len(self.rom.data)
        
        # Limit analysis range for performance
        analysis_end = min(entry + 0x100000, end)  # Analyze 1MB max
        
        functions = self.decompiler.detect_functions(entry, analysis_end)
        
        # Add to tree
        for func in sorted(functions, key=lambda f: f.start_address):
            self.func_tree.insert('', 'end', text=func.name,
                                  values=(f"0x{func.start_address:08X}",
                                         f"{func.end_address - func.start_address}"))
        
        self.status_label.configure(text=f"Found {len(functions)} functions")
    
    def decompile_selection(self):
        """Decompile selected function"""
        selection = self.func_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a function to decompile")
            return
        
        item = selection[0]
        addr_str = self.func_tree.item(item)['values'][0]
        
        try:
            addr = int(addr_str, 16)
            if addr in self.decompiler.functions:
                func = self.decompiler.functions[addr]
                self._display_decompiled(func)
        except Exception as e:
            messagebox.showerror("Error", f"Decompilation failed:\n{str(e)}")
    
    def _display_decompiled(self, func: Function):
        """Display decompiled C code"""
        self.status_label.configure(text=f"Decompiling {func.name}...")
        self.root.update()
        
        try:
            c_code = self.decompiler.decompile_function(func)
            
            self.decompile_text.configure(state=tk.NORMAL)
            self.decompile_text.delete('1.0', tk.END)
            self.decompile_text.insert('1.0', c_code)
            
            # Apply C syntax highlighting
            self._highlight_c_code()
            
            self.decompile_text.configure(state=tk.DISABLED)
            self.status_label.configure(text=f"Decompiled: {func.name}")
        except Exception as e:
            messagebox.showerror("Error", f"Decompilation failed:\n{str(e)}")
    
    def _highlight_c_code(self):
        """Apply syntax highlighting to C code"""
        theme = THEMES[self.current_theme]
        
        # C keywords
        keywords = ['if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default',
                   'break', 'continue', 'return', 'goto', 'sizeof', 'typedef',
                   'struct', 'union', 'enum', 'const', 'static', 'extern', 'volatile']
        
        # C types
        types = ['void', 'int', 'char', 'short', 'long', 'float', 'double',
                's8', 's16', 's32', 's64', 'u8', 'u16', 'u32', 'u64',
                'f32', 'f64', 'bool']
        
        content = self.decompile_text.get('1.0', tk.END)
        
        # Highlight keywords
        for keyword in keywords:
            self._highlight_pattern(f'\\b{keyword}\\b', 'keyword')
        
        # Highlight types
        for type_name in types:
            self._highlight_pattern(f'\\b{type_name}\\b', 'type')
        
        # Highlight comments
        self._highlight_pattern(r'//.*$', 'comment', multiline=True)
        
        # Highlight numbers
        self._highlight_pattern(r'\b0x[0-9A-Fa-f]+\b', 'number')
        self._highlight_pattern(r'\b\d+\b', 'number')
        
        # Highlight function names
        self._highlight_pattern(r'\b\w+(?=\s*\()', 'function')
    
    def _highlight_pattern(self, pattern: str, tag: str, multiline: bool = False):
        """Highlight all occurrences of a pattern"""
        content = self.decompile_text.get('1.0', tk.END)
        flags = re.MULTILINE if multiline else 0
        
        for match in re.finditer(pattern, content, flags):
            start_idx = f"1.0+{match.start()}c"
            end_idx = f"1.0+{match.end()}c"
            self.decompile_text.tag_add(tag, start_idx, end_idx)
    
    def copy_decompiled(self):
        """Copy decompiled code to clipboard"""
        content = self.decompile_text.get('1.0', tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.status_label.configure(text="Copied to clipboard")
    
    def export_disassembly(self):
        """Export disassembly to file"""
        if not self.rom:
            messagebox.showwarning("Warning", "No ROM loaded")
            return
        
        filepath = filedialog.asksaveasfilename(
            title="Export Disassembly",
            defaultextension=".asm",
            filetypes=[("Assembly files", "*.asm"), ("Text files", "*.txt")]
        )
        
        if filepath:
            content = self.disasm_text.get('1.0', tk.END)
            with open(filepath, 'w') as f:
                f.write(content)
            self.status_label.configure(text=f"Exported to {os.path.basename(filepath)}")
    
    def export_c_code(self):
        """Export decompiled C code to file"""
        if not self.decompiler or not self.decompiler.functions:
            messagebox.showwarning("Warning", "No functions to export")
            return
        
        filepath = filedialog.asksaveasfilename(
            title="Export C Code",
            defaultextension=".c",
            filetypes=[("C files", "*.c"), ("Header files", "*.h"), ("Text files", "*.txt")]
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write("/* Decompiled by Cat's Universal SM64 Decompiler 1.0 */\n")
                f.write(f"/* Source ROM: {os.path.basename(self.rom.filepath)} */\n\n")
                
                f.write("#include <types.h>\n\n")
                
                for addr, func in sorted(self.decompiler.functions.items()):
                    try:
                        c_code = self.decompiler.decompile_function(func)
                        f.write(c_code)
                        f.write("\n\n")
                    except:
                        f.write(f"/* Failed to decompile {func.name} at 0x{addr:08X} */\n\n")
            
            self.status_label.configure(text=f"Exported to {os.path.basename(filepath)}")
    
    def find_text(self):
        """Open find dialog"""
        # Simple find dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Find")
        dialog.geometry("300x80")
        dialog.transient(self.root)
        
        theme = THEMES[self.current_theme]
        dialog.configure(bg=theme['bg'])
        
        frame = tk.Frame(dialog, bg=theme['bg'])
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(frame, text="Find:", bg=theme['bg'], fg=theme['fg']).pack(side=tk.LEFT)
        
        entry = tk.Entry(frame, width=25, bg=theme['bg_input'], fg=theme['fg'])
        entry.pack(side=tk.LEFT, padx=5)
        entry.focus_set()
        
        def do_find():
            text = entry.get()
            if text:
                # Search in disassembly
                idx = self.disasm_text.search(text, '1.0', tk.END)
                if idx:
                    self.disasm_text.see(idx)
                    self.disasm_text.tag_remove('found', '1.0', tk.END)
                    end_idx = f"{idx}+{len(text)}c"
                    self.disasm_text.tag_add('found', idx, end_idx)
                    self.disasm_text.tag_configure('found', background=theme['selection'])
        
        tk.Button(frame, text="Find", command=do_find,
                 bg=theme['accent'], fg='white').pack(side=tk.LEFT, padx=5)
        
        entry.bind('<Return>', lambda e: do_find())
    
    def add_symbol(self):
        """Add a symbol/label"""
        if not self.disasm:
            messagebox.showwarning("Warning", "No ROM loaded")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Symbol")
        dialog.geometry("300x120")
        dialog.transient(self.root)
        
        theme = THEMES[self.current_theme]
        dialog.configure(bg=theme['bg'])
        
        frame = tk.Frame(dialog, bg=theme['bg'])
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(frame, text="Address:", bg=theme['bg'], fg=theme['fg']).grid(row=0, column=0, sticky='w')
        addr_entry = tk.Entry(frame, bg=theme['bg_input'], fg=theme['fg'])
        addr_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Name:", bg=theme['bg'], fg=theme['fg']).grid(row=1, column=0, sticky='w')
        name_entry = tk.Entry(frame, bg=theme['bg_input'], fg=theme['fg'])
        name_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def add():
            try:
                addr = int(addr_entry.get(), 16) if addr_entry.get().startswith('0x') else int(addr_entry.get())
                name = name_entry.get().strip()
                if name:
                    self.disasm.add_symbol(addr, name, "label")
                    dialog.destroy()
                    self.status_label.configure(text=f"Added symbol: {name} @ 0x{addr:08X}")
            except:
                messagebox.showwarning("Warning", "Invalid input")
        
        tk.Button(frame, text="Add", command=add, bg=theme['accent'], fg='white').grid(row=2, column=1, pady=10)
    
    def load_symbols(self):
        """Load symbols from file"""
        filepath = filedialog.askopenfilename(
            title="Load Symbols",
            filetypes=[("Symbol files", "*.sym *.json"), ("All files", "*.*")]
        )
        
        if filepath and self.disasm:
            try:
                with open(filepath, 'r') as f:
                    if filepath.endswith('.json'):
                        data = json.load(f)
                        for sym in data.get('symbols', []):
                            self.disasm.add_symbol(sym['address'], sym['name'], sym.get('type', 'label'))
                    else:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                addr = int(parts[0], 16)
                                name = parts[1]
                                self.disasm.add_symbol(addr, name)
                
                self.status_label.configure(text=f"Loaded symbols from {os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load symbols:\n{str(e)}")
    
    def save_symbols(self):
        """Save symbols to file"""
        if not self.disasm or not self.disasm.symbols:
            messagebox.showwarning("Warning", "No symbols to save")
            return
        
        filepath = filedialog.asksaveasfilename(
            title="Save Symbols",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Symbol files", "*.sym")]
        )
        
        if filepath:
            try:
                symbols = [
                    {'address': sym.address, 'name': sym.name, 'type': sym.sym_type, 'size': sym.size}
                    for sym in self.disasm.symbols.values()
                ]
                
                with open(filepath, 'w') as f:
                    json.dump({'symbols': symbols}, f, indent=2)
                
                self.status_label.configure(text=f"Saved symbols to {os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save symbols:\n{str(e)}")
    
    def show_docs(self):
        """Show documentation"""
        messagebox.showinfo("Documentation",
                           "Cat's Universal SM64 Decompiler 1.0\n\n"
                           "A Ghidra-like N64 ROM decompiler.\n\n"
                           "Features:\n"
                           "• Load z64, n64, v64 ROM formats\n"
                           "• MIPS R4300 disassembly\n"
                           "• Function detection\n"
                           "• Decompilation to C code\n"
                           "• Symbol management\n"
                           "• Dark/Light themes\n\n"
                           "Visit: https://github.com/flames-co")
    
    def show_shortcuts(self):
        """Show keyboard shortcuts"""
        messagebox.showinfo("Keyboard Shortcuts",
                           "Ctrl+O  - Open ROM\n"
                           "Ctrl+G  - Go to address\n"
                           "Ctrl+F  - Find\n"
                           "F5      - Analyze/Detect functions\n\n"
                           "Double-click function to decompile")
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About",
                           "╔═══════════════════════════════════════╗\n"
                           "║  Cat's Universal SM64 Decompiler 1.0  ║\n"
                           "╚═══════════════════════════════════════╝\n\n"
                           "A Ghidra-like N64 ROM decompiler with\n"
                           "Visual Studio-style interface.\n\n"
                           "© 2025 Flames Co. / Team Flames\n\n"
                           "Built with Python & Tkinter")
    
    def run(self):
        """Run the application"""
        self.root.mainloop()


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = CatsDecompilerApp()
    app.run()
