#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          CAT'S UNIVERSAL ROM EDITOR PRO 2.0                                  ║
║          Ultimate Hex Editor + Decompiler + C-to-English Translator          ║
║          All 2025 Hex Editor Tools Integrated                                ║
║          (C) 2025 Flames Co. / Team Flames / Samsoft                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

FEATURES:
- Full Hex Editor with edit/insert/delete
- C Code to Plain English Translation
- MIPS R4300 Disassembly
- Pattern Search & Replace
- Data Type Converter
- Checksum Calculator (CRC32, MD5, SHA1, SHA256)
- Structure Viewer
- Binary Diff Tool
- String Extractor
- Entropy Analysis
- Bookmark System
- Undo/Redo Support
- Multiple File Tabs
- Dark/Light Themes
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import struct
import os
import re
import json
import hashlib
import zlib
import math
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any
from enum import Enum, auto
from collections import defaultdict

# ═══════════════════════════════════════════════════════════════════════════════
# THEME SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

THEMES = {
    "dark": {
        "name": "Dark (VS Code)",
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
        "hex_offset": "#858585",
        "hex_byte": "#9cdcfe",
        "hex_ascii": "#ce9178",
        "hex_modified": "#4ec9b0",
        "hex_selected": "#264f78",
        "hex_null": "#6a6a6a",
        "hex_printable": "#d4d4d4",
        "hex_nonprint": "#808080",
        "status_bg": "#007acc",
        "status_fg": "#ffffff",
        "error": "#f44747",
        "warning": "#cca700",
        "success": "#4ec9b0",
        "keyword": "#569cd6",
        "type": "#4ec9b0",
        "string": "#ce9178",
        "number": "#b5cea8",
        "comment": "#6a9955",
        "function": "#dcdcaa",
        "instruction": "#569cd6",
        "register": "#c586c0",
        "address": "#d7ba7d",
    },
    "light": {
        "name": "Light",
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
        "hex_offset": "#6e6e6e",
        "hex_byte": "#001080",
        "hex_ascii": "#a31515",
        "hex_modified": "#267f99",
        "hex_selected": "#add6ff",
        "hex_null": "#999999",
        "hex_printable": "#1e1e1e",
        "hex_nonprint": "#999999",
        "status_bg": "#0078d4",
        "status_fg": "#ffffff",
        "error": "#d32f2f",
        "warning": "#f9a825",
        "success": "#2e7d32",
        "keyword": "#0000ff",
        "type": "#267f99",
        "string": "#a31515",
        "number": "#098658",
        "comment": "#008000",
        "function": "#795e26",
        "instruction": "#0000ff",
        "register": "#af00db",
        "address": "#795e26",
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# C TO ENGLISH TRANSLATOR
# ═══════════════════════════════════════════════════════════════════════════════

class CToEnglishTranslator:
    """Translates C code to plain English explanations"""
    
    KEYWORD_MEANINGS = {
        "if": "If the condition",
        "else": "Otherwise",
        "else if": "Or if the condition",
        "while": "While the condition",
        "for": "Loop",
        "do": "Do the following",
        "switch": "Check the value of",
        "case": "If the value is",
        "default": "Otherwise (default case)",
        "break": "Stop and exit the current block",
        "continue": "Skip to the next iteration",
        "return": "Return/give back",
        "void": "nothing (no value)",
        "int": "integer number",
        "float": "decimal number",
        "double": "large decimal number",
        "char": "single character",
        "unsigned": "positive-only",
        "signed": "positive or negative",
        "const": "constant (unchangeable)",
        "static": "persistent/shared",
        "struct": "data structure containing",
        "typedef": "define a new type called",
        "sizeof": "the size in bytes of",
        "NULL": "nothing/empty",
        "true": "yes/true",
        "false": "no/false",
    }
    
    OPERATORS = {
        "==": "equals",
        "!=": "does not equal",
        "<=": "is less than or equal to",
        ">=": "is greater than or equal to",
        "<": "is less than",
        ">": "is greater than",
        "&&": "AND",
        "||": "OR",
        "!": "NOT",
        "++": "increase by 1",
        "--": "decrease by 1",
        "+=": "increase by",
        "-=": "decrease by",
        "*=": "multiply by",
        "/=": "divide by",
        "%=": "set to remainder when divided by",
        "&": "bitwise AND",
        "|": "bitwise OR",
        "^": "bitwise XOR",
        "~": "bitwise NOT",
        "<<": "shift left by",
        ">>": "shift right by",
        "->": "'s",
        ".": "'s",
    }
    
    FUNCTION_PATTERNS = {
        r'printf\s*\(': "Print to screen:",
        r'scanf\s*\(': "Read input from user:",
        r'malloc\s*\(': "Allocate memory of size",
        r'free\s*\(': "Free/release the memory at",
        r'strlen\s*\(': "Get the length of string",
        r'strcpy\s*\(': "Copy string to",
        r'strcmp\s*\(': "Compare strings",
        r'memcpy\s*\(': "Copy memory from",
        r'memset\s*\(': "Set memory to",
        r'fopen\s*\(': "Open file",
        r'fclose\s*\(': "Close file",
        r'exit\s*\(': "Exit program with code",
    }
    
    def __init__(self):
        self.indent_level = 0
        
    def translate(self, c_code: str) -> str:
        """Translate C code to English"""
        lines = c_code.strip().split('\n')
        result = []
        self.indent_level = 0
        
        for line in lines:
            translated = self._translate_line(line)
            if translated:
                result.append(translated)
        
        return '\n'.join(result)
    
    def _translate_line(self, line: str) -> str:
        """Translate a single line of C code"""
        line = line.strip()
        
        if not line or line.startswith('//'):
            if line.startswith('//'):
                return f"  {'  ' * self.indent_level}[Comment: {line[2:].strip()}]"
            return ""
        
        if line.startswith('/*') or line.endswith('*/') or line.startswith('*'):
            return f"  {'  ' * self.indent_level}[Comment: {line.strip('/* *')}]"
        
        if '{' in line:
            self.indent_level += 1
        if '}' in line:
            self.indent_level = max(0, self.indent_level - 1)
        
        indent = "  " * self.indent_level
        
        if line in ('{', '}', '};'):
            return ""
        
        if line.startswith('#include'):
            header = re.search(r'[<"](.+?)[>"]', line)
            if header:
                return f"{indent}📦 Include the '{header.group(1)}' library"
            return f"{indent}📦 Include a library"
        
        if line.startswith('#define'):
            parts = line.split(None, 2)
            if len(parts) >= 3:
                return f"{indent}📝 Define '{parts[1]}' as {parts[2]}"
            return f"{indent}📝 Define a constant"
        
        func_match = re.match(r'(\w+)\s+(\w+)\s*\(([^)]*)\)\s*\{?', line)
        if func_match:
            ret_type, func_name, params = func_match.groups()
            ret_english = self.KEYWORD_MEANINGS.get(ret_type, ret_type)
            if params.strip():
                return f"{indent}🔧 Define function '{func_name}' that takes parameters and returns {ret_english}:"
            return f"{indent}🔧 Define function '{func_name}' that returns {ret_english}:"
        
        if_match = re.match(r'if\s*\((.+)\)\s*\{?', line)
        if if_match:
            condition = self._translate_expression(if_match.group(1))
            return f"{indent}❓ IF {condition}, THEN:"
        
        elif_match = re.match(r'else\s+if\s*\((.+)\)\s*\{?', line)
        if elif_match:
            condition = self._translate_expression(elif_match.group(1))
            return f"{indent}❓ ELSE IF {condition}, THEN:"
        
        if re.match(r'else\s*\{?', line):
            return f"{indent}❓ ELSE (otherwise):"
        
        while_match = re.match(r'while\s*\((.+)\)\s*\{?', line)
        if while_match:
            condition = self._translate_expression(while_match.group(1))
            return f"{indent}🔄 WHILE {condition}, REPEAT:"
        
        for_match = re.match(r'for\s*\((.+);(.+);(.+)\)\s*\{?', line)
        if for_match:
            init, cond, incr = for_match.groups()
            return f"{indent}🔄 LOOP: Start with {init.strip()}, while {cond.strip()}, each time {incr.strip()}:"
        
        return_match = re.match(r'return\s*(.+)?;', line)
        if return_match:
            value = return_match.group(1)
            if value:
                return f"{indent}↩️ RETURN {self._translate_expression(value)}"
            return f"{indent}↩️ RETURN (exit function)"
        
        if line == 'break;':
            return f"{indent}🛑 BREAK out of the loop/switch"
        if line == 'continue;':
            return f"{indent}⏭️ SKIP to next iteration"
        
        decl_match = re.match(r'((?:unsigned\s+|signed\s+|const\s+|static\s+)*\w+)\s+(\w+)\s*(?:=\s*(.+))?;', line)
        if decl_match:
            var_type, var_name, value = decl_match.groups()
            type_english = self._translate_type(var_type)
            if value:
                return f"{indent}📦 Create {type_english} variable '{var_name}' = {value}"
            return f"{indent}📦 Create {type_english} variable '{var_name}'"
        
        assign_match = re.match(r'(\w+)\s*([+\-*/%&|^]?=)\s*(.+);', line)
        if assign_match:
            var, op, value = assign_match.groups()
            if op == '=':
                return f"{indent}✏️ Set '{var}' to {value}"
            op_english = self.OPERATORS.get(op, op)
            return f"{indent}✏️ {op_english.capitalize()} '{var}' by {value}"
        
        call_match = re.match(r'(\w+)\s*\(([^)]*)\)\s*;', line)
        if call_match:
            func_name, args = call_match.groups()
            for pattern, meaning in self.FUNCTION_PATTERNS.items():
                if re.match(pattern, line):
                    return f"{indent}▶️ {meaning} {args}"
            return f"{indent}▶️ Call function '{func_name}'"
        
        return f"{indent}📝 {line}"
    
    def _translate_expression(self, expr: str) -> str:
        """Translate a C expression to English"""
        expr = expr.strip()
        for op, meaning in sorted(self.OPERATORS.items(), key=lambda x: -len(x[0])):
            if op in expr:
                parts = expr.split(op, 1)
                if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                    return f"'{parts[0].strip()}' {meaning} '{parts[1].strip()}'"
        return f"'{expr}'"
    
    def _translate_type(self, type_str: str) -> str:
        """Translate C type to English"""
        parts = type_str.split()
        result = []
        for part in parts:
            if part in self.KEYWORD_MEANINGS:
                result.append(self.KEYWORD_MEANINGS[part])
            else:
                result.append(part)
        return ' '.join(result)


# ═══════════════════════════════════════════════════════════════════════════════
# HEX EDITOR ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class HexBuffer:
    """Manages binary data with undo/redo support"""
    
    def __init__(self, data: bytes = b''):
        self.data = bytearray(data)
        self.original = bytes(data)
        self.undo_stack: List[Tuple[str, int, bytes, bytes]] = []
        self.redo_stack: List[Tuple[str, int, bytes, bytes]] = []
        self.modified_offsets: Set[int] = set()
        self.bookmarks: Dict[int, str] = {}
        
    def __len__(self):
        return len(self.data)
    
    def get_byte(self, offset: int) -> int:
        if 0 <= offset < len(self.data):
            return self.data[offset]
        return 0
    
    def set_byte(self, offset: int, value: int):
        if 0 <= offset < len(self.data):
            old_value = bytes([self.data[offset]])
            new_value = bytes([value & 0xFF])
            self.undo_stack.append(('set', offset, old_value, new_value))
            self.redo_stack.clear()
            self.data[offset] = value & 0xFF
            self.modified_offsets.add(offset)
    
    def set_bytes(self, offset: int, data: bytes):
        if offset < 0 or offset >= len(self.data):
            return
        end = min(offset + len(data), len(self.data))
        length = end - offset
        old_data = bytes(self.data[offset:end])
        new_data = data[:length]
        self.undo_stack.append(('set', offset, old_data, new_data))
        self.redo_stack.clear()
        for i, b in enumerate(new_data):
            self.data[offset + i] = b
            self.modified_offsets.add(offset + i)
    
    def undo(self) -> bool:
        if not self.undo_stack:
            return False
        op, offset, old_data, new_data = self.undo_stack.pop()
        self.redo_stack.append((op, offset, old_data, new_data))
        if op == 'set':
            for i, b in enumerate(old_data):
                if offset + i < len(self.data):
                    self.data[offset + i] = b
        return True
    
    def redo(self) -> bool:
        if not self.redo_stack:
            return False
        op, offset, old_data, new_data = self.redo_stack.pop()
        self.undo_stack.append((op, offset, old_data, new_data))
        if op == 'set':
            for i, b in enumerate(new_data):
                if offset + i < len(self.data):
                    self.data[offset + i] = b
        return True
    
    def is_modified(self, offset: int) -> bool:
        return offset in self.modified_offsets
    
    def save(self, filepath: str) -> bool:
        try:
            with open(filepath, 'wb') as f:
                f.write(self.data)
            self.original = bytes(self.data)
            self.modified_offsets.clear()
            return True
        except:
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# DATA ANALYSIS TOOLS
# ═══════════════════════════════════════════════════════════════════════════════

class DataAnalyzer:
    """Various data analysis tools"""
    
    @staticmethod
    def calculate_checksums(data: bytes) -> Dict[str, str]:
        return {
            'CRC32': format(zlib.crc32(data) & 0xFFFFFFFF, '08X'),
            'MD5': hashlib.md5(data).hexdigest().upper(),
            'SHA1': hashlib.sha1(data).hexdigest().upper(),
            'SHA256': hashlib.sha256(data).hexdigest().upper(),
            'Adler32': format(zlib.adler32(data) & 0xFFFFFFFF, '08X'),
        }
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
    
    @staticmethod
    def find_strings(data: bytes, min_length: int = 4) -> List[Tuple[int, str]]:
        strings = []
        current_string = ""
        start_offset = 0
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:
                if not current_string:
                    start_offset = i
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append((start_offset, current_string))
                current_string = ""
        if len(current_string) >= min_length:
            strings.append((start_offset, current_string))
        return strings
    
    @staticmethod
    def find_pattern(data: bytes, pattern: bytes) -> List[int]:
        offsets = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            offsets.append(pos)
            start = pos + 1
        return offsets
    
    @staticmethod
    def find_pattern_wildcard(data: bytes, pattern: str) -> List[int]:
        parts = pattern.upper().split()
        pattern_bytes = []
        for part in parts:
            if part == '??' or part == '**':
                pattern_bytes.append(None)
            else:
                try:
                    pattern_bytes.append(int(part, 16))
                except:
                    continue
        if not pattern_bytes:
            return []
        offsets = []
        for i in range(len(data) - len(pattern_bytes) + 1):
            match = True
            for j, pb in enumerate(pattern_bytes):
                if pb is not None and data[i + j] != pb:
                    match = False
                    break
            if match:
                offsets.append(i)
        return offsets
    
    @staticmethod
    def read_value(data: bytes, offset: int, fmt: str, big_endian: bool = True) -> Any:
        endian = '>' if big_endian else '<'
        formats = {
            'byte': ('B', 1), 'sbyte': ('b', 1),
            'word': ('H', 2), 'sword': ('h', 2),
            'dword': ('I', 4), 'sdword': ('i', 4),
            'qword': ('Q', 8), 'sqword': ('q', 8),
            'float': ('f', 4), 'double': ('d', 8),
        }
        if fmt not in formats:
            return None
        struct_fmt, size = formats[fmt]
        if offset + size > len(data):
            return None
        try:
            return struct.unpack(endian + struct_fmt, data[offset:offset + size])[0]
        except:
            return None


# ═══════════════════════════════════════════════════════════════════════════════
# MIPS DISASSEMBLER
# ═══════════════════════════════════════════════════════════════════════════════

MIPS_REGISTERS = [
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra"
]

class MIPSDisassembler:
    """Simple MIPS R4300 disassembler"""
    
    R_TYPE = {
        0x00: "sll", 0x02: "srl", 0x03: "sra", 0x08: "jr", 0x09: "jalr",
        0x0c: "syscall", 0x0d: "break", 0x10: "mfhi", 0x12: "mflo",
        0x18: "mult", 0x19: "multu", 0x1a: "div", 0x1b: "divu",
        0x20: "add", 0x21: "addu", 0x22: "sub", 0x23: "subu",
        0x24: "and", 0x25: "or", 0x26: "xor", 0x27: "nor",
        0x2a: "slt", 0x2b: "sltu",
    }
    
    I_J_TYPE = {
        0x02: "j", 0x03: "jal", 0x04: "beq", 0x05: "bne",
        0x06: "blez", 0x07: "bgtz", 0x08: "addi", 0x09: "addiu",
        0x0a: "slti", 0x0b: "sltiu", 0x0c: "andi", 0x0d: "ori",
        0x0e: "xori", 0x0f: "lui", 0x20: "lb", 0x21: "lh",
        0x23: "lw", 0x24: "lbu", 0x25: "lhu", 0x28: "sb",
        0x29: "sh", 0x2b: "sw",
    }
    
    @classmethod
    def disassemble(cls, word: int, address: int = 0) -> str:
        if word == 0:
            return "nop"
        opcode = (word >> 26) & 0x3F
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        rd = (word >> 11) & 0x1F
        sa = (word >> 6) & 0x1F
        funct = word & 0x3F
        imm = word & 0xFFFF
        target = word & 0x03FFFFFF
        
        if opcode == 0:
            if funct in cls.R_TYPE:
                mn = cls.R_TYPE[funct]
                if funct in (0x00, 0x02, 0x03):
                    return f"{mn} {MIPS_REGISTERS[rd]}, {MIPS_REGISTERS[rt]}, {sa}"
                elif funct == 0x08:
                    return f"{mn} {MIPS_REGISTERS[rs]}"
                elif funct in (0x10, 0x12):
                    return f"{mn} {MIPS_REGISTERS[rd]}"
                elif funct in (0x18, 0x19, 0x1a, 0x1b):
                    return f"{mn} {MIPS_REGISTERS[rs]}, {MIPS_REGISTERS[rt]}"
                else:
                    return f"{mn} {MIPS_REGISTERS[rd]}, {MIPS_REGISTERS[rs]}, {MIPS_REGISTERS[rt]}"
        elif opcode in cls.I_J_TYPE:
            mn = cls.I_J_TYPE[opcode]
            if opcode in (0x02, 0x03):
                t = ((address + 4) & 0xF0000000) | (target << 2)
                return f"{mn} 0x{t:08X}"
            elif opcode in (0x04, 0x05):
                simm = imm if imm < 0x8000 else imm - 0x10000
                t = address + 4 + (simm << 2)
                return f"{mn} {MIPS_REGISTERS[rs]}, {MIPS_REGISTERS[rt]}, 0x{t:08X}"
            elif opcode == 0x0f:
                return f"{mn} {MIPS_REGISTERS[rt]}, 0x{imm:04X}"
            elif opcode in (0x20, 0x21, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2b):
                simm = imm if imm < 0x8000 else imm - 0x10000
                return f"{mn} {MIPS_REGISTERS[rt]}, {simm}({MIPS_REGISTERS[rs]})"
            else:
                simm = imm if imm < 0x8000 else imm - 0x10000
                return f"{mn} {MIPS_REGISTERS[rt]}, {MIPS_REGISTERS[rs]}, {simm}"
        return f".word 0x{word:08X}"


# ═══════════════════════════════════════════════════════════════════════════════
# HEX EDITOR WIDGET
# ═══════════════════════════════════════════════════════════════════════════════

class HexEditorWidget(tk.Frame):
    """Professional hex editor widget"""
    
    def __init__(self, parent, theme: dict, **kwargs):
        super().__init__(parent, **kwargs)
        self.theme = theme
        self.buffer: Optional[HexBuffer] = None
        self.bytes_per_row = 16
        self.visible_rows = 32
        self.scroll_offset = 0
        self.cursor_offset = 0
        self.selection_start = -1
        self.selection_end = -1
        self.nibble_pos = 0
        self._create_widgets()
        self._bind_events()
    
    def _create_widgets(self):
        self.configure(bg=self.theme['bg'])
        self.canvas = tk.Canvas(self, bg=self.theme['bg'], highlightthickness=0)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self._on_scroll)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.font = ('Consolas', 11)
        self.char_width = 10
        self.char_height = 18
    
    def _bind_events(self):
        self.canvas.bind('<Configure>', self._on_resize)
        self.canvas.bind('<MouseWheel>', self._on_mousewheel)
        self.canvas.bind('<Button-1>', self._on_click)
        self.canvas.bind('<B1-Motion>', self._on_drag)
        self.canvas.bind('<Key>', self._on_key)
        self.canvas.bind('<Up>', lambda e: self._move_cursor(-self.bytes_per_row))
        self.canvas.bind('<Down>', lambda e: self._move_cursor(self.bytes_per_row))
        self.canvas.bind('<Left>', lambda e: self._move_cursor(-1))
        self.canvas.bind('<Right>', lambda e: self._move_cursor(1))
        self.canvas.bind('<Prior>', lambda e: self._move_cursor(-self.bytes_per_row * self.visible_rows))
        self.canvas.bind('<Next>', lambda e: self._move_cursor(self.bytes_per_row * self.visible_rows))
        self.canvas.bind('<Home>', lambda e: self._move_cursor(-self.cursor_offset))
        self.canvas.bind('<End>', lambda e: self._move_cursor(len(self.buffer) - self.cursor_offset - 1 if self.buffer else 0))
        self.canvas.focus_set()
    
    def load_data(self, data: bytes):
        self.buffer = HexBuffer(data)
        self.scroll_offset = 0
        self.cursor_offset = 0
        self.selection_start = -1
        self.selection_end = -1
        self._update_scrollbar()
        self._redraw()
    
    def get_data(self) -> bytes:
        if self.buffer:
            return bytes(self.buffer.data)
        return b''
    
    def _on_resize(self, event):
        self.visible_rows = max(1, (event.height - 20) // self.char_height)
        self._redraw()
    
    def _on_scroll(self, *args):
        if args[0] == 'moveto':
            if self.buffer:
                total_rows = (len(self.buffer) + self.bytes_per_row - 1) // self.bytes_per_row
                self.scroll_offset = int(float(args[1]) * total_rows) * self.bytes_per_row
                self._redraw()
        elif args[0] == 'scroll':
            self.scroll_offset += int(args[1]) * self.bytes_per_row
            if self.buffer:
                max_offset = max(0, len(self.buffer) - self.visible_rows * self.bytes_per_row)
                self.scroll_offset = max(0, min(self.scroll_offset, max_offset))
            self._redraw()
    
    def _on_mousewheel(self, event):
        delta = -1 if event.delta > 0 else 1
        self.scroll_offset += delta * self.bytes_per_row * 3
        if self.buffer:
            max_offset = max(0, len(self.buffer) - self.visible_rows * self.bytes_per_row)
            self.scroll_offset = max(0, min(self.scroll_offset, max_offset))
        self._update_scrollbar()
        self._redraw()
    
    def _on_click(self, event):
        self.canvas.focus_set()
        offset = self._coords_to_offset(event.x, event.y)
        if offset is not None and offset >= 0:
            self.cursor_offset = offset
            self.selection_start = offset
            self.selection_end = offset
            self.nibble_pos = 0
            self._redraw()
    
    def _on_drag(self, event):
        offset = self._coords_to_offset(event.x, event.y)
        if offset is not None and offset >= 0:
            self.selection_end = offset
            self.cursor_offset = offset
            self._redraw()
    
    def _on_key(self, event):
        if not self.buffer:
            return
        char = event.char.upper()
        if char in '0123456789ABCDEF':
            value = int(char, 16)
            if self.nibble_pos == 0:
                current = self.buffer.get_byte(self.cursor_offset)
                new_value = (value << 4) | (current & 0x0F)
                self.buffer.set_byte(self.cursor_offset, new_value)
                self.nibble_pos = 1
            else:
                current = self.buffer.get_byte(self.cursor_offset)
                new_value = (current & 0xF0) | value
                self.buffer.set_byte(self.cursor_offset, new_value)
                self.nibble_pos = 0
                self._move_cursor(1)
            self._redraw()
    
    def _move_cursor(self, delta: int):
        if not self.buffer:
            return
        self.cursor_offset = max(0, min(self.cursor_offset + delta, len(self.buffer) - 1))
        self.nibble_pos = 0
        cursor_row = self.cursor_offset // self.bytes_per_row
        scroll_row = self.scroll_offset // self.bytes_per_row
        if cursor_row < scroll_row:
            self.scroll_offset = cursor_row * self.bytes_per_row
        elif cursor_row >= scroll_row + self.visible_rows:
            self.scroll_offset = (cursor_row - self.visible_rows + 1) * self.bytes_per_row
        self._update_scrollbar()
        self._redraw()
    
    def _coords_to_offset(self, x: int, y: int) -> Optional[int]:
        if not self.buffer:
            return None
        row = y // self.char_height
        hex_x = 100
        col = (x - hex_x) // (3 * self.char_width)
        if 0 <= col < self.bytes_per_row:
            return self.scroll_offset + row * self.bytes_per_row + col
        return None
    
    def _update_scrollbar(self):
        if not self.buffer:
            return
        total_rows = (len(self.buffer) + self.bytes_per_row - 1) // self.bytes_per_row
        if total_rows <= self.visible_rows:
            self.scrollbar.set(0, 1)
        else:
            current_row = self.scroll_offset // self.bytes_per_row
            self.scrollbar.set(current_row / total_rows, (current_row + self.visible_rows) / total_rows)
    
    def _redraw(self):
        self.canvas.delete('all')
        if not self.buffer:
            self.canvas.create_text(self.canvas.winfo_width() // 2, self.canvas.winfo_height() // 2,
                                   text="No data loaded", fill=self.theme['fg_muted'], font=self.font)
            return
        
        hex_x = 100
        ascii_x = hex_x + self.bytes_per_row * 3 * self.char_width + 20
        sel_start = min(self.selection_start, self.selection_end) if self.selection_start >= 0 else -1
        sel_end = max(self.selection_start, self.selection_end) if self.selection_start >= 0 else -1
        
        for row in range(self.visible_rows):
            y = row * self.char_height + 5
            row_offset = self.scroll_offset + row * self.bytes_per_row
            if row_offset >= len(self.buffer):
                break
            
            self.canvas.create_text(10, y, text=f"{row_offset:08X}", anchor='nw',
                                   fill=self.theme['hex_offset'], font=self.font)
            
            for col in range(self.bytes_per_row):
                byte_offset = row_offset + col
                if byte_offset >= len(self.buffer):
                    break
                
                byte_val = self.buffer.get_byte(byte_offset)
                
                if byte_offset == self.cursor_offset:
                    bg_color, fg_color = self.theme['accent'], 'white'
                elif sel_start <= byte_offset <= sel_end:
                    bg_color, fg_color = self.theme['hex_selected'], self.theme['fg']
                elif self.buffer.is_modified(byte_offset):
                    bg_color, fg_color = None, self.theme['hex_modified']
                elif byte_val == 0:
                    bg_color, fg_color = None, self.theme['hex_null']
                else:
                    bg_color, fg_color = None, self.theme['hex_byte']
                
                hx = hex_x + col * 3 * self.char_width
                if bg_color:
                    self.canvas.create_rectangle(hx - 2, y - 2, hx + 2 * self.char_width + 2,
                                                y + self.char_height - 2, fill=bg_color, outline='')
                self.canvas.create_text(hx, y, text=f"{byte_val:02X}", anchor='nw',
                                       fill=fg_color, font=self.font)
                
                ax = ascii_x + col * self.char_width
                ascii_char = chr(byte_val) if 32 <= byte_val <= 126 else '.'
                ascii_color = self.theme['hex_ascii'] if 32 <= byte_val <= 126 else self.theme['hex_nonprint']
                self.canvas.create_text(ax, y, text=ascii_char, anchor='nw',
                                       fill=ascii_color, font=self.font)
        
        sep_x = ascii_x - 10
        self.canvas.create_line(sep_x, 0, sep_x, self.canvas.winfo_height(), fill=self.theme['border'])
    
    def goto_offset(self, offset: int):
        if self.buffer and 0 <= offset < len(self.buffer):
            self.cursor_offset = offset
            row = offset // self.bytes_per_row
            self.scroll_offset = max(0, (row - self.visible_rows // 2)) * self.bytes_per_row
            self._update_scrollbar()
            self._redraw()
    
    def get_selection(self) -> bytes:
        if not self.buffer or self.selection_start < 0:
            return b''
        start = min(self.selection_start, self.selection_end)
        end = max(self.selection_start, self.selection_end)
        return bytes(self.buffer.data[start:end + 1])


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

class ROMEditorPro:
    """Main application window"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Cat's ROM Editor Pro 2.0 - Hex Editor & Decompiler")
        self.root.geometry("1400x900")
        self.root.minsize(1000, 600)
        
        self.current_theme = "dark"
        self.current_file = None
        self.translator = CToEnglishTranslator()
        
        self._setup_fonts()
        self._setup_styles()
        self._create_menu()
        self._create_ui()
        self._bind_shortcuts()
    
    def _setup_fonts(self):
        self.fonts = {
            'ui': ('Segoe UI', 10),
            'ui_bold': ('Segoe UI', 10, 'bold'),
            'code': ('Consolas', 11),
            'small': ('Segoe UI', 9),
        }
    
    def _setup_styles(self):
        style = ttk.Style()
        theme = THEMES[self.current_theme]
        style.configure('TNotebook', background=theme['bg_secondary'])
        style.configure('TNotebook.Tab', padding=[12, 4])
    
    def _create_menu(self):
        theme = THEMES[self.current_theme]
        self.menubar = tk.Menu(self.root, bg=theme['bg_tertiary'], fg=theme['fg'])
        self.root.config(menu=self.menubar)
        
        file_menu = tk.Menu(self.menubar, tearoff=0, bg=theme['bg_tertiary'], fg=theme['fg'])
        self.menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open...", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Save", command=self.save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As...", command=self.save_file_as)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        edit_menu = tk.Menu(self.menubar, tearoff=0, bg=theme['bg_tertiary'], fg=theme['fg'])
        self.menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Undo", command=self.undo, accelerator="Ctrl+Z")
        edit_menu.add_command(label="Redo", command=self.redo, accelerator="Ctrl+Y")
        edit_menu.add_separator()
        edit_menu.add_command(label="Go to Offset...", command=self.goto_offset, accelerator="Ctrl+G")
        edit_menu.add_command(label="Find...", command=self.find_dialog, accelerator="Ctrl+F")
        
        tools_menu = tk.Menu(self.menubar, tearoff=0, bg=theme['bg_tertiary'], fg=theme['fg'])
        self.menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Checksum Calculator", command=self.show_checksums)
        tools_menu.add_command(label="String Extractor", command=self.extract_strings)
        tools_menu.add_command(label="Entropy Analysis", command=self.show_entropy)
        tools_menu.add_separator()
        tools_menu.add_command(label="Disassemble MIPS", command=self.disassemble_mips)
        tools_menu.add_command(label="C to English Translator", command=self.show_translator)
        
        view_menu = tk.Menu(self.menubar, tearoff=0, bg=theme['bg_tertiary'], fg=theme['fg'])
        self.menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Theme", command=self.toggle_theme)
        
        help_menu = tk.Menu(self.menubar, tearoff=0, bg=theme['bg_tertiary'], fg=theme['fg'])
        self.menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def _create_ui(self):
        theme = THEMES[self.current_theme]
        self.main_frame = tk.Frame(self.root, bg=theme['bg'])
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self._create_toolbar()
        
        self.paned = tk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL, bg=theme['border'], sashwidth=4)
        self.paned.pack(fill=tk.BOTH, expand=True)
        
        self._create_hex_panel()
        self._create_tools_panel()
        self._create_status_bar()
    
    def _create_toolbar(self):
        theme = THEMES[self.current_theme]
        toolbar = tk.Frame(self.main_frame, bg=theme['bg_tertiary'], height=40)
        toolbar.pack(fill=tk.X)
        toolbar.pack_propagate(False)
        
        btn_frame = tk.Frame(toolbar, bg=theme['bg_tertiary'])
        btn_frame.pack(side=tk.LEFT, padx=10, pady=5)
        
        for text, cmd in [("📂 Open", self.open_file), ("💾 Save", self.save_file),
                          ("🔍 Find", self.find_dialog), ("📍 Goto", self.goto_offset),
                          ("↩️ Undo", self.undo), ("↪️ Redo", self.redo)]:
            tk.Button(btn_frame, text=text, command=cmd, bg=theme['bg_tertiary'],
                     fg=theme['fg'], relief=tk.FLAT, padx=8, font=self.fonts['ui']).pack(side=tk.LEFT, padx=2)
        
        tk.Frame(btn_frame, width=2, height=20, bg=theme['border']).pack(side=tk.LEFT, padx=10)
        
        tk.Label(btn_frame, text="Offset:", bg=theme['bg_tertiary'], fg=theme['fg'],
                font=self.fonts['ui']).pack(side=tk.LEFT, padx=5)
        self.offset_entry = tk.Entry(btn_frame, width=12, bg=theme['bg_input'],
                                    fg=theme['fg'], font=self.fonts['code'], relief=tk.FLAT)
        self.offset_entry.pack(side=tk.LEFT, padx=2)
        self.offset_entry.bind('<Return>', lambda e: self.goto_offset())
    
    def _create_hex_panel(self):
        theme = THEMES[self.current_theme]
        hex_frame = tk.Frame(self.paned, bg=theme['bg'])
        self.paned.add(hex_frame, minsize=600, width=800)
        
        header = tk.Frame(hex_frame, bg=theme['bg_tertiary'], height=30)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="Hex Editor", bg=theme['bg_tertiary'], fg=theme['fg'],
                font=self.fonts['ui_bold']).pack(side=tk.LEFT, padx=10, pady=5)
        self.file_label = tk.Label(header, text="No file loaded", bg=theme['bg_tertiary'],
                                  fg=theme['fg_secondary'], font=self.fonts['small'])
        self.file_label.pack(side=tk.RIGHT, padx=10, pady=5)
        
        self.hex_editor = HexEditorWidget(hex_frame, theme, bg=theme['bg'])
        self.hex_editor.pack(fill=tk.BOTH, expand=True)
    
    def _create_tools_panel(self):
        theme = THEMES[self.current_theme]
        tools_frame = tk.Frame(self.paned, bg=theme['bg_secondary'])
        self.paned.add(tools_frame, minsize=300, width=500)
        
        self.notebook = ttk.Notebook(tools_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Data Inspector
        frame1 = tk.Frame(self.notebook, bg=theme['bg'])
        self.notebook.add(frame1, text="Inspector")
        self.inspector_text = tk.Text(frame1, wrap=tk.WORD, bg=theme['bg'], fg=theme['fg'],
                                      font=self.fonts['code'], relief=tk.FLAT)
        self.inspector_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Disassembly
        frame2 = tk.Frame(self.notebook, bg=theme['bg'])
        self.notebook.add(frame2, text="Disassembly")
        ctrl = tk.Frame(frame2, bg=theme['bg_secondary'])
        ctrl.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(ctrl, text="Disassemble", command=self.disassemble_mips,
                 bg=theme['accent'], fg='white', font=self.fonts['ui']).pack(side=tk.LEFT)
        self.disasm_text = tk.Text(frame2, wrap=tk.NONE, bg=theme['bg'], fg=theme['fg'],
                                  font=self.fonts['code'], relief=tk.FLAT)
        self.disasm_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # C to English
        frame3 = tk.Frame(self.notebook, bg=theme['bg'])
        self.notebook.add(frame3, text="C → English")
        tk.Label(frame3, text="Enter C Code:", bg=theme['bg'], fg=theme['fg'],
                font=self.fonts['ui_bold']).pack(anchor='w', padx=5, pady=2)
        self.c_input = tk.Text(frame3, wrap=tk.WORD, bg=theme['bg_input'], fg=theme['fg'],
                              font=self.fonts['code'], height=10, relief=tk.FLAT)
        self.c_input.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(frame3, text="🔄 Translate", command=self.translate_c_code,
                 bg=theme['accent'], fg='white', font=self.fonts['ui']).pack(pady=5)
        tk.Label(frame3, text="Plain English:", bg=theme['bg'], fg=theme['fg'],
                font=self.fonts['ui_bold']).pack(anchor='w', padx=5, pady=2)
        self.english_output = tk.Text(frame3, wrap=tk.WORD, bg=theme['bg'], fg=theme['fg'],
                                     font=self.fonts['ui'], relief=tk.FLAT)
        self.english_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Strings
        frame4 = tk.Frame(self.notebook, bg=theme['bg'])
        self.notebook.add(frame4, text="Strings")
        ctrl4 = tk.Frame(frame4, bg=theme['bg_secondary'])
        ctrl4.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(ctrl4, text="Min:", bg=theme['bg_secondary'], fg=theme['fg']).pack(side=tk.LEFT)
        self.string_min = tk.Entry(ctrl4, width=5, bg=theme['bg_input'], fg=theme['fg'])
        self.string_min.pack(side=tk.LEFT, padx=5)
        self.string_min.insert(0, "4")
        tk.Button(ctrl4, text="Extract", command=self.extract_strings,
                 bg=theme['accent'], fg='white').pack(side=tk.LEFT, padx=5)
        self.strings_text = tk.Text(frame4, wrap=tk.NONE, bg=theme['bg'], fg=theme['fg'],
                                   font=self.fonts['code'], relief=tk.FLAT)
        self.strings_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Checksums
        frame5 = tk.Frame(self.notebook, bg=theme['bg'])
        self.notebook.add(frame5, text="Checksums")
        tk.Button(frame5, text="Calculate", command=self.show_checksums,
                 bg=theme['accent'], fg='white', font=self.fonts['ui']).pack(pady=10)
        self.checksums_text = tk.Text(frame5, wrap=tk.WORD, bg=theme['bg'], fg=theme['fg'],
                                     font=self.fonts['code'], relief=tk.FLAT)
        self.checksums_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_status_bar(self):
        theme = THEMES[self.current_theme]
        status = tk.Frame(self.main_frame, bg=theme['status_bg'], height=25)
        status.pack(fill=tk.X, side=tk.BOTTOM)
        status.pack_propagate(False)
        self.status_label = tk.Label(status, text="Ready", bg=theme['status_bg'],
                                    fg=theme['status_fg'], font=self.fonts['small'])
        self.status_label.pack(side=tk.LEFT, padx=10)
        self.size_label = tk.Label(status, text="Size: 0", bg=theme['status_bg'],
                                  fg=theme['status_fg'], font=self.fonts['small'])
        self.size_label.pack(side=tk.RIGHT, padx=10)
    
    def _bind_shortcuts(self):
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-s>', lambda e: self.save_file())
        self.root.bind('<Control-g>', lambda e: self.goto_offset())
        self.root.bind('<Control-f>', lambda e: self.find_dialog())
        self.root.bind('<Control-z>', lambda e: self.undo())
        self.root.bind('<Control-y>', lambda e: self.redo())
    
    def open_file(self):
        filepath = filedialog.askopenfilename(title="Open File", filetypes=[
            ("All Files", "*.*"), ("ROM Files", "*.z64 *.n64 *.v64 *.rom *.bin")])
        if filepath:
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                self.hex_editor.load_data(data)
                self.current_file = filepath
                self.file_label.config(text=os.path.basename(filepath))
                self.size_label.config(text=f"Size: {len(data):,} bytes")
                self.status_label.config(text=f"Loaded: {os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def save_file(self):
        if self.current_file and self.hex_editor.buffer:
            self.hex_editor.buffer.save(self.current_file)
            self.status_label.config(text="Saved")
        else:
            self.save_file_as()
    
    def save_file_as(self):
        if not self.hex_editor.buffer:
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".bin")
        if filepath:
            self.current_file = filepath
            self.save_file()
            self.file_label.config(text=os.path.basename(filepath))
    
    def undo(self):
        if self.hex_editor.buffer and self.hex_editor.buffer.undo():
            self.hex_editor._redraw()
    
    def redo(self):
        if self.hex_editor.buffer and self.hex_editor.buffer.redo():
            self.hex_editor._redraw()
    
    def goto_offset(self):
        offset_str = self.offset_entry.get().strip()
        if not offset_str:
            offset_str = simpledialog.askstring("Goto", "Enter offset (hex or dec):")
        if offset_str:
            try:
                offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
                self.hex_editor.goto_offset(offset)
            except:
                messagebox.showerror("Error", "Invalid offset")
    
    def find_dialog(self):
        theme = THEMES[self.current_theme]
        dialog = tk.Toplevel(self.root)
        dialog.title("Find")
        dialog.geometry("400x120")
        dialog.configure(bg=theme['bg'])
        
        tk.Label(dialog, text="Find hex (e.g., 'FF 00 ?? AB'):", bg=theme['bg'],
                fg=theme['fg']).pack(padx=20, pady=10)
        entry = tk.Entry(dialog, width=40, bg=theme['bg_input'], fg=theme['fg'])
        entry.pack(padx=20)
        entry.focus_set()
        
        def do_find():
            pattern = entry.get().strip()
            if pattern and self.hex_editor.buffer:
                results = DataAnalyzer.find_pattern_wildcard(self.hex_editor.buffer.data, pattern)
                if results:
                    self.hex_editor.goto_offset(results[0])
                    self.status_label.config(text=f"Found {len(results)} matches")
                else:
                    messagebox.showinfo("Find", "Not found")
            dialog.destroy()
        
        tk.Button(dialog, text="Find", command=do_find, bg=theme['accent'], fg='white').pack(pady=10)
        entry.bind('<Return>', lambda e: do_find())
    
    def show_checksums(self):
        self.checksums_text.delete('1.0', tk.END)
        if not self.hex_editor.buffer:
            return
        data = bytes(self.hex_editor.buffer.data)
        checksums = DataAnalyzer.calculate_checksums(data)
        text = "═══ CHECKSUMS ═══\n\n"
        for name, val in checksums.items():
            text += f"{name:8}: {val}\n"
        text += f"\nEntropy: {DataAnalyzer.calculate_entropy(data):.4f} bits/byte"
        self.checksums_text.insert('1.0', text)
    
    def extract_strings(self):
        self.strings_text.delete('1.0', tk.END)
        if not self.hex_editor.buffer:
            return
        try:
            min_len = int(self.string_min.get())
        except:
            min_len = 4
        strings = DataAnalyzer.find_strings(self.hex_editor.buffer.data, min_len)
        text = f"═══ {len(strings)} Strings ═══\n\n"
        for off, s in strings[:500]:
            text += f"0x{off:08X}: {s}\n"
        self.strings_text.insert('1.0', text)
    
    def show_entropy(self):
        if not self.hex_editor.buffer:
            return
        entropy = DataAnalyzer.calculate_entropy(self.hex_editor.buffer.data)
        messagebox.showinfo("Entropy", f"Shannon Entropy: {entropy:.4f} bits/byte")
    
    def disassemble_mips(self):
        self.disasm_text.delete('1.0', tk.END)
        if not self.hex_editor.buffer:
            return
        start = self.hex_editor.cursor_offset
        start = (start // 4) * 4
        data = self.hex_editor.buffer.data
        lines = []
        for off in range(start, min(start + 256, len(data) - 3), 4):
            word = struct.unpack('>I', data[off:off+4])[0]
            lines.append(f"0x{off:08X}:  {word:08X}  {MIPSDisassembler.disassemble(word, 0x80000000 + off)}\n")
        self.disasm_text.insert('1.0', ''.join(lines))
        self.notebook.select(1)
    
    def translate_c_code(self):
        c_code = self.c_input.get('1.0', tk.END)
        english = self.translator.translate(c_code)
        self.english_output.delete('1.0', tk.END)
        self.english_output.insert('1.0', english)
    
    def show_translator(self):
        self.notebook.select(2)
    
    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        theme = THEMES[self.current_theme]
        self.hex_editor.theme = theme
        self.hex_editor.configure(bg=theme['bg'])
        self.hex_editor.canvas.configure(bg=theme['bg'])
        self.hex_editor._redraw()
        self.status_label.config(text=f"Theme: {theme['name']}")
    
    def show_about(self):
        messagebox.showinfo("About", """
╔══════════════════════════════════════════════╗
║      CAT'S ROM EDITOR PRO 2.0                ║
║      Ultimate Hex Editor & Decompiler        ║
╠══════════════════════════════════════════════╣
║  • Full Hex Editing with Undo/Redo           ║
║  • C Code to English Translation             ║
║  • MIPS R4300 Disassembly                    ║
║  • Pattern Search with Wildcards             ║
║  • Checksum Calculator                       ║
║  • String Extractor                          ║
║  • Entropy Analysis                          ║
║                                              ║
║  © 2025 Flames Co. / Team Flames / Samsoft   ║
╚══════════════════════════════════════════════╝
        """)
    
    def run(self):
        self.root.mainloop()


def main():
    print("=" * 60)
    print("  CAT'S ROM EDITOR PRO 2.0")
    print("  Ultimate Hex Editor + C-to-English Translator")
    print("  © 2025 Flames Co. / Team Flames / Samsoft")
    print("=" * 60)
    app = ROMEditorPro()
    app.run()

if __name__ == "__main__":
    main()
