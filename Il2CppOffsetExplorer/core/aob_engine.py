import struct
import re
from typing import Dict, Any, List, Optional
from core.binary_reader import BinaryReader
from core.disassembler import SimpleARM64Disassembler, SimpleARM32Disassembler, FunctionAnalyzer

class AOBEngine:
    def __init__(self, binary_reader: Optional[BinaryReader] = None):
        self.binary = binary_reader

    def set_binary(self, binary_reader: BinaryReader):
        self.binary = binary_reader

    def generate_aob(self, address: int, length: int = 24, mask_relative: bool = True, ensure_unique: bool = True) -> Dict[str, Any]:
        if not self.binary:
            return {"error": "Binario no cargado"}

        current_length = max(12, length)
        max_length = 160
        
        while current_length <= max_length:
            raw_bytes = self.binary.read_bytes(address, current_length, is_vaddr=True)
            if not raw_bytes:
                return {"error": f"No se pudieron leer bytes en la dirección {hex(address)}"}

            exact_aob = self.bytes_to_aob(raw_bytes)
            
            if mask_relative and self.binary.is_64bit:
                masked_aob = self.mask_arm64_bytes(raw_bytes)
            elif mask_relative and not self.binary.is_64bit:
                masked_aob = self.mask_arm32_bytes(raw_bytes)
            else:
                masked_aob = exact_aob

            pattern_to_test = masked_aob if mask_relative else exact_aob

            # Eliminar comodines sobrantes al final del patrón para máxima compatibilidad
            pattern_trimmed = self.trim_trailing_wildcards(pattern_to_test)

            matches = self.count_matches(pattern_trimmed)
            is_unique = (len(matches) == 1)

            if is_unique or not ensure_unique or current_length >= max_length or len(raw_bytes) < current_length:
                # Generar desglose de instrucciones desensambladas
                disasm_lines = []
                for i in range(0, len(raw_bytes) - 3, 4):
                    chunk = raw_bytes[i:i+4]
                    pc = address + i
                    if self.binary.is_64bit:
                        disasm_text = SimpleARM64Disassembler.decode_instruction(chunk, pc)
                    else:
                        disasm_text = SimpleARM32Disassembler.decode_instruction(chunk, pc)
                    hex_str = " ".join(f"{b:02X}" for b in chunk)
                    disasm_lines.append({
                        "offset": hex(pc),
                        "bytes": hex_str,
                        "asm": disasm_text
                    })

                # Análisis heurístico de la función
                analysis = FunctionAnalyzer.analyze(disasm_lines)

                # Generar formatos de exportación de la firma
                export_formats = self.format_aob_all(pattern_trimmed)

                return {
                    "address": address,
                    "address_hex": hex(address),
                    "address_hex_upper": f"0x{address:08X}",
                    "length_bytes": len(raw_bytes),
                    "raw_hex": raw_bytes.hex().upper(),
                    "exact_aob": exact_aob,
                    "masked_aob": masked_aob,
                    "active_pattern": pattern_trimmed,
                    "matches_count": len(matches),
                    "is_unique": is_unique,
                    "match_offsets": [f"0x{m:08X}" for m in matches[:5]],
                    "disassembly": disasm_lines,
                    "analysis": analysis,
                    "formats": export_formats
                }

            current_length += 8

        return {
            "address": address,
            "address_hex": hex(address),
            "exact_aob": exact_aob,
            "masked_aob": masked_aob,
            "active_pattern": pattern_to_test,
            "matches_count": len(matches),
            "is_unique": False,
            "formats": self.format_aob_all(pattern_to_test)
        }

    @staticmethod
    def trim_trailing_wildcards(pattern: str) -> str:
        """Elimina los comodines '??' del final del patrón"""
        tokens = pattern.strip().split()
        while tokens and tokens[-1] in ("??", "?", "*"):
            tokens.pop()
        return " ".join(tokens)

    @staticmethod
    def bytes_to_aob(data: bytes) -> str:
        return " ".join(f"{b:02X}" for b in data)

    @staticmethod
    def mask_arm64_bytes(data: bytes) -> str:
        """
        Enmascara instrucciones dependientes de la posición (PC-relative) en ARM64:
        ADRP, ADR, B, BL, B.cond, CBZ, CBNZ, TBZ, TBNZ, LDR literal.
        """
        result_parts = []
        for i in range(0, len(data) - 3, 4):
            chunk = data[i:i+4]
            insn, = struct.unpack('<I', chunk)
            
            # ADRP (0x90000000 / 0xF0000000) o ADR (0x10000000)
            if (insn & 0x1F000000) == 0x10000000:
                result_parts.append("?? ?? ?? ??")
            # B / BL (0x14000000 / 0x94000000)
            elif (insn & 0x7C000000) == 0x14000000:
                result_parts.append("?? ?? ?? ??")
            # B.cond (0x54000000)
            elif (insn & 0xFF000010) == 0x54000000:
                result_parts.append("?? ?? ?? ??")
            # CBZ / CBNZ (0x34000000 / 0x35000000)
            elif (insn & 0x7E000000) == 0x34000000:
                result_parts.append("?? ?? ?? ??")
            # TBZ / TBNZ (0x36000000 / 0x37000000)
            elif (insn & 0x7E000000) == 0x36000000:
                result_parts.append("?? ?? ?? ??")
            # LDR literal (0x18000000)
            elif (insn & 0x3B000000) == 0x18000000:
                result_parts.append("?? ?? ?? ??")
            else:
                result_parts.append(f"{chunk[0]:02X} {chunk[1]:02X} {chunk[2]:02X} {chunk[3]:02X}")
                
        remainder = len(data) % 4
        if remainder > 0:
            for b in data[-remainder:]:
                result_parts.append(f"{b:02X}")

        return " ".join(result_parts)

    @staticmethod
    def mask_arm32_bytes(data: bytes) -> str:
        """Enmascara instrucciones ARM32 dependientes de la posición (B, BL, LDR PC)"""
        result_parts = []
        for i in range(0, len(data) - 3, 4):
            chunk = data[i:i+4]
            insn, = struct.unpack('<I', chunk)
            
            # B / BL (0x0A000000 / 0x0B000000)
            if (insn & 0x0E000000) == 0x0A000000:
                result_parts.append("?? ?? ?? ??")
            # LDR Rd, [PC, #offset] (0x059F0000 / 0x051F0000)
            elif (insn & 0x0F7F0000) == 0x051F0000:
                result_parts.append("?? ?? ?? ??")
            else:
                result_parts.append(f"{chunk[0]:02X} {chunk[1]:02X} {chunk[2]:02X} {chunk[3]:02X}")

        remainder = len(data) % 4
        if remainder > 0:
            for b in data[-remainder:]:
                result_parts.append(f"{b:02X}")

        return " ".join(result_parts)

    @classmethod
    def format_aob_all(cls, pattern: str) -> Dict[str, str]:
        """Genera representaciones del patrón para múltiples entornos y herramientas"""
        tokens = pattern.strip().split()
        if not tokens:
            return {}

        # 1. IDA / Cheat Engine
        ida_ce = " ".join(tokens)

        # 2. C / C++ Byte Pattern + Mask
        cpp_bytes = []
        cpp_mask = []
        for t in tokens:
            if t in ("??", "?", "*"):
                cpp_bytes.append(r"\x00")
                cpp_mask.append("?")
            else:
                cpp_bytes.append(f"\\x{t.upper()}")
                cpp_mask.append("x")
        cpp_format = f'const char* aob_bytes = "{"".join(cpp_bytes)}";\nconst char* aob_mask  = "{"".join(cpp_mask)}";'

        # 3. C# Harmony / BepInEx Array
        cs_bytes = []
        for t in tokens:
            if t in ("??", "?", "*"):
                cs_bytes.append("0x00")
            else:
                cs_bytes.append(f"0x{t.upper()}")
        cs_format = f'byte[] pattern = new byte[] {{ {", ".join(cs_bytes)} }};\nstring mask = "{"".join(cpp_mask)}";'

        # 4. GameGuardian Lua Format
        gg_tokens = [f"'{t}'" if t in ("??", "?", "*") else t for t in tokens]
        gg_format = f"local pattern = \"{' '.join(gg_tokens)}\""

        # 5. Frida Memory.scan Format
        frida_format = " ".join([t.lower() if t not in ("??", "?", "*") else "??" for t in tokens])

        return {
            "ida_cheat_engine": ida_ce,
            "cpp_mask": cpp_format,
            "csharp_array": cs_format,
            "gameguardian_lua": gg_format,
            "frida_scan": frida_format
        }

    def count_matches(self, aob_pattern: str, max_limit: int = 10) -> List[int]:
        if not self.binary or not self.binary.mm:
            return []

        regex_pattern = self.aob_to_regex(aob_pattern)
        if not regex_pattern:
            return []

        matches = []
        try:
            for match in re.finditer(regex_pattern, self.binary.mm):
                vaddr = self.binary.file_offset_to_vaddr(match.start())
                matches.append(vaddr)
                if len(matches) >= max_limit:
                    break
        except Exception:
            pass

        return matches

    @staticmethod
    def aob_to_regex(aob_pattern: str) -> Optional[bytes]:
        tokens = aob_pattern.strip().split()
        if not tokens:
            return None

        pattern_parts = []
        for t in tokens:
            t = t.strip()
            if t in ("??", "?", "*", "**"):
                pattern_parts.append(b'.')
            else:
                try:
                    byte_val = int(t, 16)
                    pattern_parts.append(re.escape(bytes([byte_val])))
                except ValueError:
                    return None

        return b''.join(pattern_parts)
