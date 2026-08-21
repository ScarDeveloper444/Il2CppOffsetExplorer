import struct
import math
from typing import Tuple, Optional, List, Dict, Any

class SimpleARM64Disassembler:
    COND_NAMES = ["EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"]

    @classmethod
    def decode_instruction(cls, insn_bytes: bytes, pc: int = 0) -> str:
        if len(insn_bytes) < 4:
            return "?? (bytes insuficientes)"
        
        insn, = struct.unpack('<I', insn_bytes[:4])
        
        # 1. NOP / BRK / HLT
        if insn == 0xD503201F:
            return "NOP"
        if (insn & 0xFFE0001F) == 0xD4200000:
            imm16 = (insn >> 5) & 0xFFFF
            return f"BRK #0x{imm16:X}"
        if (insn & 0xFFE0001F) == 0xD4400000:
            imm16 = (insn >> 5) & 0xFFFF
            return f"HLT #0x{imm16:X}"

        # 2. ARMv8.3+ Pointer Authentication (PAC / AUT / BTI)
        if insn == 0xD503233F:
            return "PACIASP"
        if insn == 0xD50323BF:
            return "AUTIASP"
        if insn == 0xD503237F:
            return "PACIBASP"
        if insn == 0xD50323FF:
            return "AUTIBASP"
        if insn == 0xD503241F:
            return "BTI"
        if insn == 0xD65F0BFF:
            return "RETAA"
        if insn == 0xD65F0FFF:
            return "RETAB"

        # 3. RET
        if (insn & 0xFFFFFC1F) == 0xD65F0000:
            rn = (insn >> 5) & 0x1F
            return f"RET X{rn}" if rn != 30 else "RET"

        # 4. BR / BLR (Indirect jump / call)
        if (insn & 0xFFFFFC1F) == 0xD61F0000:
            rn = (insn >> 5) & 0x1F
            return f"BR X{rn}"
        if (insn & 0xFFFFFC1F) == 0xD63F0000:
            rn = (insn >> 5) & 0x1F
            return f"BLR X{rn}"

        # 5. B / BL (Incondicional)
        if (insn & 0x7C000000) == 0x14000000:
            is_bl = (insn & 0x80000000) != 0
            imm26 = insn & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 -= 0x04000000
            target = pc + (imm26 << 2)
            op = "BL" if is_bl else "B"
            return f"{op} 0x{target:X}"

        # 6. ADRP / ADR
        if (insn & 0x1F000000) == 0x10000000:
            is_adrp = (insn & 0x80000000) != 0
            rd = insn & 0x1F
            immhi = (insn >> 5) & 0x7FFFF
            immlo = (insn >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            if is_adrp:
                target = (pc & ~0xFFF) + (imm << 12)
                return f"ADRP X{rd}, 0x{target:X}"
            else:
                target = pc + imm
                return f"ADR X{rd}, 0x{target:X}"

        # 7. TBZ / TBNZ (Test bit and branch)
        if (insn & 0x7E000000) == 0x36000000:
            is_tbnz = (insn & 0x01000000) != 0
            b5 = (insn >> 31) & 1
            b40 = (insn >> 19) & 0x1F
            bit = (b5 << 5) | b40
            rt = insn & 0x1F
            imm14 = (insn >> 5) & 0x3FFF
            if imm14 & 0x2000:
                imm14 -= 0x4000
            target = pc + (imm14 << 2)
            op = "TBNZ" if is_tbnz else "TBZ"
            reg = f"X{rt}" if b5 else f"W{rt}"
            return f"{op} {reg}, #{bit}, 0x{target:X}"

        # 8. CBZ / CBNZ
        if (insn & 0x7E000000) == 0x34000000:
            is_cbnz = (insn & 0x01000000) != 0
            is_64 = (insn & 0x80000000) != 0
            rt = insn & 0x1F
            reg = f"X{rt}" if is_64 else f"W{rt}"
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 -= 0x80000
            target = pc + (imm19 << 2)
            op = "CBNZ" if is_cbnz else "CBZ"
            return f"{op} {reg}, 0x{target:X}"

        # 9. B.cond
        if (insn & 0xFF000010) == 0x54000000:
            cond = insn & 0xF
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 -= 0x80000
            target = pc + (imm19 << 2)
            cond_str = cls.COND_NAMES[cond] if cond < len(cls.COND_NAMES) else f"C{cond}"
            return f"B.{cond_str} 0x{target:X}"

        # 10. MOV Register (ORR rd, xzr/wzr, rm) - FIX MASK BIT 31
        if (insn & 0x7FE0FFE0) == 0x2A0003E0:
            is_64 = (insn & 0x80000000) != 0
            rd = insn & 0x1F
            rm = (insn >> 16) & 0x1F
            r_type = "X" if is_64 else "W"
            return f"MOV {r_type}{rd}, {r_type}{rm}"

        # 11. MVN Register (ORN rd, xzr/wzr, rm)
        if (insn & 0x7FE0FFE0) == 0x2A2003E0:
            is_64 = (insn & 0x80000000) != 0
            rd = insn & 0x1F
            rm = (insn >> 16) & 0x1F
            r_type = "X" if is_64 else "W"
            return f"MVN {r_type}{rd}, {r_type}{rm}"

        # 12. MOVZ / MOVN / MOVK (Move wide immediate)
        if (insn & 0x1F800000) == 0x12800000:
            is_64 = (insn & 0x80000000) != 0
            opc = (insn >> 29) & 0x3
            hw = (insn >> 21) & 0x3
            imm16 = (insn >> 5) & 0xFFFF
            rd = insn & 0x1F
            reg = f"X{rd}" if is_64 else f"W{rd}"
            op_name = ["MOVN", "UNALLOC", "MOVZ", "MOVK"][opc]
            shift = hw * 16
            
            # Formato amigable: MOV W0, #1 o MOV X0, #0
            if opc == 2 and shift == 0: # MOVZ
                return f"MOV {reg}, #0x{imm16:X}" if imm16 > 9 else f"MOV {reg}, #{imm16}"
            if shift > 0:
                return f"{op_name} {reg}, #0x{imm16:X}, LSL #{shift}"
            return f"{op_name} {reg}, #0x{imm16:X}"

        # 13. ADD / SUB / ADDS / SUBS (Immediate)
        if (insn & 0x1F000000) == 0x11000000:
            is_64 = (insn & 0x80000000) != 0
            is_sub = (insn & 0x40000000) != 0
            is_flags = (insn & 0x20000000) != 0
            sh = (insn >> 22) & 1
            imm12 = (insn >> 10) & 0xFFF
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            reg_d = (f"SP" if rd == 31 and not is_flags else f"X{rd}") if is_64 else (f"WSP" if rd == 31 and not is_flags else f"W{rd}")
            reg_n = (f"SP" if rn == 31 else f"X{rn}") if is_64 else (f"WSP" if rn == 31 else f"W{rn}")
            val = imm12 << (12 if sh else 0)
            
            # Alias CMP / CMN
            if is_flags and rd == 31:
                return f"CMP {reg_n}, #0x{val:X}" if is_sub else f"CMN {reg_n}, #0x{val:X}"
            
            op = ("SUBS" if is_flags else "SUB") if is_sub else ("ADDS" if is_flags else "ADD")
            return f"{op} {reg_d}, {reg_n}, #0x{val:X}"

        # 14. ADD / SUB / ADDS / SUBS (Shifted register)
        if (insn & 0x1F200000) == 0x0B000000:
            is_64 = (insn & 0x80000000) != 0
            is_sub = (insn & 0x40000000) != 0
            is_flags = (insn & 0x20000000) != 0
            shift_t = (insn >> 22) & 3
            rm = (insn >> 16) & 0x1F
            imm6 = (insn >> 10) & 0x3F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            shift_names = ["LSL", "LSR", "ASR", "ROR"]
            
            r_type = "X" if is_64 else "W"
            reg_d = f"{r_type}{rd}"
            reg_n = f"{r_type}{rn}"
            reg_m = f"{r_type}{rm}"
            
            if is_flags and rd == 31:
                cmp_op = "CMP" if is_sub else "CMN"
                if imm6 > 0:
                    return f"{cmp_op} {reg_n}, {reg_m}, {shift_names[shift_t]} #{imm6}"
                return f"{cmp_op} {reg_n}, {reg_m}"

            # NEG alias: SUB Rd, XZR, Rm
            if is_sub and rn == 31:
                neg_op = "NEGS" if is_flags else "NEG"
                if imm6 > 0:
                    return f"{neg_op} {reg_d}, {reg_m}, {shift_names[shift_t]} #{imm6}"
                return f"{neg_op} {reg_d}, {reg_m}"

            op = ("SUBS" if is_flags else "SUB") if is_sub else ("ADDS" if is_flags else "ADD")
            if imm6 > 0:
                return f"{op} {reg_d}, {reg_n}, {reg_m}, {shift_names[shift_t]} #{imm6}"
            return f"{op} {reg_d}, {reg_n}, {reg_m}"

        # 15. Logical Register (AND, ORR, EOR, BIC, ORN, EON, TST)
        if (insn & 0x1F000000) == 0x0A000000:
            is_64 = (insn & 0x80000000) != 0
            opc = (insn >> 29) & 3
            is_n = (insn & 0x00200000) != 0
            rm = (insn >> 16) & 0x1F
            imm6 = (insn >> 10) & 0x3F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            
            r_type = "X" if is_64 else "W"
            reg_d = f"{r_type}{rd}"
            reg_n = f"{r_type}{rn}"
            reg_m = f"{r_type}{rm}"
            
            op_table = {
                (0, False): "AND", (0, True): "BIC",
                (1, False): "ORR", (1, True): "ORN",
                (2, False): "EOR", (2, True): "EON",
                (3, False): "ANDS", (3, True): "BICS"
            }
            op_name = op_table.get((opc, is_n), "LOGIC")
            
            # TST alias: ANDS XZR, Xn, Xm
            if opc == 3 and not is_n and rd == 31:
                return f"TST {reg_n}, {reg_m}"

            if imm6 > 0:
                return f"{op_name} {reg_d}, {reg_n}, {reg_m}, LSL #{imm6}"
            return f"{op_name} {reg_d}, {reg_n}, {reg_m}"

        # 16. Multiplication & Division (MUL, MADD, MSUB, SDIV, UDIV)
        if (insn & 0x1F800000) == 0x1B000000:
            is_64 = (insn & 0x80000000) != 0
            op54 = (insn >> 21) & 7
            op31 = (insn >> 15) & 1
            rm = (insn >> 16) & 0x1F
            ra = (insn >> 10) & 0x1F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            
            r_type = "X" if is_64 else "W"
            reg_d = f"{r_type}{rd}"
            reg_n = f"{r_type}{rn}"
            reg_m = f"{r_type}{rm}"
            reg_a = f"{r_type}{ra}"
            
            if op54 == 0 and op31 == 0:
                if ra == 31:
                    return f"MUL {reg_d}, {reg_n}, {reg_m}"
                return f"MADD {reg_d}, {reg_n}, {reg_m}, {reg_a}"
            elif op54 == 0 and op31 == 1:
                return f"MSUB {reg_d}, {reg_n}, {reg_m}, {reg_a}"
            elif op54 == 6 and op31 == 0:
                return f"SDIV {reg_d}, {reg_n}, {reg_m}"
            elif op54 == 6 and op31 == 1:
                return f"UDIV {reg_d}, {reg_n}, {reg_m}"

        # 17. CSEL / CSINC / CSINV / CSNEG / CSET / CSETM
        if (insn & 0x1FE00000) == 0x1A800000:
            is_64 = (insn & 0x80000000) != 0
            rm = (insn >> 16) & 0x1F
            cond = (insn >> 12) & 0xF
            op2 = (insn >> 10) & 3
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            
            r_type = "X" if is_64 else "W"
            reg_d = f"{r_type}{rd}"
            reg_n = f"{r_type}{rn}"
            reg_m = f"{r_type}{rm}"
            cond_str = cls.COND_NAMES[cond] if cond < len(cls.COND_NAMES) else f"C{cond}"
            inv_cond_str = cls.COND_NAMES[cond ^ 1] if (cond ^ 1) < len(cls.COND_NAMES) else f"C{cond^1}"
            
            # CSET: CSINC Rd, XZR, XZR, inv_cond
            if op2 == 1 and rn == 31 and rm == 31:
                return f"CSET {reg_d}, {inv_cond_str}"
            # CSETM: CSINV Rd, XZR, XZR, inv_cond
            if op2 == 2 and rn == 31 and rm == 31:
                return f"CSETM {reg_d}, {inv_cond_str}"

            c_ops = ["CSEL", "CSINC", "CSINV", "CSNEG"]
            return f"{c_ops[op2]} {reg_d}, {reg_n}, {reg_m}, {cond_str}"

        # 18. STP / LDP (Load / Store Pair)
        if (insn & 0x3E400000) in (0x28000000, 0x29000000):
            opc = (insn >> 30) & 3
            is_fp = (insn & 0x04000000) != 0
            is_load = (insn & 0x00400000) != 0
            imm7 = (insn >> 15) & 0x7F
            if imm7 & 0x40:
                imm7 -= 0x80
            rt2 = (insn >> 10) & 0x1F
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            
            scale = 3 if opc == 2 else (2 if opc == 0 else 4)
            offset = imm7 << scale
            op = "LDP" if is_load else "STP"
            
            if is_fp:
                r_type = "D" if opc == 1 else ("S" if opc == 0 else "Q")
            else:
                r_type = "X" if opc == 2 else "W"
                
            reg_n = "SP" if rn == 31 else f"X{rn}"
            if offset == 0:
                return f"{op} {r_type}{rt}, {r_type}{rt2}, [{reg_n}]"
            return f"{op} {r_type}{rt}, {r_type}{rt2}, [{reg_n}, #{offset}]"

        # 19. LDR / STR (Immediate unsigned offset)
        if (insn & 0x3B000000) == 0x39000000:
            size = (insn >> 30) & 3
            is_fp = (insn & 0x04000000) != 0
            is_load = (insn & 0x00400000) != 0
            imm12 = (insn >> 10) & 0xFFF
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            offset = imm12 << size
            
            op_base = "LDR" if is_load else "STR"
            if is_fp:
                r_type = ["S", "D", "Q", "S"][size]
            else:
                r_type = "X" if size == 3 else "W"
                
            reg_n = "SP" if rn == 31 else f"X{rn}"
            if offset == 0:
                return f"{op_base} {r_type}{rt}, [{reg_n}]"
            return f"{op_base} {r_type}{rt}, [{reg_n}, #{offset}]"

        # 20. LDRB / STRB / LDRH / STRH
        if (insn & 0x3B000000) == 0x38000000:
            size = (insn >> 30) & 3
            is_load = (insn & 0x00400000) != 0
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            imm9 = (insn >> 12) & 0x1FF
            if imm9 & 0x100:
                imm9 -= 0x200
            
            sub_op = ["B", "H", "", ""][size]
            op = ("LDR" if is_load else "STR") + sub_op
            reg_n = "SP" if rn == 31 else f"X{rn}"
            return f"{op} W{rt}, [{reg_n}, #{imm9}]"

        # 21. LDR Literal (PC Relative)
        if (insn & 0x3B000000) == 0x18000000:
            is_fp = (insn & 0x04000000) != 0
            opc = (insn >> 30) & 3
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 -= 0x80000
            rt = insn & 0x1F
            target = pc + (imm19 << 2)
            r_type = "D" if (is_fp and opc == 1) else ("S" if is_fp else ("X" if opc == 1 else "W"))
            return f"LDR {r_type}{rt}, 0x{target:X}"

        # 22. FMOV (Floating-Point Move)
        if (insn & 0x5F200000) == 0x1E200000:
            rd = insn & 0x1F
            imm8 = (insn >> 13) & 0xFF
            # Decodificar float literal ARM64
            sign = (imm8 >> 7) & 1
            exp = ((imm8 >> 4) & 7) ^ 4
            mant = imm8 & 0xF
            val = (1.0 + mant / 16.0) * (2 ** (exp - 3))
            if sign: val = -val
            return f"FMOV S{rd}, #{val}"

        # 23. FMOV Register (Int <-> Float conversion / move)
        if (insn & 0x5F200000) == 0x1E260000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            return f"FMOV S{rd}, W{rn}"
        if (insn & 0x5F200000) == 0x1E270000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            return f"FMOV W{rd}, S{rn}"

        # 24. Floating Point Arithmetic (FADD, FSUB, FMUL, FDIV, FCMP, FABS, FNEG)
        if (insn & 0x5F200000) == 0x1E200000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            rm = (insn >> 16) & 0x1F
            opc = (insn >> 12) & 0xF
            fp_ops = {
                0x0: "FMUL", 0x1: "FDIV", 0x2: "FADD", 0x3: "FSUB",
                0x4: "FMAX", 0x5: "FMIN", 0x8: "FNMUL"
            }
            if opc in fp_ops:
                return f"{fp_ops[opc]} S{rd}, S{rn}, S{rm}"

        return f".inst 0x{insn:08X}"

    @classmethod
    def disassemble_function(cls, raw_bytes: bytes, start_pc: int = 0, max_instructions: int = 40) -> List[Dict[str, Any]]:
        """Desensambla una secuencia de bytes hasta encontrar RET o el límite de instrucciones"""
        disasm_list = []
        for i in range(0, min(len(raw_bytes), max_instructions * 4) - 3, 4):
            chunk = raw_bytes[i:i+4]
            pc = start_pc + i
            asm_text = cls.decode_instruction(chunk, pc)
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            
            is_ret = asm_text.startswith("RET")
            is_branch = any(asm_text.startswith(p) for p in ("B ", "BL ", "CBZ", "CBNZ", "TBZ", "TBNZ", "B."))
            is_call = asm_text.startswith("BL ") or asm_text.startswith("BLR ")
            
            disasm_list.append({
                "offset": f"0x{pc:08X}",
                "offset_rel": f"+0x{i:X}",
                "bytes": hex_str,
                "asm": asm_text,
                "is_ret": is_ret,
                "is_branch": is_branch,
                "is_call": is_call
            })
            
            if is_ret and len(disasm_list) >= 4:
                break

        return disasm_list


class SimpleARM32Disassembler:
    @classmethod
    def decode_instruction(cls, insn_bytes: bytes, pc: int = 0) -> str:
        if len(insn_bytes) < 4:
            return "??"
        insn, = struct.unpack('<I', insn_bytes[:4])
        
        # NOP
        if insn == 0xE320F000:
            return "NOP"
        # BX LR
        if insn == 0xE12FFF1E:
            return "BX LR"
        # MOV R0, #1 / #0
        if (insn & 0xFFFFF000) == 0xE3A00000:
            rd = (insn >> 12) & 0xF
            imm = insn & 0xFF
            return f"MOV R{rd}, #{imm}"
        # PUSH {r4-r7, lr}
        if (insn & 0xFFFF0000) == 0xE92D0000:
            regs = [f"R{i}" for i in range(16) if (insn & (1 << i))]
            return f"PUSH {{{', '.join(regs)}}}"
        # POP {r4-r7, pc}
        if (insn & 0xFFFF0000) == 0xE8BD0000:
            regs = [f"R{i}" if i != 15 else "PC" for i in range(16) if (insn & (1 << i))]
            return f"POP {{{', '.join(regs)}}}"
        # B / BL
        if (insn & 0x0E000000) == 0x0A000000:
            is_bl = (insn & 0x01000000) != 0
            imm24 = insn & 0x00FFFFFF
            if imm24 & 0x00800000:
                imm24 -= 0x01000000
            target = pc + 8 + (imm24 << 2)
            op = "BL" if is_bl else "B"
            return f"{op} 0x{target:X}"

        return f".inst 0x{insn:08X}"


class FunctionAnalyzer:
    @classmethod
    def analyze(cls, disasm_instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not disasm_instructions:
            return {"summary": "Sin instrucciones", "heuristic": "Desconocido", "callees": []}

        first_few = [d["asm"] for d in disasm_instructions[:8]]
        first_few_str = " \n ".join(first_few)
        
        callees = []
        for d in disasm_instructions:
            text = d["asm"]
            if text.startswith("BL 0x") or text.startswith("B 0x"):
                parts = text.split()
                if len(parts) >= 2 and parts[1].startswith("0x"):
                    callees.append(parts[1])

        # 1. Heurística: Retorna Bool True (MOV W0, #1 + RET)
        if "MOV W0, #1" in first_few_str and ("RET" in first_few_str or "BX LR" in first_few_str):
            return {
                "summary": "Retorna constante True (bool = 1)",
                "heuristic": "RETURN_TRUE_CONST",
                "return_type": "bool",
                "const_value": "true",
                "callees": callees
            }

        # 2. Heurística: Retorna Bool False / 0 (MOV W0, #0 / MOV X0, #0 + RET)
        if ("MOV W0, #0" in first_few_str or "MOV X0, #0" in first_few_str) and "RET" in first_few_str:
            return {
                "summary": "Retorna constante False / Cero (0)",
                "heuristic": "RETURN_ZERO_CONST",
                "return_type": "bool / int / ptr",
                "const_value": "0 / false",
                "callees": callees
            }

        # 3. Heurística: Retorna Float Constante (FMOV S0, #val + RET)
        if "FMOV S0, #" in first_few_str and "RET" in first_few_str:
            f_val = first_few_str.split("FMOV S0, #")[1].split()[0]
            return {
                "summary": f"Retorna Float literal ({f_val})",
                "heuristic": "RETURN_FLOAT_CONST",
                "return_type": "float",
                "const_value": f_val,
                "callees": callees
            }

        # 4. Heurística: Getter de Campo (LDR W0/X0/S0, [X0, #offset] + RET)
        if len(disasm_instructions) <= 4 and ("LDR" in first_few_str) and ("[X0" in first_few_str or "[X1" in first_few_str):
            for d in disasm_instructions:
                if d["asm"].startswith("LDR") and "[X0" in d["asm"]:
                    return {
                        "summary": f"Getter de Propiedad ({d['asm']})",
                        "heuristic": "PROPERTY_GETTER",
                        "field_access": d["asm"],
                        "callees": callees
                    }

        # 5. Heurística: Setter de Campo (STR W1/X1/S1, [X0, #offset] + RET)
        if len(disasm_instructions) <= 5 and ("STR" in first_few_str) and "[X0" in first_few_str:
            for d in disasm_instructions:
                if d["asm"].startswith("STR") and "[X0" in d["asm"]:
                    return {
                        "summary": f"Setter de Propiedad ({d['asm']})",
                        "heuristic": "PROPERTY_SETTER",
                        "field_access": d["asm"],
                        "callees": callees
                    }

        # 6. Heurística: Función Vacía / Stub (RET directo o NOP + RET)
        if disasm_instructions[0]["asm"] == "RET" or (len(disasm_instructions) <= 2 and disasm_instructions[-1]["asm"] == "RET"):
            return {
                "summary": "Método Vacío / Stub (RET inmediato)",
                "heuristic": "VOID_STUB",
                "return_type": "void",
                "callees": callees
            }

        # 7. Heurística: Forwarder / Wrapper (Inmediatamente salta o llama a otra dirección)
        if len(callees) > 0 and len(disasm_instructions) <= 6:
            return {
                "summary": f"Wrapper / Llamada directa a {callees[0]}",
                "heuristic": "FORWARDER",
                "callees": callees
            }

        return {
            "summary": f"Función Normal ({len(disasm_instructions)} instrucciones, {len(callees)} llamadas)",
            "heuristic": "STANDARD_FUNCTION",
            "callees": callees
        }
