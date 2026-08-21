import struct
from typing import List, Dict, Any, Optional
from core.il2cpp_parser import Il2CppParser
from core.binary_reader import BinaryReader

class XRefEngine:
    def __init__(self, parser: Il2CppParser, binary_reader: Optional[BinaryReader] = None):
        self.parser = parser
        self.binary = binary_reader

    def set_binary(self, binary_reader: BinaryReader):
        self.binary = binary_reader

    def find_string_xrefs(self, search_text: str, max_results: int = 60) -> List[Dict[str, Any]]:
        return self.parser.search_strings(search_text, max_results=max_results)

    def find_class_members(self, class_name: str) -> Dict[str, Any]:
        """Retorna todos los métodos y campos pertenecientes a una clase"""
        methods = [m for m in self.parser.methods if (m.get("Class") == class_name or f"{class_name}$$" in m.get("Name", ""))]
        fields = self.parser.get_class_fields(class_name)
        struct_layout = self.parser.generate_struct_layout(class_name)

        return {
            "class_name": class_name,
            "methods_count": len(methods),
            "methods": [self.parser._format_method(m) for m in methods],
            "fields_count": len(fields),
            "fields": fields,
            "struct_layout": struct_layout
        }

    def find_caller_xrefs(self, target_vaddr: int, max_results: int = 30) -> List[Dict[str, Any]]:
        """
        Escanea el binario buscando llamadas directas (BL / B) hacia target_vaddr.
        """
        if not self.binary or not self.binary.mm:
            return []

        callers = []
        mm = self.binary.mm
        filesize = self.binary.filesize

        # Buscar en los segmentos de código
        for seg_name, vmaddr, vmsize, fileoff, seg_filesize in self.binary.segments:
            if "text" in seg_name.lower() or "load" in seg_name.lower() or seg_name == "RAW":
                limit = min(fileoff + seg_filesize, filesize) - 3
                for off in range(fileoff, limit, 4):
                    chunk = mm[off:off+4]
                    insn, = struct.unpack('<I', chunk)
                    pc = vmaddr + (off - fileoff)

                    # ARM64: BL / B (0x14000000 / 0x94000000)
                    if (insn & 0x7C000000) == 0x14000000:
                        is_bl = (insn & 0x80000000) != 0
                        imm26 = insn & 0x03FFFFFF
                        if imm26 & 0x02000000:
                            imm26 -= 0x04000000
                        call_target = pc + (imm26 << 2)

                        if call_target == target_vaddr:
                            # Resolver si el llamador corresponde a algún método conocido
                            caller_method = self.parser.get_method_by_address(pc)
                            callers.append({
                                "caller_vaddr": pc,
                                "caller_vaddr_hex": f"0x{pc:08X}",
                                "type": "BL (Llamada)" if is_bl else "B (Salto)",
                                "file_offset": hex(off),
                                "method_info": caller_method
                            })
                            if len(callers) >= max_results:
                                return callers

        return callers
