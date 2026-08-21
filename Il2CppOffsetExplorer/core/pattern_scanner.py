import re
import os
import json
from typing import List, Dict, Any, Optional, Callable
from core.binary_reader import BinaryReader
from core.aob_engine import AOBEngine

class PatternScanner:
    def __init__(self, binary_reader: Optional[BinaryReader] = None):
        self.binary = binary_reader

    def set_binary(self, binary_reader: BinaryReader):
        self.binary = binary_reader

    def scan_pattern(self, aob_pattern: str, max_results: int = 60) -> List[Dict[str, Any]]:
        if not self.binary or not self.binary.mm:
            return []

        regex_bytes = AOBEngine.aob_to_regex(aob_pattern)
        if not regex_bytes:
            return []

        results = []
        try:
            for match in re.finditer(regex_bytes, self.binary.mm):
                file_off = match.start()
                vaddr = self.binary.file_offset_to_vaddr(file_off)
                matched_bytes = bytes(self.binary.mm[file_off:file_off + min(16, len(self.binary.mm) - file_off)])
                
                results.append({
                    "address": vaddr,
                    "address_hex": hex(vaddr),
                    "address_hex_upper": f"0x{vaddr:08X}",
                    "file_offset": file_off,
                    "file_offset_hex": hex(file_off),
                    "matched_bytes_hex": AOBEngine.bytes_to_aob(matched_bytes)
                })
                
                if len(results) >= max_results:
                    break
        except Exception as e:
            print(f"Error durante el escaneo: {e}")

        return results

    def batch_update_offsets(self, offset_profiles: List[Dict[str, Any]], progress_callback: Optional[Callable[[int, int], None]] = None) -> List[Dict[str, Any]]:
        """
        Escanea y actualiza por lotes una lista de funciones/hacks.
        Calcula también la diferencia de desplazamiento (Delta shift).
        """
        if not self.binary:
            return []

        updated_results = []
        total = len(offset_profiles)

        for idx, item in enumerate(offset_profiles):
            if progress_callback:
                progress_callback(idx + 1, total)

            name = item.get("name", "Unknown")
            pattern = item.get("pattern", "")
            old_addr_str = str(item.get("old_address", item.get("offset_hex", "0")))
            
            try:
                old_addr_int = int(old_addr_str, 16) if old_addr_str.startswith("0x") or old_addr_str.startswith("0X") else int(old_addr_str)
            except Exception:
                old_addr_int = 0

            if not pattern:
                updated_results.append({
                    "name": name,
                    "old_address": old_addr_str,
                    "new_address": "N/A",
                    "new_address_hex": "N/A",
                    "delta": "N/A",
                    "status": "SIN_PATRON",
                    "matches_count": 0,
                    "pattern": ""
                })
                continue

            matches = self.scan_pattern(pattern, max_results=5)
            if len(matches) == 1:
                m = matches[0]
                new_vaddr = m["address"]
                delta = new_vaddr - old_addr_int if old_addr_int > 0 else 0
                delta_str = f"+0x{delta:X}" if delta >= 0 else f"-0x{-delta:X}"

                updated_results.append({
                    "name": name,
                    "old_address": old_addr_str,
                    "new_address": new_vaddr,
                    "new_address_hex": m["address_hex_upper"],
                    "delta": delta_str,
                    "status": "ACTUALIZADO",
                    "matches_count": 1,
                    "pattern": pattern
                })
            elif len(matches) > 1:
                updated_results.append({
                    "name": name,
                    "old_address": old_addr_str,
                    "new_address": matches[0]["address_hex_upper"],
                    "new_address_hex": matches[0]["address_hex_upper"],
                    "delta": "MULTIPLE",
                    "status": f"MULTIPLES ({len(matches)})",
                    "matches_count": len(matches),
                    "pattern": pattern
                })
            else:
                updated_results.append({
                    "name": name,
                    "old_address": old_addr_str,
                    "new_address": "NO_ENCONTRADO",
                    "new_address_hex": "NO_ENCONTRADO",
                    "delta": "N/A",
                    "status": "NO_ENCONTRADO",
                    "matches_count": 0,
                    "pattern": pattern
                })

        return updated_results
