import os
import re
import json
from typing import Dict, Any, List
from core.pattern_scanner import PatternScanner

class VersionMigrator:
    def __init__(self, pattern_scanner: PatternScanner):
        self.scanner = pattern_scanner

    def migrate_header_file(self, header_filepath: str, aob_mapping: Dict[str, str], output_filepath: str) -> Dict[str, Any]:
        if not os.path.exists(header_filepath):
            return {"error": f"Archivo {header_filepath} no encontrado."}

        with open(header_filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        updated_count = 0
        log = []

        # Buscar patrones #define OFFSET_NAME 0x...
        def replace_offset(match):
            nonlocal updated_count
            define_name = match.group(1)
            old_hex = match.group(2)
            
            # Buscar si tenemos un AOB pattern para este nombre o prefijo
            pattern = aob_mapping.get(define_name) or aob_mapping.get(define_name.replace("OFFSET_", ""))
            if pattern:
                matches = self.scanner.scan_pattern(pattern, max_results=1)
                if matches:
                    new_hex = matches[0]["address_hex_upper"]
                    log.append(f"[MIGRADO] {define_name}: {old_hex} -> {new_hex}")
                    updated_count += 1
                    return f"#define {define_name} {new_hex}"
            
            log.append(f"[SIN CAMBIO] {define_name}: {old_hex}")
            return match.group(0)

        new_content = re.sub(r'#define\s+([A-Za-z0-9_]+)\s+(0x[0-9A-Fa-f]+)', replace_offset, content)

        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)

        return {
            "total_updated": updated_count,
            "log": log,
            "output_file": output_filepath
        }

    def migrate_json_profile(self, profile_filepath: str, output_filepath: str) -> Dict[str, Any]:
        """
        Actualiza un archivo JSON de perfil de hacks escaneando todas las firmas AOB.
        """
        if not os.path.exists(profile_filepath):
            return {"error": f"Archivo {profile_filepath} no encontrado."}

        with open(profile_filepath, 'r', encoding='utf-8') as f:
            profiles = json.load(f)

        updated_results = self.scanner.batch_update_offsets(profiles)

        with open(output_filepath, 'w', encoding='utf-8') as f:
            json.dump(updated_results, f, indent=2)

        return {
            "total": len(profiles),
            "updated": sum(1 for u in updated_results if u.get("status") == "ACTUALIZADO"),
            "output_file": output_filepath
        }
