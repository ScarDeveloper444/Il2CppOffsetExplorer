import json
import os
import re
import time
from collections import defaultdict
from typing import List, Dict, Any, Optional, Set, Tuple

class Il2CppParser:
    CATEGORIES = {
        "AIM": [
            "aim", "autoaim", "aimassist", "aiming", "target", "headshot", "crosshair", 
            "sight", "lookat", "fov", "bullettrack", "silentaim", "aimbot", "locktarget"
        ],
        "DAMAGE": [
            "damage", "takedamage", "hitpoint", "calc_damage", "attackdamage", "hurtdamage", 
            "bulletdamage", "criticaldamage", "damagemultiplier", "applydamage", "hurt"
        ],
        "HP": [
            "health", "godmode", "isdead", "isalive", "immortal", "heal", "shield", 
            "armor", "maxhp", "currenthp", "invulnerable", "revive", "autorevive"
        ],
        "SPEED": [
            "speed", "movespeed", "walkspeed", "runspeed", "velocity", "fly", "dash", 
            "jumpheight", "speedmultiplier", "swimspeed", "climbspeed", "gravity"
        ],
        "RECOIL": [
            "recoil", "norecoil", "spread", "nospread", "firerate", "ammo", "reload", 
            "gunrecoil", "crosshairspread", "infinitammo", "rapidfire", "bulletdrop"
        ],
        "ESP": [
            "isvisible", "render", "outline", "chams", "drawbox", "camera", "glow", 
            "visibility", "worldtoscreen", "esp", "boundingbox", "skeleton", "playername"
        ],
        "ANTICHEAT": [
            "cheat", "detect", "ban", "security", "protect", "verify", "integrity", 
            "anticheat", "hook", "crc", "root", "jailbreak", "emulator", "tamper", "signature"
        ],
        "ITEMS_SKINS": [
            "diamond", "gold", "coin", "skin", "item", "inventory", "bundle", "weapon",
            "unlock", "shop", "purchase", "free", "cost", "price", "vip", "pass"
        ],
        "VEHICLES_PHYSICS": [
            "vehicle", "car", "drive", "physics", "collision", "water", "underwater",
            "teleport", "position", "transform", "motor", "wheel"
        ]
    }

    def __init__(self):
        self.methods: List[Dict[str, Any]] = []
        self.strings: List[Dict[str, Any]] = []
        self.metadata_methods: List[Dict[str, Any]] = []
        self.string_literals: List[Dict[str, Any]] = []
        
        # Estructuras y campos de clases
        self.class_fields: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.class_names: Set[str] = set()

        # Índices de alta velocidad
        self.addr_to_method: Dict[int, Dict[str, Any]] = {}
        self.token_index: Dict[str, List[int]] = defaultdict(list)
        self.acronym_index: Dict[str, List[int]] = defaultdict(list)
        
        self.loaded_sources = {"dump_cs": False, "script_json": False, "string_json": False, "il2cpp_h": False}
        self.source_paths = {"dump_cs": "", "script_json": "", "string_json": "", "il2cpp_h": ""}

    def _split_words(self, text: str) -> List[str]:
        """Divide camelCase, PascalCase, símbolos y números en palabras clave normalizadas"""
        return [w.lower() for w in re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\W|$)|[0-9]+', text) if len(w) >= 2]

    def _get_acronym(self, text: str) -> str:
        """Genera el acrónimo de un nombre (e.g. 'TakeDamage' -> 'td', 'FireBullet' -> 'fb')"""
        capitals = re.findall(r'[A-Z]', text)
        if len(capitals) >= 2:
            return "".join(capitals).lower()
        return ""

    def _build_inverted_index(self):
        """Construye el índice invertido de tokens y acrónimos para búsquedas instantáneas"""
        self.token_index.clear()
        self.acronym_index.clear()
        
        for idx, m in enumerate(self.methods):
            name = m.get("Name", "")
            tokens = set(self._split_words(name))
            for t in tokens:
                self.token_index[t].append(idx)

            # Acrónimo
            clean_m = name.split("$$")[-1] if "$$" in name else name.split(".")[-1]
            acr = self._get_acronym(clean_m)
            if acr and len(acr) >= 2:
                self.acronym_index[acr].append(idx)

    def load_dump_cs(self, filepath: str, progress_callback=None) -> int:
        """
        Parsea el archivo dump.cs extrayendo:
        - RVA, Métodos, Firmas y Parámetros
        - Clases y Namespaces
        - Campos de Clase con sus Offsets de memoria (// 0x58)
        """
        if not os.path.exists(filepath):
            return 0

        if progress_callback: progress_callback("Parseando dump.cs (RVA, Clases, Campos y Métodos)...")
        
        rva_pattern = re.compile(r'//\s+RVA:\s+(0x[0-9A-Fa-f]+)\s+Offset:\s+(0x[0-9A-Fa-f]+)')
        class_pattern = re.compile(r'public\s+(?:abstract\s+|sealed\s+|static\s+)?(?:class|struct|interface)\s+([A-Za-z0-9_<>`]+)')
        field_pattern = re.compile(r'(?:public|private|protected|internal)\s+([A-Za-z0-9_<>`\[\],\s\*]+)\s+([A-Za-z0-9_]+);\s*//\s*(0x[0-9A-Fa-f]+)')

        new_methods = []
        current_class = "Global"
        current_namespace = ""

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_s = line.strip()
                if line_s.startswith('// Namespace:'):
                    current_namespace = line_s.replace('// Namespace:', '').strip()
                elif ' class ' in line_s or ' struct ' in line_s or ' interface ' in line_s:
                    m_c = class_pattern.search(line_s)
                    if m_c:
                        current_class = m_c.group(1)
                        self.class_names.add(current_class)
                elif '// 0x' in line_s and ';' in line_s:
                    # Capturar campo de clase con su offset
                    m_f = field_pattern.search(line_s)
                    if m_f:
                        f_type = m_f.group(1).strip()
                        f_name = m_f.group(2).strip()
                        f_off_str = m_f.group(3).strip()
                        try:
                            f_off_int = int(f_off_str, 16)
                            self.class_fields[current_class].append({
                                "name": f_name,
                                "type": f_type,
                                "offset": f_off_int,
                                "offset_hex": f_off_str,
                                "class": current_class
                            })
                        except Exception:
                            pass
                elif line_s.startswith('// RVA: 0x'):
                    m_rva = rva_pattern.search(line_s)
                    if m_rva:
                        rva_str = m_rva.group(1)
                        sig = f.readline().strip()
                        
                        clean_m_name = sig
                        if '(' in sig:
                            before_paren = sig.split('(')[0].strip()
                            clean_m_name = before_paren.split()[-1] if before_paren.split() else sig

                        full_name = f"{current_class}$${clean_m_name}" if current_class != "Global" else clean_m_name
                        addr_int = int(rva_str, 16)

                        item = {
                            "Address": addr_int,
                            "Name": full_name,
                            "Signature": sig,
                            "TypeSignature": "",
                            "Source": "dump.cs",
                            "Class": current_class,
                            "Namespace": current_namespace
                        }
                        new_methods.append(item)
                        if addr_int not in self.addr_to_method:
                            self.addr_to_method[addr_int] = item

        if not self.methods:
            self.methods = new_methods
        else:
            existing_addrs = set(self.addr_to_method.keys())
            for m in new_methods:
                if m["Address"] not in existing_addrs:
                    self.methods.append(m)
                    self.addr_to_method[m["Address"]] = m

        self.loaded_sources["dump_cs"] = True
        self.source_paths["dump_cs"] = filepath
        self._build_inverted_index()
        return len(new_methods)

    def load_script_json(self, filepath: str, progress_callback=None) -> Dict[str, int]:
        if not os.path.exists(filepath):
            return {}

        if progress_callback: progress_callback("Indexando script.json...")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)

        s_methods = data.get("ScriptMethod", [])
        self.strings = data.get("ScriptString", [])
        self.metadata_methods = data.get("ScriptMetadataMethod", [])

        for m in s_methods:
            m["Source"] = "script.json"
            addr = m.get("Address", 0)
            if addr:
                self.addr_to_method[addr] = m

        self.methods = s_methods
        self.loaded_sources["script_json"] = True
        self.source_paths["script_json"] = filepath
        self._build_inverted_index()

        return {
            "methods": len(self.methods),
            "strings": len(self.strings),
            "metadata_methods": len(self.metadata_methods)
        }

    def load_stringliteral_json(self, filepath: str) -> int:
        if not os.path.exists(filepath):
            return 0
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            self.string_literals = json.load(f)
        self.loaded_sources["string_json"] = True
        self.source_paths["string_json"] = filepath
        return len(self.string_literals)

    def get_class_fields(self, class_name: str) -> List[Dict[str, Any]]:
        """Retorna la lista de campos con sus offsets para una clase dada"""
        fields = self.class_fields.get(class_name, [])
        return sorted(fields, key=lambda x: x["offset"])

    def generate_struct_layout(self, class_name: str) -> str:
        fields = self.get_class_fields(class_name)
        if not fields:
            return f"struct {class_name} {{\n    void* __this;\n}};"

        lines = [
            f"#pragma once",
            f"#include <cstdint>",
            f"",
            f"#pragma pack(push, 1)",
            f"struct {class_name}_Fields {{",
        ]

        current_offset = 0
        for f in fields:
            f_off = f["offset"]
            f_type = f["type"]
            f_name = f["name"]

            cpp_type = "uint8_t"
            size = 1
            if f_type in ("int", "System.Int32"):
                cpp_type = "int32_t"; size = 4
            elif f_type in ("float", "System.Single"):
                cpp_type = "float"; size = 4
            elif f_type in ("bool", "System.Boolean"):
                cpp_type = "bool"; size = 1
            elif f_type in ("long", "System.Int64"):
                cpp_type = "int64_t"; size = 8
            elif f_type in ("uint", "System.UInt32"):
                cpp_type = "uint32_t"; size = 4
            elif "Vector3" in f_type:
                cpp_type = "Vector3"; size = 12
            elif "Quaternion" in f_type:
                cpp_type = "Vector4"; size = 16
            elif "*" in f_type or "." in f_type or f_type.startswith("System."):
                cpp_type = "void*"; size = 8

            if f_off > current_offset:
                pad_size = f_off - current_offset
                lines.append(f"    uint8_t pad_0x{current_offset:X}[0x{pad_size:X}];")
                current_offset = f_off

            lines.append(f"    {cpp_type} {f_name}; // 0x{f_off:X}")
            current_offset += size

        lines.append(f"}};\n#pragma pack(pop)")
        return "\n".join(lines)

    def generate_csharp_struct_layout(self, class_name: str) -> str:
        fields = self.get_class_fields(class_name)
        if not fields:
            return f"public class {class_name} {{\n}}"

        lines = [
            f"using System;",
            f"using System.Runtime.InteropServices;",
            f"",
            f"[StructLayout(LayoutKind.Explicit)]",
            f"public struct {class_name}_Fields",
            f"{{",
        ]

        for f in fields:
            f_off = f["offset"]
            f_type = f["type"]
            f_name = f["name"]

            cs_type = "IntPtr"
            if f_type in ("int", "System.Int32"):
                cs_type = "int"
            elif f_type in ("float", "System.Single"):
                cs_type = "float"
            elif f_type in ("bool", "System.Boolean"):
                cs_type = "bool"
            elif f_type in ("long", "System.Int64"):
                cs_type = "long"
            elif f_type in ("uint", "System.UInt32"):
                cs_type = "uint"

            lines.append(f"    [FieldOffset(0x{f_off:X})]")
            lines.append(f"    public {cs_type} {f_name};")
            lines.append("")

        lines.append(f"}}")
        return "\n".join(lines)

    def _score_method(self, m: Dict[str, Any], query: str, query_words: List[str]) -> int:
        """Calcula una puntuación de relevancia para ordenar los resultados de forma inteligente"""
        score = 0
        name = m.get("Name", "")
        name_lower = name.lower()
        q_lower = query.lower()
        
        # Extraer método limpio
        clean_name = name.split("$$")[-1].lower() if "$$" in name else name.split(".")[-1].lower()

        # Coincidencia Exacta
        if clean_name == q_lower:
            score += 1000
        elif name_lower == q_lower:
            score += 800
        elif clean_name.startswith(q_lower):
            score += 500
        elif q_lower in clean_name:
            score += 300
        elif q_lower in name_lower:
            score += 150

        # Multi-token bonus
        for w in query_words:
            if w == clean_name:
                score += 200
            elif clean_name.startswith(w):
                score += 100
            elif w in clean_name:
                score += 50
            elif w in name_lower:
                score += 20

        sig = m.get("Signature", "").lower()
        if q_lower in sig:
            score += 25

        return score

    def search_methods_advanced(
        self, 
        query: str, 
        max_results: int = 150, 
        search_type: str = "all", 
        return_type_filter: str = "ALL",
        access_filter: str = "ALL"
    ) -> Tuple[List[Dict[str, Any]], float]:
        """
        Búsqueda avanzada con scoring de relevancia, acrónimos, filtros de tipo de retorno y cronómetro.
        """
        t0 = time.perf_counter()
        if not self.methods or not query:
            return [], 0.0

        query = query.strip()
        matched_candidates = []

        # 1. Búsqueda por dirección directa (0x1234 o rango)
        if query.startswith("0x") or query.startswith("0X"):
            if ".." in query or "-" in query:
                parts = query.replace("..", "-").split("-")
                try:
                    start_addr = int(parts[0].strip(), 16)
                    end_addr = int(parts[1].strip(), 16)
                    for m in self.methods:
                        addr = m.get("Address", 0)
                        if start_addr <= addr <= end_addr:
                            matched_candidates.append(m)
                            if len(matched_candidates) >= max_results:
                                break
                    elapsed = (time.perf_counter() - t0) * 1000
                    return [self._format_method(m) for m in matched_candidates], elapsed
                except Exception:
                    pass

            try:
                target_addr = int(query, 16)
                if target_addr in self.addr_to_method:
                    elapsed = (time.perf_counter() - t0) * 1000
                    return [self._format_method(self.addr_to_method[target_addr])], elapsed
                
                hex_target = query[2:].lower()
                for m in self.methods:
                    addr_hex = hex(m.get("Address", 0))[2:].lower()
                    if hex_target in addr_hex:
                        matched_candidates.append(m)
                        if len(matched_candidates) >= max_results:
                            break
                elapsed = (time.perf_counter() - t0) * 1000
                return [self._format_method(m) for m in matched_candidates], elapsed
            except ValueError:
                pass
        elif query.isdigit():
            target_addr = int(query)
            if target_addr in self.addr_to_method:
                elapsed = (time.perf_counter() - t0) * 1000
                return [self._format_method(self.addr_to_method[target_addr])], elapsed

        # 2. Búsqueda Regex (r/pattern/)
        if query.startswith("r/") or query.startswith("R/"):
            regex_str = query[2:].rstrip("/")
            try:
                rx = re.compile(regex_str, re.IGNORECASE)
                for m in self.methods:
                    if rx.search(m.get("Name", "")) or rx.search(m.get("Signature", "")):
                        matched_candidates.append(m)
                        if len(matched_candidates) >= max_results:
                            break
                elapsed = (time.perf_counter() - t0) * 1000
                return [self._format_method(m) for m in matched_candidates], elapsed
            except re.error:
                pass

        # 3. Búsqueda por Acrónimo (e.g. 'TD' -> TakeDamage)
        q_clean = query.lower()
        if len(query) in (2, 3) and q_clean in self.acronym_index:
            for idx in self.acronym_index[q_clean]:
                matched_candidates.append(self.methods[idx])

        # 4. Búsqueda Multi-Token Invertida
        query_words = self._split_words(query)
        if query_words and self.token_index:
            matched_indices = None
            for w in query_words:
                matching_keys = [k for k in self.token_index if k == w or k.startswith(w)]
                if matching_keys:
                    hits = set()
                    for k in matching_keys:
                        hits.update(self.token_index[k])
                    if matched_indices is None:
                        matched_indices = hits
                    else:
                        matched_indices &= hits
                else:
                    matched_indices = set()
                    break

            if matched_indices:
                matched_candidates = [self.methods[idx] for idx in matched_indices]

        # 5. Fallback lineal si no hubo tokens
        if not matched_candidates:
            q_lower = query.lower()
            for m in self.methods:
                name = m.get("Name", "")
                sig = m.get("Signature", "")
                
                matched = False
                if search_type == "name" and q_lower in name.lower():
                    matched = True
                elif search_type == "signature" and q_lower in sig.lower():
                    matched = True
                elif search_type == "class":
                    c_name = m.get("Class") or (name.split("$$")[0] if "$$" in name else name.rsplit(".", 1)[0])
                    if q_lower in c_name.lower():
                        matched = True
                elif search_type == "all":
                    if q_lower in name.lower() or q_lower in sig.lower():
                        matched = True

                if matched:
                    matched_candidates.append(m)
                    if len(matched_candidates) >= max_results * 3:
                        break

        # 6. Aplicar Filtros de Tipo de Retorno y Acceso
        filtered = []
        for m in matched_candidates:
            sig = m.get("Signature", "")
            name = m.get("Name", "")

            # Filtro de tipo de retorno
            if return_type_filter != "ALL":
                sig_lower = sig.lower()
                if return_type_filter == "BOOL" and not ("bool " in sig_lower or "boolean" in sig_lower):
                    continue
                elif return_type_filter == "FLOAT" and not ("float " in sig_lower or "single" in sig_lower or "double" in sig_lower):
                    continue
                elif return_type_filter == "INT" and not ("int " in sig_lower or "int32" in sig_lower or "int64" in sig_lower):
                    continue
                elif return_type_filter == "VOID" and not ("void " in sig_lower):
                    continue
                elif return_type_filter == "VECTOR3" and not ("vector3" in sig_lower):
                    continue

            # Filtro de acceso (Getters / Setters / Static)
            if access_filter == "GETTERS" and not ("get_" in name or "get_" in sig):
                continue
            elif access_filter == "SETTERS" and not ("set_" in name or "set_" in sig):
                continue
            elif access_filter == "STATIC" and not ("static " in sig.lower()):
                continue

            filtered.append(m)

        # 7. Ordenar por Puntuación de Relevancia
        scored_results = []
        for m in filtered:
            score = self._score_method(m, query, query_words)
            scored_results.append((score, m))

        scored_results.sort(key=lambda x: x[0], reverse=True)
        final_list = [self._format_method(item[1]) for item in scored_results[:max_results]]
        
        elapsed = (time.perf_counter() - t0) * 1000
        return final_list, elapsed

    def search_methods(self, query: str, max_results: int = 150, search_type: str = "all") -> List[Dict[str, Any]]:
        res, _ = self.search_methods_advanced(query, max_results=max_results, search_type=search_type)
        return res

    def search_category(self, category_key: str, max_results: int = 150) -> List[Dict[str, Any]]:
        keywords = self.CATEGORIES.get(category_key.upper(), [])
        if not keywords:
            return []

        matched_indices = set()
        for kw in keywords:
            kw = kw.lower()
            for k in self.token_index:
                if k == kw or k.startswith(kw):
                    matched_indices.update(self.token_index[k])

        results = []
        for idx in list(matched_indices)[:max_results]:
            results.append(self._format_method(self.methods[idx]))
        return results

    def search_strings(self, query: str, max_results: int = 80) -> List[Dict[str, Any]]:
        if not query:
            return []
        q_lower = query.lower()
        results = []

        for item in self.string_literals:
            val = item.get("value", "")
            if q_lower in val.lower():
                addr_str = item.get("address", "0")
                addr_int = int(addr_str, 16) if isinstance(addr_str, str) and addr_str.startswith("0x") else int(addr_str)
                results.append({
                    "type": "Literal (stringliteral.json)",
                    "value": val,
                    "address_hex": hex(addr_int),
                    "address_hex_upper": f"0x{addr_int:08X}",
                    "address": addr_int
                })
                if len(results) >= max_results:
                    return results

        for item in self.strings:
            val = item.get("Value", "")
            if q_lower in val.lower():
                addr = item.get("Address", 0)
                results.append({
                    "type": "ScriptString (script.json)",
                    "value": val,
                    "address_hex": hex(addr),
                    "address_hex_upper": f"0x{addr:08X}",
                    "address": addr
                })
                if len(results) >= max_results:
                    break

        return results

    def get_method_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        m = self.addr_to_method.get(address)
        if m:
            return self._format_method(m)
        return None

    def _format_method(self, m: Dict[str, Any]) -> Dict[str, Any]:
        addr = m.get("Address", 0)
        raw_name = m.get("Name", "")
        
        class_name = m.get("Class", "")
        clean_method = raw_name
        if "$$" in raw_name:
            parts = raw_name.split("$$")
            class_name = parts[0]
            clean_method = parts[1]
        elif "." in raw_name and not class_name:
            parts = raw_name.rsplit(".", 1)
            class_name = parts[0]
            clean_method = parts[1]

        has_fields = class_name in self.class_fields
        field_count = len(self.class_fields.get(class_name, []))

        return {
            "address": addr,
            "address_hex": hex(addr),
            "address_hex_upper": f"0x{addr:08X}",
            "name": raw_name,
            "clean_name": clean_method,
            "class_name": class_name,
            "signature": m.get("Signature", ""),
            "type_signature": m.get("TypeSignature", ""),
            "source": m.get("Source", "Il2Cpp"),
            "has_fields": has_fields,
            "field_count": field_count
        }
