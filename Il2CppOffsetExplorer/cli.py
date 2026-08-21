#!/usr/bin/env python3
"""
Auto Offset & AOB Finder Pro V3+ (CLI Edition)
Soporte directo para dump.cs, script.json, structs de clases, desensamblado ARM64/ARM32 y binario.
"""
import sys
import os
import argparse
import json
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.binary_reader import BinaryReader
from core.il2cpp_parser import Il2CppParser
from core.aob_engine import AOBEngine
from core.pattern_scanner import PatternScanner
from core.patch_generator import PatchGenerator
from core.xref_engine import XRefEngine
from core.migrator import VersionMigrator

def print_banner():
    print(r"""
===================================================================
    IL2CPP OFFSET EXPLORER
===================================================================
""")

def init_environment(folder_path="freefire", dump_cs=None, script_json=None, binary_path=None):
    parser = Il2CppParser()
    
    # 1. Cargar dump.cs si fue especificado
    if dump_cs and os.path.exists(dump_cs):
        t0 = time.time()
        c = parser.load_dump_cs(dump_cs)
        print(f"[+] dump.cs cargado: {c:,} metodos indexados ({time.time()-t0:.2f}s)")
    
    # 2. Cargar script.json si fue especificado
    if script_json and os.path.exists(script_json):
        t0 = time.time()
        s = parser.load_script_json(script_json)
        print(f"[+] script.json cargado: {s.get('methods', 0):,} metodos indexados ({time.time()-t0:.2f}s)")

    # 3. Si no se especificaron archivos individuales, buscar en la carpeta
    if not dump_cs and not script_json:
        if not os.path.exists(folder_path):
            parent_ff = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "freefire")
            if os.path.exists(parent_ff):
                folder_path = parent_ff

        if os.path.exists(folder_path):
            t0 = time.time()
            s_json = os.path.join(folder_path, "script.json")
            d_cs = os.path.join(folder_path, "dump.cs")
            str_json = os.path.join(folder_path, "stringliteral.json")
            if os.path.exists(s_json):
                parser.load_script_json(s_json)
            if os.path.exists(d_cs):
                parser.load_dump_cs(d_cs)
            if os.path.exists(str_json):
                parser.load_stringliteral_json(str_json)
            print(f"[+] Carpeta '{folder_path}' cargada: {len(parser.methods):,} metodos ({time.time()-t0:.2f}s)")

    # 4. Cargar Binario
    bin_reader = None
    if binary_path and os.path.exists(binary_path):
        bin_reader = BinaryReader(binary_path)
    else:
        for b in ["UnityFramework", "libil2cpp.so", "GameAssembly.dll"]:
            candidate = os.path.join(folder_path if os.path.exists(folder_path) else "", b)
            if os.path.exists(candidate):
                bin_reader = BinaryReader(candidate)
                break

    if bin_reader:
        info = bin_reader.get_info()
        print(f"[+] Binario cargado: {info['filename']} ({info['format']}, {info['filesize_mb']} MB, {info['arch']})")

    return parser, bin_reader

def interactive_menu(parser: Il2CppParser, bin_reader: BinaryReader):
    aob_engine = AOBEngine(bin_reader) if bin_reader else None
    scanner = PatternScanner(bin_reader) if bin_reader else None
    xref_eng = XRefEngine(parser, bin_reader) if (parser and bin_reader) else None

    while True:
        print("\n" + "="*55)
        print("  MENU PRINCIPAL (PRO V3+):")
        print("  1. Buscar metodos por nombre, clase, firma o acronimo")
        print("  2. Ver campos y C++ Struct Layout de una clase")
        print("  3. Buscar cadenas literales (String Literals)")
        print("  4. Generar firma AOB con desensamblado ARM64/ARM32")
        print("  5. Escanear firma AOB en el binario")
        print("  6. Generar codigo de parche / Hook")
        print("  7. Actualizacion por lotes (Batch Profile Update)")
        print("  8. Buscar llamadores en binario (Caller XRefs)")
        print("  0. Salir")
        print("="*55)
        
        choice = input("\nSelecciona una opcion [0-8]: ").strip()
        if choice == "0":
            break
        elif choice == "1":
            q = input("Introduce termino de busqueda (ej. TakeDamage, Aim, 0x157519C, TD): ").strip()
            if not q: continue
            results = parser.search_methods(q, max_results=15)
            print(f"\n[+] Resultados ({len(results)}):")
            for i, r in enumerate(results, 1):
                fields_info = f"[{r.get('field_count')} campos]" if r.get('has_fields') else ""
                print(f"  [{i}] {r['address_hex_upper']} | {r['name']} {fields_info} ({r.get('source', '')})")
            
            if results and aob_engine:
                sel = input("\nGenerar AOB para alguno? (1-15 o Enter para omitir): ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(results):
                    target = results[int(sel) - 1]
                    res = aob_engine.generate_aob(target['address'], length=24, mask_relative=True, ensure_unique=True)
                    print(f"\n[+] AOB Generado para {target['name']} ({target['address_hex_upper']}):")
                    print(f"    Patron: {res['active_pattern']}")
                    print(f"    Coincidencias: {res['matches_count']} (Unico: {res['is_unique']})")
                    if "analysis" in res:
                        print(f"    Analisis Estatico: {res['analysis'].get('summary')}")
                    print("\n    Desensamblado ARM64:")
                    for d in res.get("disassembly", []):
                        print(f"      {d['offset']}: {d['bytes']:<16} {d['asm']}")
        elif choice == "2":
            c_name = input("Introduce nombre de clase (ej. Player, Weapon): ").strip()
            if not c_name: continue
            struct_code = parser.generate_struct_layout(c_name)
            print(f"\n{struct_code}")
        elif choice == "3":
            q = input("Introduce texto de cadena a buscar: ").strip()
            if not q: continue
            results = parser.search_strings(q, max_results=15)
            for r in results:
                print(f"  {r['address_hex_upper']} | \"{r['value']}\"")
        elif choice == "4":
            if not aob_engine:
                print("[-] Binario no cargado.")
                continue
            addr_str = input("Introduce direccion (ej. 0x0157519C): ").strip()
            try:
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                res = aob_engine.generate_aob(addr, length=24, mask_relative=True, ensure_unique=True)
                print(f"\n[+] Patron AOB: {res['active_pattern']}")
                print(f"    Coincidencias: {res['matches_count']} (Unico: {res['is_unique']})")
                print(f"    IDA / Cheat Engine: {res['formats'].get('ida_cheat_engine')}")
                print(f"    C++ Mask: {res['formats'].get('cpp_mask')}")
            except Exception as e:
                print(f"[-] Error: {e}")
        elif choice == "5":
            if not scanner:
                print("[-] Binario no cargado.")
                continue
            pattern = input("Introduce firma AOB: ").strip()
            matches = scanner.scan_pattern(pattern, max_results=10)
            for m in matches:
                print(f"  Match: {m['address_hex_upper']} (Offset: {m['file_offset_hex']})")
        elif choice == "6":
            name = input("Nombre de funcion: ").strip() or "CustomHook"
            addr = input("Direccion (ej. 0x0157519C): ").strip() or "0x0157519C"
            templates = PatchGenerator.generate_templates(name, addr, "20 00 80 D2 C0 03 5F D6")
            print("\n--- iOS Dylib Hook ---")
            print(templates["cpp_typed_hook"])
            print("\n--- KittyMemory C++ ---")
            print(templates["cpp_kittymemory"])
            print("\n--- ImGui Menu ---")
            print(templates["imgui_menu"])
        elif choice == "7":
            path = input("Ruta JSON de perfil: ").strip()
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    profiles = json.load(f)
                updated = scanner.batch_update_offsets(profiles)
                for u in updated:
                    print(f"  [{u['status']}] {u['name']}: {u['old_address']} -> {u['new_address_hex']}")
        elif choice == "8":
            if not xref_eng:
                print("[-] Requiere binario y parser cargados.")
                continue
            addr_str = input("Introduce direccion del metodo objetivo (ej. 0x0157519C): ").strip()
            try:
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                callers = xref_eng.find_caller_xrefs(addr, max_results=20)
                print(f"\n[+] Llamadores encontrados ({len(callers)}):")
                for c in callers:
                    m_info = c.get("method_info")
                    m_name = m_info["name"] if m_info else "Funcion sin simbolo"
                    print(f"  {c['caller_vaddr_hex']} | {c['type']} -> {m_name}")
            except Exception as e:
                print(f"[-] Error: {e}")

def main():
    print_banner()
    parser_arg = argparse.ArgumentParser(description="Auto Offset & AOB Finder Pro V3+")
    parser_arg.add_argument("--dir", default="freefire", help="Carpeta con archivos de Il2Cpp")
    parser_arg.add_argument("--dump", help="Ruta directa al archivo dump.cs")
    parser_arg.add_argument("--script", help="Ruta directa al archivo script.json")
    parser_arg.add_argument("--binary", help="Ruta directa al binario (UnityFramework / .so)")
    parser_arg.add_argument("--search", help="Buscar metodo por texto o direccion")
    parser_arg.add_argument("--aob", help="Generar AOB para una direccion")
    parser_arg.add_argument("--scan", help="Escanear firma AOB en el binario")
    parser_arg.add_argument("--struct", help="Generar struct C++ para una clase")
    
    args = parser_arg.parse_args()
    parser, bin_reader = init_environment(args.dir, dump_cs=args.dump, script_json=args.script, binary_path=args.binary)

    if args.struct:
        print(parser.generate_struct_layout(args.struct))
        return

    if args.search:
        results = parser.search_methods(args.search, max_results=10)
        for r in results:
            print(f"{r['address_hex_upper']} | {r['name']} ({r.get('source', '')})")
        return

    if args.aob and bin_reader:
        gen = AOBEngine(bin_reader)
        addr = int(args.aob, 16) if args.aob.startswith("0x") else int(args.aob)
        res = gen.generate_aob(addr)
        print(f"Patron: {res['active_pattern']}")
        return

    interactive_menu(parser, bin_reader)

if __name__ == "__main__":
    main()
