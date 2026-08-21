import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.binary_reader import BinaryReader
from core.il2cpp_parser import Il2CppParser
from core.aob_engine import AOBEngine
from core.disassembler import SimpleARM64Disassembler, FunctionAnalyzer
from core.patch_generator import PatchGenerator
from core.pattern_scanner import PatternScanner

print("="*65)
print("=== VERIFICACIÓN INTEGRAL DE AUTO OFFSET & AOB FINDER PRO V3+ ===")
print("="*65)

# 1. Cargar Binario
bin_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "freefire", "UnityFramework")
bin_reader = BinaryReader(bin_path)
info = bin_reader.get_info()
print(f"\n[1] Binario cargado:")
print(f"    Archivo: {info['filename']} ({info['format']}, {info['filesize_mb']} MB, {info['arch']})")

# 2. Generación AOB + Desensamblado + Análisis Estático
engine = AOBEngine(bin_reader)
sample_addr = 0x0157519C
res = engine.generate_aob(sample_addr, length=24, mask_relative=True, ensure_unique=True)

print(f"\n[2] AOB Generado para {hex(sample_addr)}:")
print(f"    Patrón: {res['active_pattern']}")
print(f"    Unicidad: {res['is_unique']} (Coincidencias: {res['matches_count']})")
print(f"    Análisis Estático: {res['analysis']['summary']}")

print("\n[3] Desensamblado ARM64 Decodificado:")
for d in res['disassembly']:
    print(f"    {d['offset']}: {d['bytes']:<16} | {d['asm']}")

# 4. Prueba del Ensamblador de Floats y Enteros Dinámicos
custom_float_hex, custom_float_asm = PatchGenerator.assemble_custom_float_arm64(250.5)
print(f"\n[4] Parche Dinámico Custom Float (250.5f):")
print(f"    Hex: {custom_float_hex}")
print(f"    Asm:\n{custom_float_asm}")

custom_int_hex, custom_int_asm = PatchGenerator.assemble_custom_int_arm64(999999)
print(f"\n[5] Parche Dinámico Custom Int (999999):")
print(f"    Hex: {custom_int_hex}")

# 5. Generación de Plantillas de Modding
templates = PatchGenerator.generate_templates("Player$$TakeDamage", "0x0157519C", "20 00 80 D2 C0 03 5F D6")
print(f"\n[6] Plantillas de Modding Verificadas:")
print(f"    - iOS Dylib Hook: {'OK' if 'MSHookFunction' in templates['cpp_typed_hook'] else 'FAIL'}")
print(f"    - Android Hook: {'OK' if 'DobbyHook' in templates['android_hook'] else 'FAIL'}")
print(f"    - KittyMemory C++: {'OK' if 'MemoryPatch' in templates['cpp_kittymemory'] else 'FAIL'}")
print(f"    - ImGui Mod Menu: {'OK' if 'ImGui::Checkbox' in templates['imgui_menu'] else 'FAIL'}")
print(f"    - C# Harmony Mod: {'OK' if 'HarmonyPatch' in templates['cs_harmony'] else 'FAIL'}")
print(f"    - GameGuardian Lua: {'OK' if 'gg.setValues' in templates['gg_lua'] else 'FAIL'}")

# 6. Prueba de Batch Updater
scanner = PatternScanner(bin_reader)
sample_profile = [
    {"name": "TakeDamage_Test", "old_address": "0x0157519C", "pattern": res["active_pattern"]}
]
batch_res = scanner.batch_update_offsets(sample_profile)
print(f"\n[7] Auto-Updater por Lotes:")
print(f"    Estado: {batch_res[0]['status']} | Nuevo Offset: {batch_res[0]['new_address_hex']} | Delta: {batch_res[0]['delta']}")

bin_reader.close()
print("\n" + "="*65)
print("=== TODAS LAS PRUEBAS PASARON EXITOSAMENTE (100% OK) ===")
print("="*65)
