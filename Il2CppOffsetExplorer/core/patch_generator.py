import struct
import re
from typing import Dict, Any, List, Tuple

class PatchGenerator:
    """
    Generador de codigo para Il2Cpp.
    """

    ARM64_PRESETS = {
        "RETURN_TRUE": {
            "name": "Return True (bool = 1)",
            "hex": "20 00 80 D2 C0 03 5F D6",
            "asm": "MOV W0, #1\nRET"
        },
        "RETURN_FALSE": {
            "name": "Return False (bool = 0)",
            "hex": "00 00 80 D2 C0 03 5F D6",
            "asm": "MOV W0, #0\nRET"
        },
        "RETURN_ZERO": {
            "name": "Return Zero (int / pointer = 0)",
            "hex": "00 00 80 D2 C0 03 5F D6",
            "asm": "MOV X0, #0\nRET"
        },
        "RETURN_ONE": {
            "name": "Return One (int = 1)",
            "hex": "20 00 80 D2 C0 03 5F D6",
            "asm": "MOV W0, #1\nRET"
        },
        "RETURN_FLOAT_1": {
            "name": "Return Float 1.0",
            "hex": "00 10 2E 1E C0 03 5F D6",
            "asm": "FMOV S0, #1.0\nRET"
        },
        "RETURN_FLOAT_0": {
            "name": "Return Float 0.0",
            "hex": "00 00 27 1E C0 03 5F D6",
            "asm": "FMOV S0, #0.0\nRET"
        },
        "RETURN_FLOAT_100": {
            "name": "Return Float 100.0",
            "hex": "00 50 2E 1E C0 03 5F D6",
            "asm": "FMOV S0, #100.0\nRET"
        },
        "RETURN_FLOAT_1000": {
            "name": "Return Float 1000.0",
            "hex": "00 A0 57 52 00 00 27 1E C0 03 5F D6",
            "asm": "MOV W0, #0x447A0000\nFMOV S0, W0\nRET"
        },
        "NOP": {
            "name": "NOP",
            "hex": "1F 20 03 D5",
            "asm": "NOP"
        },
        "RET": {
            "name": "RET",
            "hex": "C0 03 5F D6",
            "asm": "RET"
        }
    }

    ARM32_PRESETS = {
        "RETURN_TRUE": {
            "name": "Return True (ARM32)",
            "hex": "01 00 A0 E3 1E FF 2F E1",
            "asm": "MOV R0, #1\nBX LR"
        },
        "RETURN_FALSE": {
            "name": "Return False (ARM32)",
            "hex": "00 00 A0 E3 1E FF 2F E1",
            "asm": "MOV R0, #0\nBX LR"
        },
        "NOP": {
            "name": "NOP (ARM32)",
            "hex": "00 F0 20 E3",
            "asm": "NOP"
        },
        "RET": {
            "name": "BX LR (ARM32)",
            "hex": "1E FF 2F E1",
            "asm": "BX LR"
        }
    }

    @classmethod
    def assemble_custom_float_arm64(cls, value: float) -> Tuple[str, str]:
        raw_bytes = struct.pack('<f', float(value))
        int_bits, = struct.unpack('<I', raw_bytes)
        
        imm16_lo = int_bits & 0xFFFF
        imm16_hi = (int_bits >> 16) & 0xFFFF

        insn_movz = 0x52800000 | (imm16_lo << 5)
        insn_movk = 0x72A00000 | (imm16_hi << 5)
        insn_fmov = 0x1E270000
        insn_ret = 0xD65F03C0

        if imm16_hi == 0:
            byte_seq = struct.pack('<III', insn_movz, insn_fmov, insn_ret)
            asm_text = f"MOV W0, #0x{imm16_lo:X}\nFMOV S0, W0\nRET"
        else:
            byte_seq = struct.pack('<IIII', insn_movz, insn_movk, insn_fmov, insn_ret)
            asm_text = f"MOV W0, #0x{imm16_lo:X}\nMOVK W0, #0x{imm16_hi:X}, LSL #16\nFMOV S0, W0\nRET"

        hex_str = " ".join(f"{b:02X}" for b in byte_seq)
        return hex_str, asm_text

    @classmethod
    def assemble_custom_int_arm64(cls, value: int) -> Tuple[str, str]:
        val_32 = value & 0xFFFFFFFF
        imm16_lo = val_32 & 0xFFFF
        imm16_hi = (val_32 >> 16) & 0xFFFF

        insn_movz = 0x52800000 | (imm16_lo << 5)
        insn_movk = 0x72A00000 | (imm16_hi << 5)
        insn_ret = 0xD65F03C0

        if imm16_hi == 0:
            byte_seq = struct.pack('<II', insn_movz, insn_ret)
            asm_text = f"MOV W0, #{imm16_lo}\nRET"
        else:
            byte_seq = struct.pack('<III', insn_movz, insn_movk, insn_ret)
            asm_text = f"MOV W0, #0x{imm16_lo:X}\nMOVK W0, #0x{imm16_hi:X}, LSL #16\nRET"

        hex_str = " ".join(f"{b:02X}" for b in byte_seq)
        return hex_str, asm_text

    @staticmethod
    def parse_signature(signature: str, clean_name: str) -> Tuple[str, List[Tuple[str, str]]]:
        ret_type = "void"
        params = []
        
        if not signature:
            return "void", [("void*", "__this")]

        sig_clean = signature.strip().rstrip(';').rstrip('{').strip()
        
        if '(' in sig_clean and ')' in sig_clean:
            before_paren = sig_clean.split('(')[0].strip()
            paren_content = sig_clean.split('(')[1].split(')')[0].strip()
            
            words = before_paren.split()
            if len(words) >= 2:
                clean_words = [w for w in words if w not in ('public', 'private', 'protected', 'internal', 'static', 'virtual', 'override', 'extern', 'inline')]
                if len(clean_words) >= 2:
                    ret_type = clean_words[-2]
                elif len(clean_words) == 1:
                    ret_type = clean_words[0]

            if paren_content:
                raw_params = [p.strip() for p in paren_content.split(',') if p.strip()]
                for idx, p in enumerate(raw_params):
                    if "MethodInfo" in p:
                        continue
                    p_parts = p.split()
                    if len(p_parts) >= 2:
                        p_type = ' '.join(p_parts[:-1])
                        p_name = p_parts[-1].lstrip('*').lstrip('&')
                        p_type = PatchGenerator._map_type_to_cpp(p_type)
                        params.append((p_type, p_name))
                    elif len(p_parts) == 1:
                        params.append((PatchGenerator._map_type_to_cpp(p_parts[0]), f"arg{idx}"))

        if not params:
            params = [("void*", "__this")]

        return ret_type, params

    @staticmethod
    def _map_type_to_cpp(t: str) -> str:
        t_clean = t.replace('&', '').strip()
        mapping = {
            "System_String_o*": "void*",
            "System.String": "void*",
            "string": "void*",
            "System.Int32": "int",
            "int": "int",
            "System.Single": "float",
            "float": "float",
            "System.Boolean": "bool",
            "bool": "bool",
            "System.Int64": "int64_t",
            "long": "int64_t",
            "System.UInt32": "uint32_t",
            "uint": "uint32_t",
            "System.Void": "void",
            "void": "void",
            "System.Object": "void*",
            "object": "void*",
            "IntPtr": "void*",
            "Vector3": "Vector3",
            "UnityEngine.Vector3": "Vector3"
        }
        return mapping.get(t_clean, "void*" if t.endswith('*') or '.' in t else t)

    @classmethod
    def generate_templates(cls, method_name: str, address_hex: str, patch_hex: str = "20 00 80 D2 C0 03 5F D6", arch: str = "ARM64", target_binary: str = "UnityFramework", signature: str = "") -> Dict[str, str]:
        class_name = "GameClass"
        short_name = method_name
        if "$$" in method_name:
            parts = method_name.split("$$")
            class_name = parts[0]
            short_name = parts[1]
        elif "." in method_name:
            parts = method_name.rsplit(".", 1)
            class_name = parts[0]
            short_name = parts[1]

        clean_id = f"{class_name}_{short_name}"
        clean_id = re.sub(r'[^A-Za-z0-9_]', '_', clean_id).strip('_')
        if not clean_id or clean_id[0].isdigit():
            clean_id = "Fn_" + clean_id

        hex_no_spaces = patch_hex.replace(" ", "")
        ret_type, params = cls.parse_signature(signature, method_name)
        cpp_ret = cls._map_type_to_cpp(ret_type)

        cpp_param_decl = ", ".join([f"{pt} {pn}" for pt, pn in params])
        cpp_param_names = ", ".join([pn for pt, pn in params])

        cs_params_list = []
        for pt, pn in params:
            cs_t = "float" if pt == "float" else ("bool" if pt == "bool" else ("int" if pt == "int" else "IntPtr"))
            cs_params_list.append(f"{cs_t} {pn}")
        cs_param_decl = ", ".join(cs_params_list)
        cs_param_names = ", ".join([pn for pt, pn in params])

        # 1. C++ TYPED HOOK
        cpp_typed_hook = f"""#include <mach-o/dyld.h>
#include <substrate.h>

#define OFFSET_{clean_id.upper()} {address_hex}

typedef {cpp_ret} (*t_{clean_id})({cpp_param_decl});
static t_{clean_id} orig_{clean_id} = nullptr;

static bool b_{clean_id} = false;

{cpp_ret} hook_{clean_id}({cpp_param_decl}) {{
    if (b_{clean_id}) {{
        {"return true;" if cpp_ret == "bool" else ("return 100.0f;" if cpp_ret == "float" else ("return 0;" if cpp_ret == "int" else ""))}
    }}
    return orig_{clean_id}({cpp_param_names});
}}

void setup_{clean_id}() {{
    uintptr_t base = _dyld_get_image_vmaddr_slide(0);
    MSHookFunction((void*)(base + OFFSET_{clean_id.upper()}), (void*)hook_{clean_id}, (void**)&orig_{clean_id});
}}"""

        # 2. C++ ANDROID HOOK
        android_hook = f"""#include <dlfcn.h>
#include <unistd.h>
#include "dobby.h"

#define OFFSET_{clean_id.upper()} {address_hex}

typedef {cpp_ret} (*t_{clean_id})({cpp_param_decl});
static t_{clean_id} orig_{clean_id} = nullptr;

static bool b_{clean_id} = false;

{cpp_ret} hook_{clean_id}({cpp_param_decl}) {{
    if (b_{clean_id}) {{
        {"return true;" if cpp_ret == "bool" else ("return 100.0f;" if cpp_ret == "float" else ("return 0;" if cpp_ret == "int" else ""))}
    }}
    return orig_{clean_id}({cpp_param_names});
}}

void setup_android_{clean_id}() {{
    uintptr_t base = (uintptr_t)dlopen("{target_binary if target_binary.endswith('.so') else 'libil2cpp.so'}", RTLD_LAZY);
    if (base) {{
        DobbyHook((void*)(base + OFFSET_{clean_id.upper()}), (void*)hook_{clean_id}, (void**)&orig_{clean_id});
    }}
}}"""

        # 3. C++ KITTYMEMORY
        cpp_kittymemory = f"""#include "KittyMemory/MemoryPatch.h"

static MemoryPatch patch_{clean_id} = MemoryPatch::createWithHex("{target_binary}", {address_hex}, "{hex_no_spaces}");

void toggle_{clean_id}(bool enable) {{
    if (enable) {{
        patch_{clean_id}.Modify();
    }} else {{
        patch_{clean_id}.Restore();
    }}
}}"""

        # 4. C++ IMGUI MENU
        imgui_menu = f"""#include "imgui.h"

static bool b_toggle_{clean_id} = false;

if (ImGui::Checkbox("{short_name}", &b_toggle_{clean_id})) {{
    toggle_{clean_id}(b_toggle_{clean_id});
}}"""

        # 5. C++ MODERN HEADER (.hpp)
        cpp_header = f"""#pragma once
#include <cstdint>

namespace Il2CppOffsets {{
    namespace {re.sub(r'[^A-Za-z0-9_]', '_', class_name)} {{
        constexpr uintptr_t {short_name} = {address_hex};
        constexpr const char* {short_name}_PATCH = "{hex_no_spaces}";
        using {short_name}_Fn = {cpp_ret}(*)({cpp_param_decl});
    }}
}}"""

        # 6. C# HARMONY PATCH
        cs_harmony = f"""using HarmonyLib;
using System;

[HarmonyPatch(typeof({class_name}), "{short_name}")]
public class Patch_{clean_id}
{{
    [HarmonyPrefix]
    public static bool Prefix({cs_param_decl})
    {{
        return true;
    }}

    [HarmonyPostfix]
    public static void Postfix(ref {('bool' if cpp_ret=='bool' else ('int' if cpp_ret=='int' else ('float' if cpp_ret=='float' else 'object')))} __result)
    {{
    }}
}}"""

        # 7. C# DELEGATE PINVOKE
        cs_delegate = f"""using System;
using System.Runtime.InteropServices;

public static class Il2CppCall_{clean_id}
{{
    public const long OFFSET = {address_hex};

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate {('void' if cpp_ret=='void' else ('bool' if cpp_ret=='bool' else ('float' if cpp_ret=='float' else 'int')))} {clean_id}Delegate({cs_param_decl});

    private static {clean_id}Delegate _invoker;

    public static {clean_id}Delegate Invoker
    {{
        get
        {{
            if (_invoker == null)
            {{
                IntPtr baseAddress = Il2CppHelper.GetModuleBase("{target_binary}");
                IntPtr functionPtr = new IntPtr(baseAddress.ToInt64() + OFFSET);
                _invoker = Marshal.GetDelegateForFunctionPointer<{clean_id}Delegate>(functionPtr);
            }}
            return _invoker;
        }}
    }}

    public static void Execute({cs_param_decl})
    {{
        Invoker({cs_param_names});
    }}
}}"""

        # 8. ANSI C HEADER
        c_header = f"""#ifndef {clean_id.upper()}_H
#define {clean_id.upper()}_H

#include <stdint.h>

#define OFFSET_{clean_id.upper()} {address_hex}
#define PATCH_{clean_id.upper()} "{hex_no_spaces}"

typedef {cpp_ret} (*fn_{clean_id})({cpp_param_decl});

#endif"""

        # 9. GAMEGUARDIAN (LUA)
        gg_lua = f"""local target_offset = {address_hex}
local patch_hex = "{patch_hex}"

function applyPatch_{clean_id}()
    local ranges = gg.getRangesList("{target_binary}")
    if #ranges > 0 then
        local base = ranges[1].start
        local target_addr = base + target_offset
        gg.setValues({{
            {{address = target_addr, flags = gg.TYPE_DWORD, value = "~A {patch_hex.split()[0] if patch_hex.split() else '00'}"}}
        }})
    end
end
applyPatch_{clean_id}()"""

        # 10. FRIDA JS
        frida_js = f"""const base = Module.findBaseAddress("{target_binary}");
const targetAddress = base.add({address_hex});

Interceptor.attach(targetAddress, {{
    onEnter: function (args) {{
    }},
    onLeave: function (retval) {{
    }}
}});"""

        # 11. CHEAT ENGINE XML
        cheat_engine_xml = f"""<CheatEntry>
  <ID>100</ID>
  <Description>"{method_name}"</Description>
  <LastState Activated="0"/>
  <VariableType>Auto Assembler Script</VariableType>
  <AssemblerScript>[ENABLE]
{target_binary}+{address_hex.replace('0x', '')}:
db {patch_hex}

[DISABLE]
</AssemblerScript>
</CheatEntry>"""

        return {
            "cpp_typed_hook": cpp_typed_hook,
            "android_hook": android_hook,
            "cpp_kittymemory": cpp_kittymemory,
            "imgui_menu": imgui_menu,
            "cpp_header": cpp_header,
            "cs_harmony": cs_harmony,
            "cs_delegate": cs_delegate,
            "c_header": c_header,
            "gg_lua": gg_lua,
            "frida_js": frida_js,
            "cheat_engine_xml": cheat_engine_xml
        }
