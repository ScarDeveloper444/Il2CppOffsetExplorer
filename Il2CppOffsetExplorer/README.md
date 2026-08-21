# Il2Cpp Offset Explorer

Herramienta en Python para el analisis estatico de binarios, exploracion de estructuras de clases y busqueda de firmas AOB para entornos Il2Cpp / Unity (iOS Mach-O 64-bit, Android ELF ARM64/ARM32 y Windows PE x86_64).

---

## Caracteristicas Principales

### 1. Buscador Indexado de Alta Velocidad (<1ms)
- **Inverted Token & Acronym Indexing**: Busquedas instantaneas en mas de 420,000 simbolos y metodos por nombre, clase, direccion de memoria o acronimos (ej. `TD` -> `TakeDamage`).
- **Puntuacion de Relevancia (Scoring Engine)**: Ordenamiento inteligente de resultados por coincidencia exacta y jerarquia.
- **Filtros por Tipos de Retorno y Acceso**:
  - Filtros de tipo: `bool`, `float`, `int`, `void`, `Vector3`.
  - Filtros de acceso: `Getters`, `Setters`, `Static`.
- **Rangos de Memoria y Regex**:
  - Rangos: `0x1500000..0x1600000`.
  - Expresiones Regulares: `r/Take.*Damage/`.

---

### 2. Explorador de Structs & Offsets de Campos (C++ y C# Layout)
- **Extraccion Automatica de Campos desde `dump.cs`**:
  - Muestra todos los campos con sus respectivos offsets de memoria.
- **Generadores de Estructura con Padding Exacto**:
  - Generador C++ `#pragma pack(push, 1)` con relleno `pad_0x...`.
  - Generador C# con atributos `[StructLayout(LayoutKind.Explicit)]` y `[FieldOffset(0x...)]`.

---

### 3. Code Studio & Ensamblador Dinamico
Generacion de plantillas de codigo limpias para multiples entornos:
- **C++ Dylib Hook (`MSHookFunction` / `DobbyHook`)**: Con soporte para firma tipada.
- **Android Native Hook (`ShadowHook` / `Dobby` / `dlopen`)**: Para inyeccion en `libil2cpp.so`.
- **C++ KittyMemory**: `MemoryPatch::createWithHex`.
- **C++ ImGui Menu**: Integracion con checkboxes y sliders.
- **Modern C++20 Header (`.hpp`)**: `namespace` y `constexpr`.
- **C# Harmony**: Clases con `[HarmonyPatch]` para MelonLoader / BepInEx.
- **C# P/Invoke Delegate**: Invocacion directa en memoria (`Marshal.GetDelegateForFunctionPointer`).
- **ANSI C Header (`.h`)**: Cabeceras estandar.
- **GameGuardian (Lua)**: Scripts de modificacion en memoria.
- **Frida (JavaScript)**: Interceptores de funciones.
- **Cheat Engine (XML)**: Tablas Auto-Assembler.
- **Ensamblador Dinamico de Floats y Enteros**: Ensambla valores arbitrarios (ej. `250.5f` o `999999`) a opcodes ARM64 reales.

---

### 4. Desensamblador ARM64/ARM32 & Analisis Estatico
- **Desensamblado en Tiempo Real**: Decodificacion completa de instrucciones ARM64 y ARM32 (`MOV`, `LDR`, `STR`, `STP`, `LDP`, `ADRP`, `ADD`, `B`, `BL`, `CBZ`, `RET`, `PACIASP`, `AUTIASP`, `RETAA`).
- **Analisis Heuristico**: Deteccion automatica de retornos constantes, getters/setters y wrappers.
- **Visor Hex Dump & Salto Directo**: Visualizacion de memoria cruda e inspeccion inmediata de cualquier direccion `0x...`.

---

### 5. Escaner AOB, Actualizador por Lotes & XRefs
- **Validacion de Unicidad**: Comprobacion automatica de firmas AOB unicas en el binario completo.
- **Actualizador por Lotes**: Calculo de desplazamiento relativo (Delta Shift) entre diferentes versiones del binario.
- **Caller XRefs**: Localizacion de funciones en el binario que llaman a una direccion especifica.

---

## Ejecucion

Ejecutar mediante:
- `iniciar.bat` (dentro de `AutoOffset_AOB_Finder_Pro`)
- O por consola:
```powershell
py gui.py
```
