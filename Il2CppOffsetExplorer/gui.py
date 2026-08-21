#!/usr/bin/env python3
"""Il2Cpp Offset Explorer"""
import os
import sys
import json
import csv
import re
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.binary_reader import BinaryReader
from core.il2cpp_parser import Il2CppParser
from core.aob_engine import AOBEngine
from core.disassembler import SimpleARM64Disassembler, SimpleARM32Disassembler, FunctionAnalyzer
from core.pattern_scanner import PatternScanner
from core.patch_generator import PatchGenerator
from core.xref_engine import XRefEngine
from core.migrator import VersionMigrator

# --- Color Palette ---
BG_MAIN       = "#0a0e17"
BG_CARD       = "#0f1524"
BG_CARD_LIGHT = "#182035"
BG_INPUT      = "#0c1120"
BG_ELEVATED   = "#1a2540"
BORDER_SUBTLE = "#1e2d4a"
ACCENT_CYAN   = "#5eead4"
ACCENT_GREEN  = "#34d399"
ACCENT_PURPLE = "#c084fc"
ACCENT_YELLOW = "#fbbf24"
ACCENT_ORANGE = "#fb923c"
ACCENT_BLUE   = "#60a5fa"
ACCENT_RED    = "#f87171"
ACCENT_PINK   = "#f472b6"
TEXT_MAIN      = "#e2e8f0"
TEXT_BRIGHT    = "#f1f5f9"
TEXT_MUTED     = "#64748b"
TEXT_DIM       = "#475569"

FONT_HEADING = ("Segoe UI", 11, "bold")
FONT_BODY    = ("Segoe UI", 9)
FONT_BODY_B  = ("Segoe UI", 9, "bold")
FONT_SMALL   = ("Segoe UI", 8)
FONT_SMALL_B = ("Segoe UI", 8, "bold")
FONT_MONO    = ("Cascadia Mono", 9)
FONT_MONO_SM = ("Cascadia Mono", 8)
FONT_TITLE   = ("Segoe UI", 13, "bold")

class AutoOffsetUltimateTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Il2Cpp Offset Explorer")
        self.geometry("1480x960")
        self.minsize(1200, 800)
        self.configure(bg=BG_MAIN)

        self.parser = Il2CppParser()
        self.bin_reader = None
        self.aob_engine = None
        self.scanner = None
        self.xref_engine = None
        self.migrator = None

        self.current_selected_method = None
        self.current_search_results = []
        self.my_hacks_profile = []
        self.saved_profile = []
        self._search_timer = None
        self.bookmarks_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles", "saved_hacks.json")

        self._setup_styles()
        self._build_ui()
        self._load_saved_bookmarks()
        self._auto_detect_freefire()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TNotebook", background=BG_MAIN, borderwidth=0, padding=0)
        style.configure("TNotebook.Tab",
                        background=BG_CARD,
                        foreground=TEXT_MUTED,
                        font=FONT_BODY_B,
                        padding=[16, 7],
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG_ELEVATED)],
                  foreground=[("selected", ACCENT_CYAN)])

        style.configure("Code.TNotebook", background=BG_CARD, borderwidth=0, padding=0)
        style.configure("Code.TNotebook.Tab",
                        background=BG_CARD,
                        foreground=TEXT_DIM,
                        font=FONT_SMALL_B,
                        padding=[9, 4],
                        borderwidth=0)
        style.map("Code.TNotebook.Tab",
                  background=[("selected", BG_ELEVATED)],
                  foreground=[("selected", ACCENT_GREEN)])

        style.configure("Treeview",
                        background=BG_CARD,
                        foreground=TEXT_MAIN,
                        fieldbackground=BG_CARD,
                        font=FONT_MONO,
                        rowheight=28,
                        borderwidth=0)
        style.configure("Treeview.Heading",
                        background=BG_ELEVATED,
                        foreground=TEXT_MUTED,
                        font=FONT_SMALL_B,
                        borderwidth=0,
                        relief="flat")
        style.map("Treeview",
                  background=[("selected", "#1e3a5f")],
                  foreground=[("selected", ACCENT_CYAN)])

        style.configure("TCombobox",
                        fieldbackground=BG_INPUT,
                        background=BG_CARD_LIGHT,
                        foreground=TEXT_MAIN,
                        arrowcolor=TEXT_MUTED,
                        borderwidth=0)

    def _btn(self, parent, text, bg, fg, command, font=None, padx=10, pady=3):
        b = tk.Button(parent, text=text, font=font or FONT_SMALL_B,
                      bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
                      relief="flat", bd=0, padx=padx, pady=pady,
                      cursor="hand2", command=command)
        return b

    def _card(self, parent, **kw):
        f = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER_SUBTLE,
                     highlightthickness=1, **kw)
        return f

    def _entry(self, parent, font=None, width=None, **kw):
        e = tk.Entry(parent, font=font or FONT_MONO, bg=BG_INPUT, fg=TEXT_BRIGHT,
                     insertbackground=ACCENT_CYAN, relief="flat",
                     highlightbackground=BORDER_SUBTLE, highlightthickness=1,
                     highlightcolor=ACCENT_CYAN, **({"width": width} if width else {}), **kw)
        return e

    def _build_ui(self):
        # 1. TOP BAR: DIRECT FILE LOADERS
        self._build_top_file_bar()

        # 2. MAIN NOTEBOOK
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 6))

        # Tab 1: DASHBOARD DE BUSQUEDA Y CODE STUDIO
        self.tab_dashboard = tk.Frame(self.notebook, bg=BG_MAIN, padx=8, pady=8)
        self.notebook.add(self.tab_dashboard, text="Buscador & Code Studio")
        self._build_dashboard_tab()

        # Tab 2: EXPLORADOR DE STRUCTS & CAMPOS
        self.tab_structs = tk.Frame(self.notebook, bg=BG_MAIN, padx=10, pady=10)
        self.notebook.add(self.tab_structs, text="Structs & Field Offsets")
        self._build_structs_tab()

        # Tab 3: MIS FUNCIONES & EXPORTADOR
        self.tab_my_hacks = tk.Frame(self.notebook, bg=BG_MAIN, padx=10, pady=10)
        self.notebook.add(self.tab_my_hacks, text="Funciones Guardadas")
        self._build_my_hacks_tab()

        # Tab 4: ESCANER AOB & AUTO-UPDATER
        self.tab_scanner = tk.Frame(self.notebook, bg=BG_MAIN, padx=10, pady=10)
        self.notebook.add(self.tab_scanner, text="Escaner / Auto-Updater")
        self._build_scanner_tab()

        # Tab 5: STRINGS & XREFS
        self.tab_strings = tk.Frame(self.notebook, bg=BG_MAIN, padx=10, pady=10)
        self.notebook.add(self.tab_strings, text="Strings Literales")
        self._build_strings_tab()

        # 3. BOTTOM FOOTER
        bottom_bar = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER_SUBTLE, highlightthickness=1, height=30, padx=16, pady=4)
        bottom_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.footer_lbl = tk.Label(bottom_bar, text="Listo.", font=FONT_SMALL, bg=BG_CARD, fg=TEXT_DIM)
        self.footer_lbl.pack(side=tk.LEFT)

        self.perf_lbl = tk.Label(bottom_bar, text="0.0 ms", font=FONT_SMALL_B, bg=BG_CARD, fg=ACCENT_CYAN)
        self.perf_lbl.pack(side=tk.RIGHT)

    def _build_top_file_bar(self):
        top_container = self._card(self, padx=16, pady=10)
        top_container.pack(fill=tk.X, side=tk.TOP, padx=8, pady=(8, 4))

        title_row = tk.Frame(top_container, bg=BG_CARD)
        title_row.pack(fill=tk.X, pady=(0, 8))

        lbl_app = tk.Label(title_row, text="IL2CPP OFFSET EXPLORER", font=FONT_TITLE, bg=BG_CARD, fg=ACCENT_CYAN)
        lbl_app.pack(side=tk.LEFT)

        tk.Label(title_row, text="v3", font=FONT_SMALL, bg=BG_CARD, fg=TEXT_DIM).pack(side=tk.LEFT, padx=(6, 0), pady=(4, 0))

        self.badge_status = tk.Label(title_row, text="ESPERANDO ARCHIVOS", font=FONT_SMALL_B, bg=BG_CARD, fg=ACCENT_ORANGE)
        self.badge_status.pack(side=tk.RIGHT)

        self._btn(title_row, "Auto-Detectar Carpeta", ACCENT_CYAN, BG_MAIN, self._choose_folder, font=FONT_BODY_B).pack(side=tk.RIGHT, padx=6)

        grid_frame = tk.Frame(top_container, bg=BG_CARD)
        grid_frame.pack(fill=tk.X)

        for col_idx, (label_text, attr_name, browse_fn) in enumerate([
            ("dump.cs", "lbl_dump_cs", self._browse_dump_cs),
            ("script.json", "lbl_script_json", self._browse_script_json),
            ("Binario", "lbl_binary", self._browse_binary)
        ]):
            slot = tk.Frame(grid_frame, bg=BG_ELEVATED, padx=10, pady=5,
                           highlightbackground=BORDER_SUBTLE, highlightthickness=1)
            slot.grid(row=0, column=col_idx, sticky="ew", padx=(0 if col_idx == 0 else 4, 0))
            tk.Label(slot, text=label_text, font=FONT_SMALL_B, bg=BG_ELEVATED, fg=TEXT_MUTED).pack(side=tk.LEFT)
            lbl = tk.Label(slot, text="--", font=FONT_MONO_SM, bg=BG_ELEVATED, fg=TEXT_DIM, width=20, anchor="w")
            lbl.pack(side=tk.LEFT, padx=6)
            setattr(self, attr_name, lbl)
            self._btn(slot, "...", BG_CARD_LIGHT, TEXT_MAIN, browse_fn, padx=8, pady=1).pack(side=tk.RIGHT)

        grid_frame.columnconfigure(0, weight=1)
        grid_frame.columnconfigure(1, weight=1)
        grid_frame.columnconfigure(2, weight=1)

    # -------------------------------------------------------------
    # PESTAÑA 1: DASHBOARD CON BUSCADOR POTENTE
    # -------------------------------------------------------------
    def _build_dashboard_tab(self):
        # 1. Search Bar & Filter Controls Container
        search_container = tk.Frame(self.tab_dashboard, bg=BG_CARD, padx=12, pady=8)
        search_container.pack(fill=tk.X, pady=(0, 6))

        # Row 1: Search Entry & Search Type
        s_row = tk.Frame(search_container, bg=BG_CARD)
        s_row.pack(fill=tk.X, pady=(0, 6))

        tk.Label(s_row, text="Busqueda:", font=("Segoe UI", 10, "bold"), 
                 bg=BG_CARD, fg=ACCENT_CYAN).pack(side=tk.LEFT, padx=(0, 6))

        self.dash_search_entry = tk.Entry(s_row, font=("Segoe UI", 11), bg=BG_MAIN, 
                                          fg=TEXT_MAIN, insertbackground=TEXT_MAIN, relief="flat")
        self.dash_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        self.dash_search_entry.bind("<KeyRelease>", lambda e: self._on_search_keyrelease())
        self.dash_search_entry.bind("<Return>", lambda e: self._perform_dash_search())

        self.dash_search_type = tk.StringVar(value="all")
        for val, txt in [("all", "Todos"), ("name", "Metodos"), ("class", "Clases")]:
            rb = tk.Radiobutton(s_row, text=txt, value=val, variable=self.dash_search_type,
                                bg=BG_CARD, fg=TEXT_MAIN, selectcolor=BG_MAIN, activebackground=BG_CARD,
                                activeforeground=ACCENT_CYAN, command=self._perform_dash_search)
            rb.pack(side=tk.LEFT, padx=2)

        btn_find = tk.Button(s_row, text="Buscar", font=("Segoe UI", 9, "bold"),
                             bg=ACCENT_CYAN, fg=BG_MAIN, relief="flat", padx=12, pady=2,
                             command=self._perform_dash_search)
        btn_find.pack(side=tk.LEFT, padx=4)

        btn_export_search = tk.Button(s_row, text="Exportar Resultados", font=("Segoe UI", 8, "bold"),
                                      bg=BG_CARD_LIGHT, fg=TEXT_MAIN, relief="flat", padx=8, pady=2,
                                      command=self._export_search_results_dialog)
        btn_export_search.pack(side=tk.LEFT, padx=2)

        # Row 2: Return Type & Getter/Setter Filters
        filter_row = tk.Frame(search_container, bg=BG_CARD)
        filter_row.pack(fill=tk.X, pady=(0, 4))

        tk.Label(filter_row, text="Filtro Tipo:", font=("Segoe UI", 8, "bold"),
                 bg=BG_CARD, fg=TEXT_MUTED).pack(side=tk.LEFT, padx=(0, 4))

        self.ret_type_filter_var = tk.StringVar(value="ALL")
        for val, txt in [("ALL", "Todos"), ("BOOL", "bool"), ("FLOAT", "float"), ("INT", "int"), ("VOID", "void"), ("VECTOR3", "Vector3")]:
            rb = tk.Radiobutton(filter_row, text=txt, value=val, variable=self.ret_type_filter_var,
                                bg=BG_CARD, fg=TEXT_MAIN, selectcolor=BG_MAIN, activebackground=BG_CARD,
                                activeforeground=ACCENT_GREEN, command=self._perform_dash_search)
            rb.pack(side=tk.LEFT, padx=2)

        tk.Label(filter_row, text=" |  Acceso:", font=("Segoe UI", 8, "bold"),
                 bg=BG_CARD, fg=TEXT_MUTED).pack(side=tk.LEFT, padx=(4, 4))

        self.access_filter_var = tk.StringVar(value="ALL")
        for val, txt in [("ALL", "Todos"), ("GETTERS", "Getters"), ("SETTERS", "Setters"), ("STATIC", "Static")]:
            rb = tk.Radiobutton(filter_row, text=txt, value=val, variable=self.access_filter_var,
                                bg=BG_CARD, fg=TEXT_MAIN, selectcolor=BG_MAIN, activebackground=BG_CARD,
                                activeforeground=ACCENT_YELLOW, command=self._perform_dash_search)
            rb.pack(side=tk.LEFT, padx=2)

        # Row 3: Category Filter Chips Row
        chip_row = tk.Frame(search_container, bg=BG_CARD)
        chip_row.pack(fill=tk.X)

        tk.Label(chip_row, text="Categorias:", font=("Segoe UI", 8, "bold"),
                 bg=BG_CARD, fg=TEXT_MUTED).pack(side=tk.LEFT, padx=(0, 6))

        chip_presets = [
            ("Aimbot / Aim", "AIM", "#3b82f6"),
            ("Dano / Damage", "DAMAGE", "#ef4444"),
            ("Salud / HP", "HP", "#10b981"),
            ("Velocidad / Speed", "SPEED", "#f59e0b"),
            ("Recoil / Armas", "RECOIL", "#8b5cf6"),
            ("ESP / Visibilidad", "ESP", "#06b6d4"),
            ("Seguridad / Anticheat", "ANTICHEAT", "#ec4899"),
            ("Items / Inventario", "ITEMS_SKINS", "#eab308"),
            ("Vehiculos / Fisica", "VEHICLES_PHYSICS", "#14b8a6")
        ]

        for label, cat_key, col in chip_presets:
            btn_chip = tk.Button(chip_row, text=label, font=("Segoe UI", 8, "bold"),
                                 bg=BG_CARD_LIGHT, fg=TEXT_MAIN, activebackground=col,
                                 activeforeground=BG_MAIN, relief="flat", padx=6, pady=1,
                                 command=lambda c=cat_key: self._search_by_cheat_category(c))
            btn_chip.pack(side=tk.LEFT, padx=2)

        # 2. Main Split View: Left Results (48%) | Right Power Hub (52%)
        split_frame = tk.Frame(self.tab_dashboard, bg=BG_MAIN)
        split_frame.pack(fill=tk.BOTH, expand=True)

        # --- LEFT PANE: Results Table ---
        left_frame = tk.Frame(split_frame, bg=BG_MAIN)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        t_cols = ("va_hex", "class", "name", "fields", "source")
        self.dash_tree = ttk.Treeview(left_frame, columns=t_cols, show="headings", selectmode="browse")
        self.dash_tree.heading("va_hex", text="Offset / RVA")
        self.dash_tree.heading("class", text="Clase")
        self.dash_tree.heading("name", text="Metodo / Simbolo")
        self.dash_tree.heading("fields", text="Campos")
        self.dash_tree.heading("source", text="Origen")

        self.dash_tree.column("va_hex", width=120, anchor="center")
        self.dash_tree.column("class", width=160, anchor="w")
        self.dash_tree.column("name", width=250, anchor="w")
        self.dash_tree.column("fields", width=65, anchor="center")
        self.dash_tree.column("source", width=80, anchor="center")

        sb_left = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.dash_tree.yview)
        self.dash_tree.configure(yscroll=sb_left.set)
        self.dash_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_left.pack(side=tk.RIGHT, fill=tk.Y)

        self.dash_tree.bind("<<TreeviewSelect>>", self._on_method_selected)
        self.dash_tree.bind("<Button-3>", self._show_tree_context_menu)

        # --- RIGHT PANE: Code Studio & Inspectors ---
        right_frame = tk.Frame(split_frame, bg=BG_CARD, padx=12, pady=8, width=670)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False)
        right_frame.pack_propagate(False)

        # Card 1: Selected Method Header
        m_info_box = tk.Frame(right_frame, bg=BG_CARD_LIGHT, padx=10, pady=6)
        m_info_box.pack(fill=tk.X, pady=(0, 6))

        top_info_row = tk.Frame(m_info_box, bg=BG_CARD_LIGHT)
        top_info_row.pack(fill=tk.X)

        self.lbl_sel_name = tk.Label(top_info_row, text="Selecciona un metodo en la tabla", 
                                     font=("Segoe UI", 10, "bold"), bg=BG_CARD_LIGHT, fg=TEXT_MAIN, anchor="w")
        self.lbl_sel_name.pack(side=tk.LEFT, fill=tk.X, expand=True)

        btn_view_struct = tk.Button(top_info_row, text="Ver Struct", font=("Segoe UI", 8, "bold"),
                                    bg=ACCENT_BLUE, fg=TEXT_MAIN, relief="flat", padx=6, pady=1,
                                    command=self._view_selected_class_struct)
        btn_view_struct.pack(side=tk.RIGHT, padx=4)

        btn_fav = tk.Button(top_info_row, text="Guardar Funcion", font=("Segoe UI", 8, "bold"),
                            bg=ACCENT_YELLOW, fg=BG_MAIN, relief="flat", padx=8, pady=1,
                            command=self._save_current_to_hacks)
        btn_fav.pack(side=tk.RIGHT)

        self.lbl_sel_offset = tk.Label(m_info_box, text="Offset: 0x00000000 | Decimal: 0", 
                                       font=("Consolas", 9, "bold"), bg=BG_CARD_LIGHT, fg=ACCENT_CYAN, anchor="w")
        self.lbl_sel_offset.pack(fill=tk.X, pady=(2, 0))

        # Card 2: Firma AOB Automatica
        aob_box = tk.Frame(right_frame, bg=BG_CARD)
        aob_box.pack(fill=tk.X, pady=(0, 6))

        aob_header = tk.Frame(aob_box, bg=BG_CARD)
        aob_header.pack(fill=tk.X, pady=(0, 2))
        tk.Label(aob_header, text="FIRMA AOB (WILDCARDS ??)", font=("Segoe UI", 8, "bold"), 
                 bg=BG_CARD, fg=ACCENT_PURPLE).pack(side=tk.LEFT)
        
        self.aob_badge = tk.Label(aob_header, text="[Esperando seleccion]", font=("Segoe UI", 8, "bold"),
                                  bg=BG_CARD, fg=TEXT_MUTED)
        self.aob_badge.pack(side=tk.RIGHT)

        aob_input_row = tk.Frame(aob_box, bg=BG_MAIN, padx=5, pady=3)
        aob_input_row.pack(fill=tk.X)

        self.aob_dash_entry = tk.Entry(aob_input_row, font=("Consolas", 9, "bold"), bg=BG_MAIN, 
                                       fg=ACCENT_CYAN, insertbackground=TEXT_MAIN, relief="flat")
        self.aob_dash_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        btn_cp_aob = tk.Button(aob_input_row, text="Copiar AOB", font=("Segoe UI", 8, "bold"),
                               bg=ACCENT_PURPLE, fg=TEXT_MAIN, relief="flat", padx=10, pady=1,
                               command=lambda: self._copy_to_clip(self.aob_dash_entry.get()))
        btn_cp_aob.pack(side=tk.RIGHT)

        # Card 3: Code Studio (C, C++, C#, Scripts, ImGui)
        hook_box = tk.Frame(right_frame, bg=BG_CARD)
        hook_box.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        hook_ctrl = tk.Frame(hook_box, bg=BG_CARD)
        hook_ctrl.pack(fill=tk.X, pady=(0, 4))

        tk.Label(hook_ctrl, text="GENERADOR DE CODIGO:", font=("Segoe UI", 9, "bold"), 
                 bg=BG_CARD, fg=ACCENT_GREEN).pack(side=tk.LEFT)

        self.custom_val_entry = tk.Entry(hook_ctrl, font=("Segoe UI", 8), bg=BG_MAIN, fg=TEXT_MAIN,
                                         insertbackground=TEXT_MAIN, width=7, relief="flat")
        self.custom_val_entry.insert(0, "100.0")
        self.custom_val_entry.pack(side=tk.RIGHT, padx=(4, 0))
        self.custom_val_entry.bind("<KeyRelease>", lambda e: self._refresh_code_output())

        tk.Label(hook_ctrl, text="Valor:", font=("Segoe UI", 8), bg=BG_CARD, fg=TEXT_MUTED).pack(side=tk.RIGHT, padx=(4, 2))

        self.patch_preset_var = tk.StringVar(value="RETURN_TRUE")
        preset_cb = ttk.Combobox(hook_ctrl, textvariable=self.patch_preset_var, 
                                 values=["RETURN_TRUE", "RETURN_FALSE", "RETURN_ZERO", "RETURN_ONE", "RETURN_FLOAT_1", "RETURN_FLOAT_0", "RETURN_FLOAT_100", "RETURN_FLOAT_1000", "CUSTOM_FLOAT", "CUSTOM_INT", "NOP", "RET"],
                                 state="readonly", width=14)
        preset_cb.pack(side=tk.RIGHT)
        preset_cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_code_output())

        self.hook_nb = ttk.Notebook(hook_box, style="Code.TNotebook")
        self.hook_nb.pack(fill=tk.BOTH, expand=True)

        self.code_boxes = {}
        language_tabs = [
            ("C++ Dylib", "cpp_typed_hook", ".mm"),
            ("Android Hook", "android_hook", ".cpp"),
            ("KittyMemory", "cpp_kittymemory", ".cpp"),
            ("ImGui Menu", "imgui_menu", ".cpp"),
            ("C++ .hpp", "cpp_header", ".hpp"),
            ("C# Harmony", "cs_harmony", ".cs"),
            ("C# PInvoke", "cs_delegate", ".cs"),
            ("C Header", "c_header", ".h"),
            ("GG (Lua)", "gg_lua", ".lua"),
            ("Frida", "frida_js", ".js"),
            ("Cheat Engine", "cheat_engine_xml", ".xml")
        ]

        for title, key, ext in language_tabs:
            tab_f = tk.Frame(self.hook_nb, bg=BG_MAIN)
            self.hook_nb.add(tab_f, text=title)

            tb_bar = tk.Frame(tab_f, bg=BG_MAIN, padx=4, pady=2)
            tb_bar.pack(fill=tk.X)
            
            txt = tk.Text(tab_f, font=("Consolas", 9), bg=BG_MAIN, fg=TEXT_MAIN, relief="flat", padx=6, pady=6)
            txt.pack(fill=tk.BOTH, expand=True)
            self.code_boxes[key] = txt

            btn_save_f = tk.Button(tb_bar, text=f"Guardar {ext}", font=("Segoe UI", 7, "bold"),
                                   bg=BG_CARD_LIGHT, fg=TEXT_MAIN, relief="flat", padx=6,
                                   command=lambda t=txt, e=ext: self._save_snippet_file(t.get("1.0", tk.END), e))
            btn_save_f.pack(side=tk.RIGHT, padx=3)

            btn_cp = tk.Button(tb_bar, text="Copiar", font=("Segoe UI", 7, "bold"),
                               bg=ACCENT_CYAN, fg=BG_MAIN, relief="flat", padx=8,
                               command=lambda t=txt: self._copy_to_clip(t.get("1.0", tk.END)))
            btn_cp.pack(side=tk.RIGHT)

        # Card 4: Inspector Pestanas (Desensamblado ARM64 + Analisis Estatico + Hex Dump + Salto Directo)
        inspector_box = tk.Frame(right_frame, bg=BG_CARD_LIGHT, padx=6, pady=4, height=155)
        inspector_box.pack(fill=tk.X)
        inspector_box.pack_propagate(False)

        top_insp_bar = tk.Frame(inspector_box, bg=BG_CARD_LIGHT)
        top_insp_bar.pack(fill=tk.X, pady=(0, 2))

        tk.Label(top_insp_bar, text="Ir a Direccion:", font=("Segoe UI", 8, "bold"), bg=BG_CARD_LIGHT, fg=TEXT_MUTED).pack(side=tk.LEFT)
        self.goto_addr_entry = tk.Entry(top_insp_bar, font=("Consolas", 8), bg=BG_MAIN, fg=ACCENT_CYAN, width=14, relief="flat")
        self.goto_addr_entry.pack(side=tk.LEFT, padx=4)
        self.goto_addr_entry.bind("<Return>", lambda e: self._inspect_custom_address())

        tk.Button(top_insp_bar, text="Inspeccionar", font=("Segoe UI", 7, "bold"), bg=ACCENT_CYAN, fg=BG_MAIN, relief="flat", padx=6,
                  command=self._inspect_custom_address).pack(side=tk.LEFT)

        self.insp_nb = ttk.Notebook(inspector_box, style="Code.TNotebook")
        self.insp_nb.pack(fill=tk.BOTH, expand=True)

        # Tab Asm
        tab_asm = tk.Frame(self.insp_nb, bg=BG_CARD_LIGHT)
        self.insp_nb.add(tab_asm, text="ARM64 Disasm")
        self.dash_disasm_lbl = tk.Label(tab_asm, text="Selecciona un metodo para desensamblar.", 
                                        font=("Consolas", 8), bg=BG_CARD_LIGHT, fg=TEXT_MAIN, justify=tk.LEFT, anchor="nw")
        self.dash_disasm_lbl.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)

        # Tab Analisis Estatico
        tab_analysis = tk.Frame(self.insp_nb, bg=BG_CARD_LIGHT)
        self.insp_nb.add(tab_analysis, text="Analisis Estatico")
        self.dash_analysis_lbl = tk.Label(tab_analysis, text="Heuristicas automaticas de funcion.", 
                                          font=("Consolas", 8), bg=BG_CARD_LIGHT, fg=ACCENT_GREEN, justify=tk.LEFT, anchor="nw")
        self.dash_analysis_lbl.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)

        # Tab Hex Dump
        tab_hex = tk.Frame(self.insp_nb, bg=BG_CARD_LIGHT)
        self.insp_nb.add(tab_hex, text="Hex Dump")
        self.dash_hexdump_lbl = tk.Label(tab_hex, text="Carga el binario para ver bytes crudos.", 
                                         font=("Consolas", 8), bg=BG_CARD_LIGHT, fg=ACCENT_CYAN, justify=tk.LEFT, anchor="nw")
        self.dash_hexdump_lbl.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)

    # -------------------------------------------------------------
    # PESTANA 2: EXPLORADOR DE STRUCTS & CAMPOS
    # -------------------------------------------------------------
    def _build_structs_tab(self):
        ctrl_card = tk.Frame(self.tab_structs, bg=BG_CARD, padx=14, pady=10)
        ctrl_card.pack(fill=tk.X, pady=(0, 8))

        tk.Label(ctrl_card, text="EXPLORADOR DE ESTRUCTURAS Y OFFSETS DE CAMPOS (C++ / C# STRUCT LAYOUT)", 
                 font=("Segoe UI", 12, "bold"), bg=BG_CARD, fg=ACCENT_CYAN).pack(anchor="w", pady=(0, 6))

        sel_row = tk.Frame(ctrl_card, bg=BG_CARD)
        sel_row.pack(fill=tk.X)

        tk.Label(sel_row, text="Buscar Clase:", font=("Segoe UI", 9, "bold"), bg=BG_CARD, fg=TEXT_MAIN).pack(side=tk.LEFT, padx=(0, 6))
        self.struct_class_entry = tk.Entry(sel_row, font=("Segoe UI", 10), bg=BG_MAIN, fg=TEXT_MAIN, relief="flat", width=30)
        self.struct_class_entry.pack(side=tk.LEFT, padx=4)
        self.struct_class_entry.bind("<Return>", lambda e: self._search_struct_class())

        btn_search_c = tk.Button(sel_row, text="Buscar Clase", font=("Segoe UI", 8, "bold"),
                                 bg=ACCENT_CYAN, fg=BG_MAIN, relief="flat", padx=10, pady=2,
                                 command=self._search_struct_class)
        btn_search_c.pack(side=tk.LEFT, padx=4)

        btn_cp_cs = tk.Button(sel_row, text="Copiar C# Struct", font=("Segoe UI", 8, "bold"),
                              bg=ACCENT_YELLOW, fg=BG_MAIN, relief="flat", padx=10, pady=2,
                              command=self._copy_current_csharp_struct_code)
        btn_cp_cs.pack(side=tk.RIGHT, padx=4)

        btn_cp_struct = tk.Button(sel_row, text="Copiar C++ Struct", font=("Segoe UI", 8, "bold"),
                                  bg=ACCENT_GREEN, fg=BG_MAIN, relief="flat", padx=10, pady=2,
                                  command=self._copy_current_struct_code)
        btn_cp_struct.pack(side=tk.RIGHT, padx=4)

        # Split: Left Table of fields, Right C++ Struct preview
        split_struct = tk.Frame(self.tab_structs, bg=BG_MAIN)
        split_struct.pack(fill=tk.BOTH, expand=True)

        left_s = tk.Frame(split_struct, bg=BG_MAIN)
        left_s.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        f_cols = ("offset_hex", "type", "name")
        self.struct_tree = ttk.Treeview(left_s, columns=f_cols, show="headings", selectmode="browse")
        self.struct_tree.heading("offset_hex", text="Offset")
        self.struct_tree.heading("type", text="Tipo")
        self.struct_tree.heading("name", text="Nombre del Campo")

        self.struct_tree.column("offset_hex", width=120, anchor="center")
        self.struct_tree.column("type", width=220, anchor="w")
        self.struct_tree.column("name", width=260, anchor="w")

        sb_s = ttk.Scrollbar(left_s, orient=tk.VERTICAL, command=self.struct_tree.yview)
        self.struct_tree.configure(yscroll=sb_s.set)
        self.struct_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_s.pack(side=tk.RIGHT, fill=tk.Y)

        right_s = tk.Frame(split_struct, bg=BG_CARD, padx=8, pady=8, width=540)
        right_s.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False)
        right_s.pack_propagate(False)

        tk.Label(right_s, text="Definicion de Estructura C++ / C#:", font=("Segoe UI", 9, "bold"),
                 bg=BG_CARD, fg=ACCENT_CYAN).pack(anchor="w", pady=(0, 4))
        
        self.struct_code_txt = tk.Text(right_s, font=("Consolas", 9), bg=BG_MAIN, fg=TEXT_MAIN, relief="flat", padx=6, pady=6)
        self.struct_code_txt.pack(fill=tk.BOTH, expand=True)

    def _inspect_custom_address(self):
        val = self.goto_addr_entry.get().strip()
        if not val:
            return
        try:
            addr = int(val, 16) if val.startswith("0x") else int(val)
        except Exception:
            return
        
        method_info = {
            "name": f"Address_{val}",
            "class_name": "Memory",
            "clean_name": f"{val}",
            "address": addr,
            "address_hex": f"0x{addr:X}",
            "address_hex_upper": f"0x{addr:X}",
            "signature": ""
        }
        self.current_selected_method = method_info
        self._update_power_hub(method_info)

    def _search_struct_class(self):
        c_name = self.struct_class_entry.get().strip()
        if not c_name: return
        self._display_class_struct(c_name)

    def _display_class_struct(self, class_name: str):
        fields = self.parser.get_class_fields(class_name)
        for item in self.struct_tree.get_children():
            self.struct_tree.delete(item)

        for f in fields:
            self.struct_tree.insert("", tk.END, values=(f["offset_hex"], f["type"], f["name"]))

        struct_code = self.parser.generate_struct_layout(class_name)
        self.struct_code_txt.delete("1.0", tk.END)
        self.struct_code_txt.insert("1.0", struct_code)

    def _copy_current_struct_code(self):
        code = self.struct_code_txt.get("1.0", tk.END).strip()
        if code:
            self._copy_to_clip(code)

    def _copy_current_csharp_struct_code(self):
        c_name = self.struct_class_entry.get().strip()
        if c_name:
            cs_code = self.parser.generate_csharp_struct_layout(c_name)
            self._copy_to_clip(cs_code)
            self.struct_code_txt.delete("1.0", tk.END)
            self.struct_code_txt.insert("1.0", cs_code)

    def _view_selected_class_struct(self):
        if not self.current_selected_method:
            return
        c_name = self.current_selected_method.get("class_name")
        if c_name and c_name != "Global":
            self.notebook.select(self.tab_structs)
            self.struct_class_entry.delete(0, tk.END)
            self.struct_class_entry.insert(0, c_name)
            self._display_class_struct(c_name)

    # -------------------------------------------------------------
    # PESTAÑA 3: MIS FUNCIONES GUARDADAS & EXPORTADOR
    # -------------------------------------------------------------
    def _build_my_hacks_tab(self):
        ctrl_card = tk.Frame(self.tab_my_hacks, bg=BG_CARD, padx=14, pady=10)
        ctrl_card.pack(fill=tk.X, pady=(0, 8))

        tk.Label(ctrl_card, text="FUNCIONES Y OFFSETS GUARDADOS", 
                 font=("Segoe UI", 12, "bold"), bg=BG_CARD, fg=ACCENT_YELLOW).pack(anchor="w", pady=(0, 6))

        btn_row = tk.Frame(ctrl_card, bg=BG_CARD)
        btn_row.pack(fill=tk.X)

        btn_exp_dylib = tk.Button(btn_row, text="Exportar iOS Dylib (Tweak.mm)", font=("Segoe UI", 9, "bold"),
                                  bg=ACCENT_CYAN, fg=BG_MAIN, relief="flat", padx=10, pady=3,
                                  command=self._export_full_dylib)
        btn_exp_dylib.pack(side=tk.LEFT, padx=3)

        btn_exp_android = tk.Button(btn_row, text="Exportar Android Mod (ImGui.cpp)", font=("Segoe UI", 9, "bold"),
                                    bg=ACCENT_BLUE, fg=TEXT_MAIN, relief="flat", padx=10, pady=3,
                                    command=self._export_full_android_mod)
        btn_exp_android.pack(side=tk.LEFT, padx=3)

        btn_exp_cs = tk.Button(btn_row, text="Exportar C# Harmony (UnityMod.cs)", font=("Segoe UI", 9, "bold"),
                               bg=ACCENT_GREEN, fg=BG_MAIN, relief="flat", padx=10, pady=3,
                               command=self._export_full_csharp_mod)
        btn_exp_cs.pack(side=tk.LEFT, padx=3)

        btn_exp_h = tk.Button(btn_row, text="Exportar Header C++ (Offsets.h)", font=("Segoe UI", 9, "bold"),
                              bg=ACCENT_PURPLE, fg=TEXT_MAIN, relief="flat", padx=10, pady=3,
                              command=self._export_full_header)
        btn_exp_h.pack(side=tk.LEFT, padx=3)

        btn_exp_gg = tk.Button(btn_row, text="Exportar GG Script (Lua)", font=("Segoe UI", 9, "bold"),
                               bg=ACCENT_ORANGE, fg=BG_MAIN, relief="flat", padx=10, pady=3,
                               command=self._export_full_gg)
        btn_exp_gg.pack(side=tk.LEFT, padx=3)

        btn_del_sel = tk.Button(btn_row, text="Eliminar Seleccionado", font=("Segoe UI", 8),
                                bg=BG_CARD_LIGHT, fg=TEXT_MAIN, relief="flat", padx=8, pady=3,
                                command=self._delete_selected_hack)
        btn_del_sel.pack(side=tk.RIGHT, padx=3)

        btn_clear_h = tk.Button(btn_row, text="Limpiar Todo", font=("Segoe UI", 8),
                                bg=BG_CARD_LIGHT, fg=TEXT_MAIN, relief="flat", padx=8, pady=3,
                                command=self._clear_my_hacks)
        btn_clear_h.pack(side=tk.RIGHT, padx=3)

        # Hacks Table
        table_frame = tk.Frame(self.tab_my_hacks, bg=BG_MAIN)
        table_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("name", "offset_hex", "patch_type", "aob_pattern")
        self.my_hacks_tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.my_hacks_tree.heading("name", text="Funcion / Simbolo")
        self.my_hacks_tree.heading("offset_hex", text="Offset")
        self.my_hacks_tree.heading("patch_type", text="Tipo de Parche")
        self.my_hacks_tree.heading("aob_pattern", text="Firma AOB")

        self.my_hacks_tree.column("name", width=280, anchor="w")
        self.my_hacks_tree.column("offset_hex", width=140, anchor="center")
        self.my_hacks_tree.column("patch_type", width=160, anchor="center")
        self.my_hacks_tree.column("aob_pattern", width=420, anchor="w")

        sb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.my_hacks_tree.yview)
        self.my_hacks_tree.configure(yscroll=sb.set)
        self.my_hacks_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    # -------------------------------------------------------------
    # PESTAÑA 4: ESCANER AOB & AUTO-UPDATER
    # -------------------------------------------------------------
    def _build_scanner_tab(self):
        ctrl_card = tk.Frame(self.tab_scanner, bg=BG_CARD, padx=14, pady=10)
        ctrl_card.pack(fill=tk.X, pady=(0, 8))

        tk.Label(ctrl_card, text="Firma AOB a Escanear en el Binario (admite comodines ??):", 
                 font=("Segoe UI", 10, "bold"), bg=BG_CARD, fg=TEXT_MAIN).pack(anchor="w", pady=(0, 4))

        input_row = tk.Frame(ctrl_card, bg=BG_CARD)
        input_row.pack(fill=tk.X, pady=(0, 6))

        self.scan_patt_entry = tk.Entry(input_row, font=("Consolas", 11), bg=BG_MAIN, 
                                        fg=TEXT_MAIN, insertbackground=TEXT_MAIN, relief="flat")
        self.scan_patt_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        btn_scan = tk.Button(input_row, text="Escanear", font=("Segoe UI", 9, "bold"),
                             bg=ACCENT_CYAN, fg=BG_MAIN, relief="flat", padx=15, pady=3,
                             command=self._scan_aob_action)
        btn_scan.pack(side=tk.RIGHT)

        batch_row = tk.Frame(ctrl_card, bg=BG_CARD_LIGHT, padx=10, pady=6)
        batch_row.pack(fill=tk.X)

        tk.Label(batch_row, text="Actualizador por Lotes:", font=("Segoe UI", 9, "bold"),
                 bg=BG_CARD_LIGHT, fg=TEXT_MAIN).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(batch_row, text="Cargar Perfil JSON", font=("Segoe UI", 8, "bold"),
                  bg=BG_CARD, fg=TEXT_MAIN, relief="flat", padx=8, pady=2,
                  command=self._load_batch_profile).pack(side=tk.LEFT, padx=3)

        tk.Button(batch_row, text="Auto-Actualizar Offsets", font=("Segoe UI", 8, "bold"),
                  bg=ACCENT_GREEN, fg=BG_MAIN, relief="flat", padx=10, pady=2,
                  command=self._execute_batch_update).pack(side=tk.LEFT, padx=3)

        tk.Button(batch_row, text="Guardar Perfil Actualizado", font=("Segoe UI", 8, "bold"),
                  bg=ACCENT_PURPLE, fg=TEXT_MAIN, relief="flat", padx=10, pady=2,
                  command=self._save_batch_results_json).pack(side=tk.LEFT, padx=3)

        table_frame = tk.Frame(self.tab_scanner, bg=BG_MAIN)
        table_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("name", "old_va", "new_va", "delta", "status")
        self.scan_tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        self.scan_tree.heading("name", text="Funcion / Simbolo")
        self.scan_tree.heading("old_va", text="Offset Anterior")
        self.scan_tree.heading("new_va", text="Nuevo Offset (Actualizado)")
        self.scan_tree.heading("delta", text="Desplazamiento (Delta)")
        self.scan_tree.heading("status", text="Estado de Coincidencia")

        self.scan_tree.column("name", width=300, anchor="w")
        self.scan_tree.column("old_va", width=130, anchor="center")
        self.scan_tree.column("new_va", width=150, anchor="center")
        self.scan_tree.column("delta", width=120, anchor="center")
        self.scan_tree.column("status", width=150, anchor="center")

        sb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.scan_tree.yview)
        self.scan_tree.configure(yscroll=sb.set)
        self.scan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    # -------------------------------------------------------------
    # PESTAÑA 5: STRINGS & XREFS
    # -------------------------------------------------------------
    def _build_strings_tab(self):
        ctrl_frame = tk.Frame(self.tab_strings, bg=BG_CARD, padx=12, pady=10)
        ctrl_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(ctrl_frame, text="Buscar Cadena Literal:", font=("Segoe UI", 10, "bold"), 
                 bg=BG_CARD, fg=TEXT_MAIN).pack(side=tk.LEFT, padx=(0, 8))

        self.str_entry = tk.Entry(ctrl_frame, font=("Segoe UI", 11), bg=BG_MAIN, 
                                  fg=TEXT_MAIN, insertbackground=TEXT_MAIN, relief="flat", width=35)
        self.str_entry.pack(side=tk.LEFT, padx=5)
        self.str_entry.bind("<Return>", lambda e: self._search_strings_action())

        btn_s = tk.Button(ctrl_frame, text="Buscar", font=("Segoe UI", 9, "bold"),
                          bg=ACCENT_CYAN, fg=BG_MAIN, relief="flat", padx=12, pady=2,
                          command=self._search_strings_action)
        btn_s.pack(side=tk.LEFT, padx=5)

        table_frame = tk.Frame(self.tab_strings, bg=BG_MAIN)
        table_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("addr_hex", "type", "value")
        self.strings_tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.strings_tree.heading("addr_hex", text="Direccion (Hex / VA)")
        self.strings_tree.heading("type", text="Origen")
        self.strings_tree.heading("value", text="Valor de la Cadena (String)")

        self.strings_tree.column("addr_hex", width=140, anchor="center")
        self.strings_tree.column("type", width=160, anchor="center")
        self.strings_tree.column("value", width=700, anchor="w")

        sb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.strings_tree.yview)
        self.strings_tree.configure(yscroll=sb.set)
        self.strings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def _search_strings_action(self):
        q = self.str_entry.get().strip()
        if not q: return
        results = self.parser.search_strings(q, max_results=100)
        for item in self.strings_tree.get_children():
            self.strings_tree.delete(item)
        for r in results:
            self.strings_tree.insert("", tk.END, values=(r["address_hex_upper"], r["type"], r["value"]))
        self.footer_lbl.config(text=f"Cadenas '{q}': {len(results)} resultados.")

    # -------------------------------------------------------------
    # CONTROLADORES DE ARCHIVOS (dump.cs, script.json, Binary)
    # -------------------------------------------------------------
    def _browse_dump_cs(self):
        path = filedialog.askopenfilename(title="Seleccionar dump.cs", filetypes=[("C# Dump", "*.cs"), ("Todos", "*.*")])
        if path:
            self._load_dump_cs_thread(path)

    def _browse_script_json(self):
        path = filedialog.askopenfilename(title="Seleccionar script.json", filetypes=[("JSON Script", "*.json"), ("Todos", "*.*")])
        if path:
            self._load_script_json_thread(path)

    def _browse_binary(self):
        path = filedialog.askopenfilename(title="Seleccionar Binario", filetypes=[("Binarios", "*UnityFramework*;*.so;*.dll;*.dylib"), ("Todos", "*.*")])
        if path:
            self._load_binary_file(path)

    def _choose_folder(self):
        folder = filedialog.askdirectory(title="Seleccionar Carpeta Il2Cpp")
        if folder:
            self._load_folder_thread(folder)

    def _load_dump_cs_thread(self, path):
        self.badge_status.config(text="[PARSEANDO DUMP.CS...]", fg=ACCENT_PURPLE)
        def run():
            count = self.parser.load_dump_cs(path)
            def update_ui():
                self.lbl_dump_cs.config(text=f"{os.path.basename(path)} ({count:,})", fg=ACCENT_GREEN)
                self._update_status_badge()
                self._perform_dash_search()
            self.after(0, update_ui)
        threading.Thread(target=run, daemon=True).start()

    def _load_script_json_thread(self, path):
        self.badge_status.config(text="[CARGANDO SCRIPT.JSON...]", fg=ACCENT_PURPLE)
        def run():
            stats = self.parser.load_script_json(path)
            def update_ui():
                m_count = stats.get("methods", 0)
                self.lbl_script_json.config(text=f"{os.path.basename(path)} ({m_count:,})", fg=ACCENT_GREEN)
                self._update_status_badge()
                self._perform_dash_search()
            self.after(0, update_ui)
        threading.Thread(target=run, daemon=True).start()

    def _load_binary_file(self, path):
        try:
            self.bin_reader = BinaryReader(path)
            self.aob_engine = AOBEngine(self.bin_reader)
            self.scanner = PatternScanner(self.bin_reader)
            self.xref_engine = XRefEngine(self.parser, self.bin_reader)
            self.migrator = VersionMigrator(self.scanner)
            
            info = self.bin_reader.get_info()
            self.lbl_binary.config(text=f"{info['filename']} ({info['filesize_mb']} MB)", fg=ACCENT_GREEN)
            self._update_status_badge()
            
            if self.current_selected_method:
                self._update_power_hub(self.current_selected_method)
        except Exception as e:
            messagebox.showerror("Error al cargar binario", str(e))

    def _load_folder_thread(self, folder):
        self.badge_status.config(text="[AUTO-CARGANDO CARPETA...]", fg=ACCENT_PURPLE)
        def run():
            s_json = os.path.join(folder, "script.json")
            d_cs = os.path.join(folder, "dump.cs")
            str_json = os.path.join(folder, "stringliteral.json")

            if os.path.exists(s_json):
                self.parser.load_script_json(s_json)
            if os.path.exists(d_cs):
                self.parser.load_dump_cs(d_cs)
            if os.path.exists(str_json):
                self.parser.load_stringliteral_json(str_json)

            bin_p = None
            for b in ["UnityFramework", "libil2cpp.so", "GameAssembly.dll"]:
                candidate = os.path.join(folder, b)
                if os.path.exists(candidate):
                    bin_p = candidate
                    break

            def update_ui():
                if os.path.exists(s_json):
                    self.lbl_script_json.config(text=f"script.json ({len(self.parser.methods):,})", fg=ACCENT_GREEN)
                if os.path.exists(d_cs):
                    self.lbl_dump_cs.config(text=f"dump.cs ({len(self.parser.methods):,})", fg=ACCENT_GREEN)
                if bin_p:
                    self._load_binary_file(bin_p)
                self._update_status_badge()
                self.dash_search_entry.insert(0, "TakeDamage")
                self._perform_dash_search()

            self.after(0, update_ui)
        threading.Thread(target=run, daemon=True).start()

    def _auto_detect_freefire(self):
        candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "freefire"),
            os.path.join(os.getcwd(), "freefire"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "freefire")
        ]
        for c in candidates:
            if os.path.exists(c):
                self._load_folder_thread(c)
                break

    def _update_status_badge(self):
        m_count = len(self.parser.methods)
        b_loaded = self.bin_reader is not None
        if m_count > 0 and b_loaded:
            self.badge_status.config(text=f"[LISTO: {m_count:,} Metodos | Binario OK]", fg=ACCENT_GREEN)
        elif m_count > 0:
            self.badge_status.config(text=f"[METODOS CARGADOS: {m_count:,} | FALTA BINARIO]", fg=ACCENT_ORANGE)
        elif b_loaded:
            self.badge_status.config(text=f"[BINARIO CARGADO | FALTA DUMP/SCRIPT]", fg=ACCENT_ORANGE)
        else:
            self.badge_status.config(text="[ESPERANDO ARCHIVOS]", fg=TEXT_MUTED)

    # -------------------------------------------------------------
    # BUSQUEDA AVANZADA CON SCORING Y FILTROS DE TIPOS
    # -------------------------------------------------------------
    def _on_search_keyrelease(self):
        if self._search_timer is not None:
            self.after_cancel(self._search_timer)
        self._search_timer = self.after(120, self._perform_dash_search)

    def _perform_dash_search(self):
        query = self.dash_search_entry.get().strip()
        if not query:
            return
        
        stype = self.dash_search_type.get()
        ret_type = self.ret_type_filter_var.get()
        acc = self.access_filter_var.get()

        results, elapsed_ms = self.parser.search_methods_advanced(
            query, 
            max_results=150, 
            search_type=stype,
            return_type_filter=ret_type,
            access_filter=acc
        )
        self.current_search_results = results
        self.perf_lbl.config(text=f"{elapsed_ms:.1f} ms")
        self._populate_results_table(results, f"Busqueda '{query}': {len(results)} resultados encontrados.")

    def _search_by_cheat_category(self, cat_key):
        results = self.parser.search_category(cat_key, max_results=150)
        self.current_search_results = results
        self.perf_lbl.config(text=f"< 1 ms")
        self._populate_results_table(results, f"Categoria '{cat_key}': {len(results)} metodos encontrados.")

    def _populate_results_table(self, results, status_text=""):
        for item in self.dash_tree.get_children():
            self.dash_tree.delete(item)

        for r in results:
            fields_label = f"{r.get('field_count', 0)}" if r.get('has_fields') else "-"
            self.dash_tree.insert("", tk.END, values=(
                r["address_hex_upper"],
                r["class_name"] or "Global",
                r["clean_name"],
                fields_label,
                r.get("source", "Il2Cpp"),
                r.get("signature", "")
            ))

        self.footer_lbl.config(text=status_text)
        children = self.dash_tree.get_children()
        if children:
            self.dash_tree.selection_set(children[0])
            self._on_method_selected(None)

    def _on_method_selected(self, event):
        sel = self.dash_tree.selection()
        if not sel:
            return
        vals = self.dash_tree.item(sel[0])["values"]
        addr_hex = vals[0]
        c_name = vals[1]
        m_name = vals[2]
        sig = vals[5] if len(vals) > 5 else ""
        
        try:
            addr_int = int(addr_hex, 16)
        except Exception:
            addr_int = 0

        method_info = {
            "name": f"{c_name}$${m_name}" if c_name != "Global" else m_name,
            "class_name": c_name,
            "clean_name": m_name,
            "address": addr_int,
            "address_hex": addr_hex,
            "address_hex_upper": addr_hex,
            "signature": sig
        }
        self.current_selected_method = method_info
        self._update_power_hub(method_info)

    def _update_power_hub(self, m):
        self.lbl_sel_name.config(text=f"{m['class_name']} -> {m['clean_name']}")
        self.lbl_sel_offset.config(text=f"Offset / RVA: {m['address_hex_upper']}  |  Decimal: {m['address']}")

        # 1. AOB Generation & Uniqueness
        if self.aob_engine and self.bin_reader:
            res = self.aob_engine.generate_aob(m['address'], length=24, mask_relative=True, ensure_unique=True)
            if "error" not in res:
                self.aob_dash_entry.delete(0, tk.END)
                self.aob_dash_entry.insert(0, res["active_pattern"])
                
                if res["is_unique"]:
                    self.aob_badge.config(text="[100% UNICO - 1 Coincidencia]", fg=ACCENT_GREEN)
                else:
                    self.aob_badge.config(text=f"[Multiples: {res['matches_count']}]", fg=ACCENT_ORANGE)

                dis_lines = []
                for d in res.get("disassembly", [])[:5]:
                    dis_lines.append(f"{d['offset']}:  {d['bytes']:<14} |  {d['asm']}")
                self.dash_disasm_lbl.config(text="\n".join(dis_lines) if dis_lines else "Sin opcodes")

                # Analisis Heuristico
                analysis = res.get("analysis", {})
                sum_text = f"Analisis: {analysis.get('summary', 'Normal')}\n"
                if analysis.get('callees'):
                    sum_text += f"Llamadas: {', '.join(analysis['callees'][:3])}\n"
                if analysis.get('field_access'):
                    sum_text += f"Acceso: {analysis['field_access']}"
                self.dash_analysis_lbl.config(text=sum_text)
            else:
                self.aob_dash_entry.delete(0, tk.END)
                self.aob_dash_entry.insert(0, "Error leyendo memoria")
                self.aob_badge.config(text="[Error]", fg=TEXT_MUTED)
                self.dash_disasm_lbl.config(text="No se pudieron leer opcodes en esta direccion.")
                self.dash_analysis_lbl.config(text="Sin analisis disponible.")

            # 2. Hex Dump View (Inspector de Memoria Cruda)
            hex_dump_lines = self.bin_reader.get_hex_dump(m['address'], length=48)
            self.dash_hexdump_lbl.config(text="\n".join(hex_dump_lines[:3]))
        else:
            self.aob_dash_entry.delete(0, tk.END)
            self.aob_dash_entry.insert(0, "Carga el binario para generar AOB")
            self.aob_badge.config(text="[Falta Binario]", fg=TEXT_MUTED)
            self.dash_disasm_lbl.config(text="Carga UnityFramework o libil2cpp.so arriba.")
            self.dash_analysis_lbl.config(text="Carga el binario para analisis.")
            self.dash_hexdump_lbl.config(text="Carga el archivo binario para ver Hex Dump.")

        self._refresh_code_output()

    def _refresh_code_output(self):
        if not self.current_selected_method:
            return
        m = self.current_selected_method
        preset_key = self.patch_preset_var.get()

        if preset_key == "CUSTOM_FLOAT":
            try:
                val = float(self.custom_val_entry.get().strip() or "1.0")
                patch_hex, _ = PatchGenerator.assemble_custom_float_arm64(val)
            except Exception:
                patch_hex = "00 10 2E 1E C0 03 5F D6"
        elif preset_key == "CUSTOM_INT":
            try:
                val = int(self.custom_val_entry.get().strip() or "1")
                patch_hex, _ = PatchGenerator.assemble_custom_int_arm64(val)
            except Exception:
                patch_hex = "20 00 80 D2 C0 03 5F D6"
        else:
            preset = PatchGenerator.ARM64_PRESETS.get(preset_key, PatchGenerator.ARM64_PRESETS["RETURN_TRUE"])
            patch_hex = preset["hex"]

        target_b = self.bin_reader.get_info()["filename"] if self.bin_reader else "UnityFramework"
        templates = PatchGenerator.generate_templates(
            m["name"], 
            m["address_hex_upper"], 
            patch_hex, 
            target_binary=target_b, 
            signature=m.get("signature", "")
        )

        for key, txt_box in self.code_boxes.items():
            if key in templates:
                txt_box.delete("1.0", tk.END)
                txt_box.insert("1.0", templates[key])

    # -------------------------------------------------------------
    # MENU CONTEXTUAL (CLICK DERECHO)
    # -------------------------------------------------------------
    def _show_tree_context_menu(self, event):
        item = self.dash_tree.identify_row(event.y)
        if item:
            self.dash_tree.selection_set(item)
            self._on_method_selected(None)
            
            menu = tk.Menu(self, tearoff=0, bg=BG_CARD, fg=TEXT_MAIN, activebackground=ACCENT_CYAN, activeforeground=BG_MAIN)
            menu.add_command(label="Copiar Offset Hex", command=lambda: self._copy_to_clip(self.current_selected_method["address_hex_upper"]))
            menu.add_command(label="Copiar Nombre de Metodo", command=lambda: self._copy_to_clip(self.current_selected_method["name"]))
            menu.add_command(label="Copiar Firma Completa", command=lambda: self._copy_to_clip(self.current_selected_method.get("signature", "")))
            menu.add_separator()
            menu.add_command(label="Copiar Firma AOB", command=lambda: self._copy_to_clip(self.aob_dash_entry.get()))
            menu.add_command(label="Ver Struct de Clase", command=self._view_selected_class_struct)
            menu.add_command(label="Guardar Funcion", command=self._save_current_to_hacks)
            menu.tk_popup(event.x_root, event.y_root)

    # -------------------------------------------------------------
    # EXPORTADOR DE RESULTADOS DE BUSQUEDA
    # -------------------------------------------------------------
    def _export_search_results_dialog(self):
        if not self.current_search_results:
            messagebox.showwarning("Aviso", "No hay resultados de busqueda para exportar.")
            return

        path = filedialog.asksaveasfilename(
            title="Exportar Resultados de Busqueda",
            defaultextension=".csv",
            filetypes=[
                ("Archivo CSV (*.csv)", "*.csv"),
                ("Cabecera C++ (*.h)", "*.h"),
                ("Clase C# (*.cs)", "*.cs"),
                ("Archivo JSON (*.json)", "*.json")
            ]
        )
        if not path:
            return

        ext = os.path.splitext(path)[1].lower()
        if ext == ".csv":
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Address_Hex", "Class", "Method", "Source", "Signature"])
                for r in self.current_search_results:
                    writer.writerow([r["address_hex_upper"], r.get("class_name", ""), r.get("clean_name", ""), r.get("source", ""), r.get("signature", "")])
        elif ext == ".h":
            with open(path, "w", encoding="utf-8") as f:
                f.write("// AUTO-GENERATED IL2CPP OFFSETS HEADER\n#ifndef SEARCH_OFFSETS_H\n#define SEARCH_OFFSETS_H\n\n#include <stdint.h>\n\n")
                for r in self.current_search_results:
                    clean = re.sub(r'[^A-Za-z0-9_]', '_', r['name']).strip('_')
                    f.write(f"#define OFFSET_{clean.upper()} {r['address_hex_upper']} // {r.get('signature', '')}\n")
                f.write("\n#endif\n")
        elif ext == ".cs":
            with open(path, "w", encoding="utf-8") as f:
                f.write("// AUTO-GENERATED C# OFFSETS CLASS\npublic static class SearchOffsets\n{\n")
                for r in self.current_search_results:
                    clean = re.sub(r'[^A-Za-z0-9_]', '_', r['name']).strip('_')
                    f.write(f"    public const long {clean} = {r['address_hex_upper']};\n")
                f.write("}\n")
        elif ext == ".json":
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.current_search_results, f, indent=2)

        messagebox.showinfo("Exportado", f"Se exportaron {len(self.current_search_results)} resultados en:\n{path}")

    # -------------------------------------------------------------
    # FUNCIONES GUARDADAS CON PERSISTENCIA
    # -------------------------------------------------------------
    def _save_current_to_hacks(self):
        if not self.current_selected_method:
            messagebox.showinfo("Informacion", "Selecciona primero un metodo en la tabla.")
            return
        m = self.current_selected_method
        aob = self.aob_dash_entry.get().strip()
        preset = self.patch_preset_var.get()

        item = {
            "name": m["name"],
            "clean_name": m["clean_name"],
            "class_name": m["class_name"],
            "offset_hex": m["address_hex_upper"],
            "patch_type": preset,
            "signature": m.get("signature", ""),
            "pattern": aob
        }
        self.my_hacks_profile.append(item)
        self.my_hacks_tree.insert("", tk.END, values=(item["name"], item["offset_hex"], item["patch_type"], item["pattern"]))
        self._save_bookmarks_to_disk()
        messagebox.showinfo("Funcion Guardada", f"'{m['clean_name']}' guardado correctamente.")

    def _delete_selected_hack(self):
        sel = self.my_hacks_tree.selection()
        if not sel: return
        idx = self.my_hacks_tree.index(sel[0])
        self.my_hacks_tree.delete(sel[0])
        if 0 <= idx < len(self.my_hacks_profile):
            self.my_hacks_profile.pop(idx)
        self._save_bookmarks_to_disk()

    def _clear_my_hacks(self):
        self.my_hacks_profile.clear()
        for item in self.my_hacks_tree.get_children():
            self.my_hacks_tree.delete(item)
        self._save_bookmarks_to_disk()

    def _save_bookmarks_to_disk(self):
        try:
            os.makedirs(os.path.dirname(self.bookmarks_file), exist_ok=True)
            with open(self.bookmarks_file, "w", encoding="utf-8") as f:
                json.dump(self.my_hacks_profile, f, indent=2)
        except Exception:
            pass

    def _load_saved_bookmarks(self):
        if os.path.exists(self.bookmarks_file):
            try:
                with open(self.bookmarks_file, "r", encoding="utf-8") as f:
                    self.my_hacks_profile = json.load(f)
                for item in self.my_hacks_profile:
                    self.my_hacks_tree.insert("", tk.END, values=(item["name"], item["offset_hex"], item["patch_type"], item.get("pattern", "")))
            except Exception:
                pass

    def _save_snippet_file(self, content, extension):
        if not content.strip():
            return
        m_name = self.current_selected_method["clean_name"] if self.current_selected_method else "snippet"
        path = filedialog.asksaveasfilename(
            initialfile=f"{m_name}{extension}",
            defaultextension=extension,
            filetypes=[(f"Archivos {extension}", f"*{extension}"), ("Todos", "*.*")]
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Guardado", f"Archivo guardado con exito en:\n{path}")

    def _export_full_dylib(self):
        if not self.my_hacks_profile:
            messagebox.showwarning("Aviso", "No hay funciones en la lista para exportar.")
            return
        
        target_b = self.bin_reader.get_info()["filename"] if self.bin_reader else "UnityFramework"
        code = f"""#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#include <substrate.h>

"""
        for h in self.my_hacks_profile:
            clean = h["clean_name"].replace("$", "_").replace("<", "_").replace(">", "_").replace(".", "_")
            ret_t, params = PatchGenerator.parse_signature(h.get("signature", ""), h["name"])
            cpp_ret = PatchGenerator._map_type_to_cpp(ret_t)
            cpp_param_decl = ", ".join([f"{pt} {pn}" for pt, pn in params])
            cpp_param_names = ", ".join([pn for pt, pn in params])

            code += f"#define OFFSET_{clean.upper()} {h['offset_hex']}\n"
            code += f"typedef {cpp_ret} (*t_{clean})({cpp_param_decl});\n"
            code += f"static t_{clean} orig_{clean} = nullptr;\n"
            code += f"static bool b_{clean} = false;\n\n"
            code += f"{cpp_ret} hook_{clean}({cpp_param_decl}) {{\n"
            code += f"    if (b_{clean}) {{\n"
            if h["patch_type"] == "RETURN_TRUE":
                code += "        return (bool)true;\n"
            elif h["patch_type"] == "RETURN_FALSE":
                code += "        return (bool)false;\n"
            elif h["patch_type"] == "RETURN_ZERO":
                code += f"        return ({cpp_ret})0;\n"
            elif "FLOAT" in h["patch_type"]:
                code += "        return 100.0f;\n"
            else:
                code += "        // Logica personalizada\n"
            code += "    }\n"
            code += f"    return orig_{clean}({cpp_param_names});\n"
            code += "}\n\n"

        code += f"""void init_hooks() {{
    uintptr_t base = _dyld_get_image_vmaddr_slide(0);
"""
        for h in self.my_hacks_profile:
            clean = h["clean_name"].replace("$", "_").replace("<", "_").replace(">", "_").replace(".", "_")
            code += f"    MSHookFunction((void*)(base + OFFSET_{clean.upper()}), (void*)hook_{clean}, (void**)&orig_{clean});\n"
        code += "}\n"

        path = filedialog.asksaveasfilename(defaultextension=".mm", filetypes=[("Objective-C++ / Theos", "*.mm;*.cpp")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(code)
            messagebox.showinfo("Exportado", f"Dylib C++ exportado con exito en:\n{path}")

    def _export_full_android_mod(self):
        if not self.my_hacks_profile:
            messagebox.showwarning("Aviso", "No hay funciones para exportar.")
            return

        target_b = self.bin_reader.get_info()["filename"] if self.bin_reader else "libil2cpp.so"
        code = f"""#include <jni.h>
#include <dlfcn.h>
#include "KittyMemory/MemoryPatch.h"
#include "imgui.h"

"""
        for h in self.my_hacks_profile:
            clean = h["clean_name"].replace("$", "_").replace("<", "_").replace(">", "_").replace(".", "_")
            code += f"static MemoryPatch patch_{clean} = MemoryPatch::createWithHex(\"{target_b}\", {h['offset_hex']}, \"200080D2C0035FD6\");\n"
            code += f"static bool b_{clean} = false;\n\n"

        code += """void DrawMenu() {
    ImGui::Begin("Menu");
"""
        for h in self.my_hacks_profile:
            clean = h["clean_name"].replace("$", "_").replace("<", "_").replace(">", "_").replace(".", "_")
            code += f"    if (ImGui::Checkbox(\"{h['clean_name']}\", &b_{clean})) {{\n"
            code += f"        if (b_{clean}) patch_{clean}.Modify(); else patch_{clean}.Restore();\n"
            code += f"    }}\n"
        code += "    ImGui::End();\n}\n"

        path = filedialog.asksaveasfilename(defaultextension=".cpp", filetypes=[("C++ Source", "*.cpp")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(code)
            messagebox.showinfo("Exportado", f"Android C++ exportado con exito en:\n{path}")

    def _export_full_csharp_mod(self):
        if not self.my_hacks_profile:
            messagebox.showwarning("Aviso", "No hay funciones para exportar.")
            return

        code = """using System;
using HarmonyLib;
using UnityEngine;

namespace MyMod
{
"""
        for h in self.my_hacks_profile:
            c_name = h.get("class_name", "GameClass")
            s_name = h["clean_name"]
            clean = s_name.replace("$", "_").replace("<", "_").replace(">", "_").replace(".", "_")

            code += f"""    [HarmonyPatch(typeof({c_name}), "{s_name}")]
    public class Patch_{clean}
    {{
        [HarmonyPrefix]
        public static bool Prefix()
        {{
"""
            if h["patch_type"] == "RETURN_TRUE":
                code += "            return false;\n"
            elif h["patch_type"] == "RETURN_FALSE":
                code += "            return false;\n"
            else:
                code += "            return true;\n"
            code += "        }\n    }\n\n"

        code += "}\n"

        path = filedialog.asksaveasfilename(defaultextension=".cs", filetypes=[("C# Script", "*.cs")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(code)
            messagebox.showinfo("Exportado", f"Mod en C# exportado con exito en:\n{path}")

    def _export_full_gg(self):
        if not self.my_hacks_profile:
            messagebox.showwarning("Aviso", "No hay funciones para exportar.")
            return

        target_b = self.bin_reader.get_info()["filename"] if self.bin_reader else "UnityFramework"
        code = f"""local base = gg.getRangesList("{target_b}")[1].start

function MainMenu()
    local menu = gg.choice({{
"""
        for h in self.my_hacks_profile:
            code += f'        "Activar {h["clean_name"]}",\n'
        code += """        "Salir"
    }, nil, "Menu")

    if menu == nil then return end
"""
        for idx, h in enumerate(self.my_hacks_profile, 1):
            code += f"""    if menu == {idx} then
        gg.setValues({{{{address = base + {h['offset_hex']}, flags = gg.TYPE_DWORD, value = "~A 20 00 80 D2"}}}})
    end
"""
        code += "end\n\nwhile true do\n    if gg.isVisible() then\n        gg.setVisible(false)\n        MainMenu()\n    end\n    gg.sleep(100)\nend\n"

        path = filedialog.asksaveasfilename(defaultextension=".lua", filetypes=[("GameGuardian Script", "*.lua")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(code)
            messagebox.showinfo("Exportado", f"Script GameGuardian exportado con exito en:\n{path}")

    def _export_full_header(self):
        if not self.my_hacks_profile:
            messagebox.showwarning("Aviso", "No hay funciones para exportar.")
            return
        code = "#ifndef OFFSETS_H\n#define OFFSETS_H\n\n"
        for h in self.my_hacks_profile:
            clean = h["clean_name"].replace("$", "_").replace("<", "_").replace(">", "_").replace(".", "_")
            code += f"#define OFFSET_{clean.upper()} {h['offset_hex']}\n"
        code += "\n#endif\n"

        path = filedialog.asksaveasfilename(defaultextension=".h", filetypes=[("C/C++ Header", "*.h")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(code)
            messagebox.showinfo("Exportado", f"Cabecera C++ guardada en:\n{path}")

    def _scan_aob_action(self):
        if not self.scanner:
            messagebox.showwarning("Aviso", "Carga el binario primero.")
            return
        patt = self.scan_patt_entry.get().strip()
        if not patt: return

        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)

        matches = self.scanner.scan_pattern(patt, max_results=50)
        for m in matches:
            self.scan_tree.insert("", tk.END, values=(
                "Firma Manual",
                "N/A",
                m["address_hex_upper"],
                "0x0",
                "COINCIDENCIA"
            ))
        self.footer_lbl.config(text=f"Escaneo AOB completado: {len(matches)} coincidencias encontradas.")

    def _load_batch_profile(self):
        p = filedialog.askopenfilename(filetypes=[("Archivos JSON", "*.json"), ("Todos", "*.*")])
        if p:
            with open(p, "r", encoding="utf-8") as f:
                self.saved_profile = json.load(f)
            messagebox.showinfo("Perfil Cargado", f"{len(self.saved_profile)} firmas AOB cargadas.")

    def _execute_batch_update(self):
        if not self.scanner:
            messagebox.showwarning("Aviso", "Binario no cargado.")
            return
        if not self.saved_profile:
            messagebox.showinfo("Informacion", "Carga un perfil JSON primero.")
            return

        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)

        self.batch_updated_results = self.scanner.batch_update_offsets(self.saved_profile)
        for u in self.batch_updated_results:
            self.scan_tree.insert("", tk.END, values=(
                u.get("name", ""),
                u.get("old_address", "N/A"),
                u.get("new_address_hex", "N/A"),
                u.get("delta", "N/A"),
                u.get("status", "")
            ))
        self.footer_lbl.config(text=f"Actualizacion por lotes finalizada ({len(self.batch_updated_results)} elementos).")

    def _save_batch_results_json(self):
        if not hasattr(self, 'batch_updated_results') or not self.batch_updated_results:
            messagebox.showwarning("Aviso", "No hay resultados de actualizacion para guardar.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Archivos JSON", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.batch_updated_results, f, indent=2)
            messagebox.showinfo("Guardado", f"Perfil actualizado guardado en:\n{path}")

    def _copy_to_clip(self, text):
        self.clipboard_clear()
        self.clipboard_append(text.strip())
        messagebox.showinfo("Copiado", "Copiado al portapapeles con exito.")

if __name__ == "__main__":
    app = AutoOffsetUltimateTool()
    app.mainloop()
