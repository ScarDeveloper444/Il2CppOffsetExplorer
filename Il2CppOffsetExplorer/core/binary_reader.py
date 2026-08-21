import struct
import mmap
import os
from typing import Optional, List, Tuple, Dict, Any
from core.disassembler import SimpleARM64Disassembler, SimpleARM32Disassembler

class BinaryReader:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filesize = os.path.getsize(filepath)
        self.format_type = "UNKNOWN"
        self.arch = "ARM64"
        self.is_64bit = True
        self.segments: List[Tuple[str, int, int, int, int]] = [] # (name, vmaddr, vmsize, fileoff, filesize)
        self.file_handle = open(filepath, 'rb')
        self.mm = mmap.mmap(self.file_handle.fileno(), 0, access=mmap.ACCESS_READ)
        self._parse_headers()

    def close(self):
        if self.mm:
            self.mm.close()
        if self.file_handle:
            self.file_handle.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _parse_headers(self):
        magic = self.mm[:4]
        if magic == b'\xcf\xfa\xed\xfe' or magic == b'\xfe\xed\xfa\xcf':
            self.format_type = "Mach-O 64-bit (iOS)"
            self.arch = "ARM64"
            self.is_64bit = True
            self._parse_macho_64(0)
        elif magic == b'\xca\xfe\xba\xbe' or magic == b'\xbe\xba\xfe\xca':
            self.format_type = "Fat Mach-O Universal (iOS)"
            self._parse_fat_macho()
        elif magic == b'\x7fELF':
            ei_class = self.mm[4]
            self.is_64bit = (ei_class == 2)
            self.arch = "ARM64 / AArch64" if self.is_64bit else "ARM32 / ARMv7"
            self.format_type = "ELF 64-bit (Android)" if self.is_64bit else "ELF 32-bit (Android)"
            self._parse_elf()
        elif magic[:2] == b'MZ':
            self.format_type = "PE Executable (Windows)"
            self.arch = "x86_64"
            self.is_64bit = True
            self._parse_pe()
        else:
            self.format_type = "Raw Binary"
            self.segments.append(("RAW", 0, self.filesize, 0, self.filesize))

    def _parse_macho_64(self, base_offset: int):
        header = self.mm[base_offset:base_offset+32]
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack('<IIIIIIII', header)
        offset = base_offset + 32
        for _ in range(ncmds):
            if offset + 8 > self.filesize:
                break
            cmd, cmdsize = struct.unpack('<II', self.mm[offset:offset+8])
            if cmd == 0x19: # LC_SEGMENT_64
                seg_data = self.mm[offset+8:offset+cmdsize]
                segname = seg_data[:16].decode('utf-8', errors='ignore').rstrip('\x00')
                vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', seg_data[16:48])
                self.segments.append((segname, vmaddr, vmsize, base_offset + fileoff, filesize))
            offset += cmdsize

    def _parse_fat_macho(self):
        nfat_arch, = struct.unpack('>I', self.mm[4:8])
        for i in range(nfat_arch):
            off = 8 + i * 20
            cputype, cpusubtype, offset, size, align = struct.unpack('>IIIII', self.mm[off:off+20])
            if cputype == 0x0100000C: # CPU_TYPE_ARM64
                self.arch = "ARM64"
                self._parse_macho_64(offset)
                return
        if nfat_arch > 0:
            cputype, cpusubtype, offset, size, align = struct.unpack('>IIIII', self.mm[8:28])
            self._parse_macho_64(offset)

    def _parse_elf(self):
        if self.is_64bit:
            e_phoff, = struct.unpack('<Q', self.mm[32:40])
            e_phentsize, e_phnum = struct.unpack('<HH', self.mm[54:58])
            for i in range(e_phnum):
                off = e_phoff + (i * e_phentsize)
                p_type, p_flags = struct.unpack('<II', self.mm[off:off+8])
                if p_type == 1: # PT_LOAD
                    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack('<QQQQQ', self.mm[off+8:off+48])
                    self.segments.append((f"PT_LOAD_{i}", p_vaddr, p_memsz, p_offset, p_filesz))
        else:
            e_phoff, = struct.unpack('<I', self.mm[28:32])
            e_phentsize, e_phnum = struct.unpack('<HH', self.mm[42:46])
            for i in range(e_phnum):
                off = e_phoff + (i * e_phentsize)
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack('<IIIIII', self.mm[off:off+24])
                if p_type == 1: # PT_LOAD
                    self.segments.append((f"PT_LOAD_{i}", p_vaddr, p_memsz, p_offset, p_filesz))

    def _parse_pe(self):
        pe_offset, = struct.unpack('<I', self.mm[0x3C:0x40])
        num_sections, = struct.unpack('<H', self.mm[pe_offset+6:pe_offset+8])
        opt_hdr_size, = struct.unpack('<H', self.mm[pe_offset+20:pe_offset+22])
        sec_start = pe_offset + 24 + opt_hdr_size
        for i in range(num_sections):
            soff = sec_start + (i * 40)
            name = self.mm[soff:soff+8].decode('utf-8', errors='ignore').rstrip('\x00')
            vsize, vaddr, raw_size, raw_ptr = struct.unpack('<IIII', self.mm[soff+8:soff+24])
            self.segments.append((name, vaddr, vsize, raw_ptr, raw_size))

    def vaddr_to_file_offset(self, vaddr: int) -> Optional[int]:
        if not self.segments or self.format_type == "Raw Binary":
            return vaddr if 0 <= vaddr < self.filesize else None

        for name, vmaddr, vmsize, fileoff, filesize in self.segments:
            if vmaddr <= vaddr < (vmaddr + vmsize):
                offset_in_seg = vaddr - vmaddr
                if offset_in_seg < filesize:
                    return fileoff + offset_in_seg

        if 0 <= vaddr < self.filesize:
            return vaddr
        return None

    def file_offset_to_vaddr(self, fileoff: int) -> int:
        for name, vmaddr, vmsize, seg_fileoff, filesize in self.segments:
            if seg_fileoff <= fileoff < (seg_fileoff + filesize):
                return vmaddr + (fileoff - seg_fileoff)
        return fileoff

    def read_bytes(self, vaddr_or_offset: int, length: int, is_vaddr: bool = True) -> bytes:
        offset = self.vaddr_to_file_offset(vaddr_or_offset) if is_vaddr else vaddr_or_offset
        if offset is None or offset < 0 or (offset + length) > self.filesize:
            return b''
        return bytes(self.mm[offset:offset+length])

    def read_cstring(self, vaddr: int, max_length: int = 128) -> str:
        """Lee una cadena C terminada en null desde la memoria"""
        data = self.read_bytes(vaddr, max_length, is_vaddr=True)
        if not data:
            return ""
        null_pos = data.find(b'\x00')
        if null_pos != -1:
            data = data[:null_pos]
        return data.decode('utf-8', errors='ignore')

    def get_hex_dump(self, vaddr: int, length: int = 64) -> List[str]:
        """Genera una vista Hex Dump clásica (Offset | Bytes Hex | ASCII)"""
        data = self.read_bytes(vaddr, length, is_vaddr=True)
        if not data:
            return ["No se pudieron leer datos en memoria."]

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            curr_addr = vaddr + i
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            if len(chunk) < 16:
                hex_part = hex_part.ljust(47)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"0x{curr_addr:08X}:  {hex_part:<48}  |{ascii_part}|")

        return lines

    def disassemble_at(self, vaddr: int, count: int = 16) -> List[Dict[str, Any]]:
        """Desensambla una secuencia de instrucciones en una dirección virtual dada"""
        raw_bytes = self.read_bytes(vaddr, count * 4, is_vaddr=True)
        if not raw_bytes:
            return []
        if self.is_64bit:
            return SimpleARM64Disassembler.disassemble_function(raw_bytes, start_pc=vaddr, max_instructions=count)
        else:
            disasm = []
            for i in range(0, len(raw_bytes) - 3, 4):
                pc = vaddr + i
                chunk = raw_bytes[i:i+4]
                disasm.append({
                    "offset": f"0x{pc:08X}",
                    "bytes": " ".join(f"{b:02X}" for b in chunk),
                    "asm": SimpleARM32Disassembler.decode_instruction(chunk, pc)
                })
            return disasm

    def get_info(self) -> Dict[str, Any]:
        return {
            "filepath": self.filepath,
            "filename": os.path.basename(self.filepath),
            "filesize_mb": round(self.filesize / (1024 * 1024), 2),
            "format": self.format_type,
            "arch": self.arch,
            "segments_count": len(self.segments),
            "segments": [f"{s[0]} (VA: {hex(s[1])}, Off: {hex(s[3])}, Sz: {hex(s[4])})" for s in self.segments]
        }
