# IDAPython loader plugin for SN ProDG relocatable DLL files (*.REL)
# These files begin with a SNR2 (SN Relocatable?) header, followed by a list of relocations, followed by a list of function symbols & addresses

# Sadly the exported symbols only cover a very small amount of the code - likely only the symbols that main & other modules might access
# (the main module of the game also contains a SNR2 header with exported symbols, but again only covers certain parts of the code, too bad)
# Tested with IDA 7.6 & REL files extracted from PS2 version of Biohazard 4 (JP) bio4dat.afs

import io
import idc 
import idaapi
import ida_segment
import ida_bytes
import ida_loader
import ida_typeinf
import ida_ida
import ida_name
import struct
import ctypes
import os
from enum import Enum

_MAGIC_SNR2 = "SNR2"
_FORMAT_SNR2 = "SN ProDG relocatable DLL"

char_t = ctypes.c_char
uint8_t  = ctypes.c_byte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
int32_t = ctypes.c_int

# Debug helpers to let us print(structure)
def StructAsString(self):
  return "{}: {{{}}}".format(self.__class__.__name__,
                             ", ".join(["{}: {}".format(field[0],
                                                        getattr(self,
                                                                field[0]))
                                        for field in self._fields_]))

ctypes.BigEndianStructure.__str__ = StructAsString

class MyStructure(ctypes.Structure):
  pass

MyStructure.__str__ = StructAsString

# PE structs & enums
class SNR2Header(MyStructure):
  _fields_ = [
    ("Magic", uint32_t),
    ("RelocTableAddress", uint32_t),
    ("RelocTableCount", uint32_t),
    ("FuncTableAddress", uint32_t),
    ("FuncTableCount", uint32_t),
    ("OriginalImageNameAddress", uint32_t),
    ("GlobalCtorsAddress", uint32_t),
    ("GlobalDtorsAddress", uint32_t),
    ("ExportsAddress", uint32_t),
    ("ExportsCount", uint32_t),
    ("Unk28", uint32_t),
    ("FileSize", uint32_t),
    ("Unk30", uint32_t),
    ("UnkAddr34", uint32_t),
    ("UnkAddr38", uint32_t)
  ]

class Elf32_Rela(MyStructure):
  _pack_ = 1
  _fields_ = [
    ("r_offset", uint32_t),
    ("r_type", uint8_t), # r_type & r_sym are combined in ELF spec as r_info, that means only 256 imports allowed?
    ("r_sym", uint8_t),
    ("r_addend", int32_t),
    ("PadA", uint16_t),
  ]

class SNR2Function(MyStructure):
  _fields_ = [
    ("NameAddress", uint32_t),
    ("CodeAddress", uint32_t),
    ("Unk8", uint16_t),
    ("Type", uint8_t),
    ("UnkB", uint8_t),
  ]

# MIPS relocation types, from ELF format
# (only seen 2/4/5/6 being used by ProDG so far)
# theres 200+ of these, hopefully not all are used by ProDG: https://code.woboq.org/llvm/llvm/include/llvm/BinaryFormat/ELFRelocs/Mips.def.html
class MIPSRelocationType(Enum):
  NONE = 0
  _16 = 1
  _32 = 2
  REL32 = 3
  _26 = 4
  HI16 = 5
  LO16 = 6

def read_struct(li, struct):
  s = struct()
  slen = ctypes.sizeof(s)
  bytes = li.read(slen)
  fit = min(len(bytes), slen)
  ctypes.memmove(ctypes.addressof(s), bytes, fit)
  return s

def accept_file(li, n):
  li.seek(0)
  magic = li.read(4)
  if magic == bytes(_MAGIC_SNR2, 'utf-8'):
    return _FORMAT_SNR2

  return 0

def load_file(li, neflags, format):
  if format != _FORMAT_SNR2:
    Warning("Unknown format name: '%s'" % format)
    return 0

  idaapi.set_processor_type("r5900l", idc.SETPROC_LOADER)
  ida_typeinf.set_compiler_id(idc.COMP_GNU)

  im = ida_ida.compiler_info_t()
  im.id = ida_typeinf.COMP_GNU
  im.cm = 0x03 | 0x00 | 0x30
  im.defalign = 0
  im.size_i = 4
  im.size_b = 1
  im.size_e = 4
  im.size_s = 2
  im.size_l = 4
  im.size_ll = 8
  im.size_ldbl = 8

  # Resetting new settings :)
  ida_typeinf.set_compiler(im, ida_typeinf.SETCOMP_OVERRIDE)

  print("[+] SN ProDG relocatable DLL loader by emoose")

  li.seek(0)
  snr_header = read_struct(li, SNR2Header)

  # header doesn't actually specify where code/data starts & ends, so we need to try working it our ourselves...
  sndata_ext_addr = snr_header.OriginalImageNameAddress
  if sndata_ext_addr == 0 or sndata_ext_addr > snr_header.RelocTableAddress:
    sndata_ext_addr = snr_header.RelocTableAddress
  if sndata_ext_addr == 0 or sndata_ext_addr > snr_header.FuncTableAddress:
    sndata_ext_addr = snr_header.FuncTableAddress

  li.seek(snr_header.FuncTableAddress)

  funcs = []
  for i in range(0, snr_header.FuncTableCount):
    entry = read_struct(li, SNR2Function)
    funcs.append(entry)
    if sndata_ext_addr == 0 or sndata_ext_addr > entry.NameAddress:
      sndata_ext_addr = entry.NameAddress

  li.seek(snr_header.RelocTableAddress)
  relocs = []
  for i in range(0, snr_header.RelocTableCount):
    entry = read_struct(li, Elf32_Rela)
    relocs.append(entry)

  li.seek(0)
  li.file2base(0, 0, li.size(), 1)
  idaapi.add_segm(0, 0, 0x100, ".sndata", "DATA")
  idaapi.add_segm(0, 0x100, sndata_ext_addr, ".text", "CODE")
  idaapi.add_segm(0, sndata_ext_addr, li.size(), ".sndata2", "DATA")
   # some reason IDA tends to turn first few bytes of sndata_ext_addr to code, why?

  names = []
  for ent in funcs:
    li.seek(ent.NameAddress)
    name = li.getz(256)
    names.append(name)

    if ent.CodeAddress == 0:
      continue

    idc.set_name(ent.CodeAddress, name)

    if "$" not in name and "__CTOR_LIST__" not in name and "__DTOR_LIST__" not in name:
      #print(hex(ent.CodeAddress) + " = " + name + " (" + hex(ent.Unk8) + " - " + hex(ent.Type) + " - " + hex(ent.UnkB) + ")")
      idc.add_func(ent.CodeAddress)

  # Find unique reloc imports
  import_count = 0
  imports = {}
  for reloc in relocs:
    reloc_dest_name = names[reloc.r_sym]

    if reloc_dest_name not in imports:
        imports[reloc_dest_name] = import_count
        import_count = import_count + 1

  # import_count is how many unique imports there are - make a segment for them
  import_seg_size = import_count * 4
  import_seg_addr = int((li.size() + 3) / 4) * 4
  if import_seg_size > 0:
    idaapi.add_segm(1, import_seg_addr, import_seg_addr + import_seg_size, ".ref", "XTRN")

    # add & name imports
    for name, index in imports.items():
      ida_name.force_name(import_seg_addr + (index * 4), name)

    # fixup relocs
    for reloc in relocs:
      reloc_dest_name = names[reloc.r_sym]
      reloc_dest_impidx = imports[reloc_dest_name]
      reloc_dest_addr = import_seg_addr + (reloc_dest_impidx * 4)

      r_type_str = hex(reloc.r_type)

      if reloc.r_type == MIPSRelocationType._32.value: # 32-bit address
        ida_bytes.patch_dword(reloc.r_offset, reloc_dest_addr)

      elif reloc.r_type == MIPSRelocationType._26.value: # 26-bit address?
        reloc_dest_addr = int(reloc_dest_addr / 4)
        reloc_orig_dword = ida_bytes.get_dword(reloc.r_offset)
        reloc_new_opcode = reloc_orig_dword | reloc_dest_addr
        ida_bytes.patch_dword(reloc.r_offset, reloc_new_opcode)

      elif reloc.r_type == MIPSRelocationType.HI16.value: # upper 16-bits, plus 1
        reloc_upper_bits = reloc_dest_addr >> 16
        reloc_upper_bits = reloc_upper_bits + 1
        ida_bytes.patch_word(reloc.r_offset, reloc_upper_bits)

      elif reloc.r_type == MIPSRelocationType.LO16.value: # lower 16-bits
        reloc_lower_bits = reloc_dest_addr & 0xFFFF
        ida_bytes.patch_word(reloc.r_offset, reloc_lower_bits)

      else:
        r_type_str = hex(reloc.r_type) + " (UNHANDLED!)"
        idc.set_cmt(reloc.r_offset, "r_type = " + r_type_str, 1)
        print("[!] Unhandled reloc type " + str(reloc.r_type) + " @ " + hex(reloc.r_offset) + " -> " + hex(reloc_dest_addr) + " (" + reloc_dest_name + ")")

      # comment about weird r_addend that we don't handle atm
      if reloc.r_addend != 0:
        idc.set_cmt(reloc.r_offset, "r_type = " + r_type_str + ", r_addend = " + hex(reloc.r_addend) + " (UNHANDLED!)", 1)

  # print some totals to console
  print("[+] Found " + str(len(funcs)) + " SNR2Function defs")
  print("[+] Found " + str(len(relocs)) + " Elf32_Rela defs")
  if import_count > 0:
    print("[+] Found " + str(import_count) + " imports")

  # Done :)
  print("[+] REL loaded, voila!")
  return 1
