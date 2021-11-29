# IDAPython loader plugin for SN ProDG relocatable DLL files (*.REL)
# These files begin with a SNR2 (SN Relocatable?) header, followed by lists of exported symbol names/addresses
# (likely contains info about relocation too, and imports from the main module & other DLLs, but those aren't implemented here yet)

# Sadly the exported symbols only cover a very small amount of the code - likely just the symbols that main & other modules might access
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
import struct
import ctypes
import os

_MAGIC_SNR2 = "SNR2"
_FORMAT_SNR2 = "SN ProDG relocatable DLL"

char_t = ctypes.c_char
uint8_t  = ctypes.c_byte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint

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
    ("Table1Offset", uint32_t),
    ("Table1Count", uint32_t),
    ("Table2Offset", uint32_t),
    ("Table2Count", uint32_t),
    ("ImagePathAddress", uint32_t),
    ("GlobalCtorsAddress", uint32_t),
    ("GlobalDtorsAddress", uint32_t),
    ("ExportsAddress", uint32_t),
    ("ExportsCount", uint32_t),
    ("Unk28", uint32_t),
    ("FileSize", uint32_t),
    ("Unk30", uint32_t),
    ("UnkAddr34", uint32_t),
    ("UnkAddr38", uint32_t),
    ("Pad3C", uint32_t),
  ]
  
class SNR2Table2Entry(MyStructure):
  _fields_ = [
    ("NameOffset", uint32_t),
    ("CodeOffset", uint32_t),
    ("Unk8", uint16_t),
    ("Type", uint8_t),
    ("UnkB", uint8_t),
  ]

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
  print(magic)
  if magic == bytes(_MAGIC_SNR2, 'utf-8'):
    print("OKAY")
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
  sndata_ext_addr = snr_header.ImagePathAddress
  if sndata_ext_addr == 0 or sndata_ext_addr > snr_header.Table1Offset:
    sndata_ext_addr = snr_header.Table1Offset
  if sndata_ext_addr == 0 or sndata_ext_addr > snr_header.Table2Offset:
    sndata_ext_addr = snr_header.Table2Offset
  
  li.seek(snr_header.Table2Offset)
  
  table2 = []
  for i in range(0, snr_header.Table2Count):
    entry = read_struct(li, SNR2Table2Entry)
    table2.append(entry)
    if sndata_ext_addr == 0 or sndata_ext_addr > entry.NameOffset:
      sndata_ext_addr = entry.NameOffset
    
  li.seek(0)
  li.file2base(0, 0, li.size(), 1)
  idaapi.add_segm(0, 0, 0x100, ".sndata", "DATA")
  idaapi.add_segm(0, 0x100, sndata_ext_addr, ".text", "CODE")
  idaapi.add_segm(0, sndata_ext_addr, li.size(), ".sndata2", "DATA")
   # some reason IDA tends to turn first few bytes of sndata_ext_addr to code, why?
    
  print("found " + str(len(table2)))
  # names = []
  for ent in table2:
    li.seek(ent.NameOffset)
    name = li.getz(256)
   #  names.append(name)
    
    if ent.CodeOffset == 0:
      continue
      
    idc.set_name(ent.CodeOffset, name)
    
    if "$" not in name and "__CTOR_LIST__" not in name and "__DTOR_LIST__" not in name:
      print(hex(ent.CodeOffset) + " = " + name + " (" + hex(ent.Unk8) + " - " + hex(ent.Type) + " - " + hex(ent.UnkB) + ")")
      idc.add_func(ent.CodeOffset)
    
  # Done :)
  print("[+] REL loaded, voila!")
  return 1
  