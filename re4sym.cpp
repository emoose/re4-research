// Tool for parsing the SYM files found inside RE4 GC debug build into IDA/Ghidra compatible naming-scripts

#include <iostream>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <filesystem>

struct SymHeader
{
  uint32_t num_funcs;
  uint32_t funcinfo_addr;
  uint32_t strtab_addr;
  uint32_t funcname_addr;
};

struct SymFuncInfo // funcinfo
{
  uint32_t virtual_addr;
  uint32_t unk4;
  uint32_t unk8;
  uint32_t name_addr;
};

struct SymFuncInfo_Parsed // funcinfo
{
  uint32_t virtual_addr;
  std::string name;
  uint32_t unk4;
  uint32_t unk8;
};

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
  size_t start_pos = 0;
  while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
    str.replace(start_pos, from.length(), to);
    start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
  }
  return str;
}

int main(int argc, char* argv[])
{
    if (argc <= 1)
    {
        printf("Usage: re4sym <path/to/sym/file>\n");
        printf("Will create filepath.ida.py & filepath.ghidra.txt files containing symbol names/addresses\n");
        return 1;
    }

    FILE* file;
    fopen_s(&file, argv[1], "rb");
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* mem = (uint8_t*)malloc(size);
    if (!mem)
      return 0;
    fread(mem, 1, size, file);
    fclose(file);

    SymHeader* header = (SymHeader*)mem;
    header->num_funcs = _byteswap_ulong(header->num_funcs);
    header->funcinfo_addr = _byteswap_ulong(header->funcinfo_addr);
    header->strtab_addr = _byteswap_ulong(header->strtab_addr);
    header->funcname_addr = _byteswap_ulong(header->funcname_addr);

    std::vector<std::string> funcnames;

    uint32_t* funcname_addr = (uint32_t*)(mem + 0x10);
    uint32_t* funcname_end = (uint32_t*)(mem + header->funcinfo_addr);
    while (funcname_end > funcname_addr)
    {
      uint32_t cur_addr = _byteswap_ulong(*funcname_addr);
      char* cur_str = (char*)(mem + header->strtab_addr + cur_addr);
      funcnames.push_back(cur_str);
      funcname_addr++;
    }

    std::vector<SymFuncInfo_Parsed> funcinfos;
    SymFuncInfo* cfuncinfos = (SymFuncInfo*)(mem + header->funcinfo_addr);
    for (uint32_t i = 0; i < header->num_funcs; i++)
    {
      auto info = &cfuncinfos[i];

      SymFuncInfo_Parsed parsed;
      parsed.virtual_addr = _byteswap_ulong(info->virtual_addr);

      char* name = (char*)(mem + header->funcname_addr + _byteswap_ulong(info->name_addr));
      parsed.name = name;

      parsed.unk4 = _byteswap_ulong(info->unk4);
      parsed.unk8 = _byteswap_ulong(info->unk8);

      funcinfos.push_back(parsed);
    }


    std::filesystem::path input = argv[1];
    std::filesystem::path basedir = input.parent_path();
    auto ida_path = basedir / "ida" / input.filename().replace_extension(".py");
    auto ghidra_path = basedir / "ghidra" / input.filename().replace_extension(".txt");

    bool isDolFile = input.filename().extension() == ".dol";

    std::ofstream ida(ida_path, std::ofstream::out | std::ofstream::trunc);
    std::ofstream ghidra(ghidra_path, std::ofstream::out | std::ofstream::trunc);

    if (ida.is_open())
    {
        // IDA boilerplate to handle dupe names & create code for functions
        ida << "import ida_segment\n";
        ida << "\n";
        ida << "def namer(ea, name):\n";
        ida << "    origName = name\n";
        ida << "    existEA = get_name_ea(idaapi.BADADDR, name)\n";
        ida << "    i = 0\n";
        ida << "    while existEA != idaapi.BADADDR:\n";
        ida << "        name = origName + \"_\" + str(i)\n";
        ida << "        i = i + 1\n";
        ida << "        existEA = get_name_ea(0, name)\n";
        ida << "\n";
        ida << "    set_name(ea, name)\n";
        ida << "    seg = ida_segment.getseg(ea)\n";
        ida << "    seg_name = ida_segment.get_segm_name(seg)\n";
        ida << "    if seg_name.startswith(\".text\"):\n";
        ida << "        idc.add_func(ea)\n";
        ida << "\n";
    }

    for (auto& info : funcinfos)
    {
      auto s = ReplaceAll(info.name, " virtual table", "_vtable");

      std::replace(s.begin(), s.end(), '<', '_');
      std::replace(s.begin(), s.end(), '>', '_');
      std::replace(s.begin(), s.end(), ' ', '_');

      if (s.length() <= 1)
        continue;

      if (s[0] == '@')
        continue;

      if (s.length() >= 4 && s.substr(0, 4) == "sub_")
        s = "_" + s;

      auto ida_addr = info.virtual_addr;
      auto ghidra_addr = info.virtual_addr;

      if (!isDolFile)
      {
          ida_addr += 0x80500000;
          ghidra_addr += 0x80000000;
      }

      if (ida.is_open())
        ida << "namer(0x" << std::hex << ida_addr << ", \"" << s << "\")\n";
      if (ghidra.is_open())
        ghidra << s << " 0x" << std::hex << ghidra_addr << "\n";
      //printf("set_name(0x%X,\"%s\")\n", info.virtual_addr, s.c_str(), info.unk4, info.unk8);
    }

    if (ida.is_open())
        std::cout << "Wrote IDAPython script to " << ida_path << std::endl;
    else
        std::cout << "Failed to write IDAPython script to " << ida_path << std::endl;


    if (ghidra.is_open())
        std::cout << "Wrote Ghidra ImportSymbolsScript file to " << ghidra_path << std::endl;
    else
        std::cout << "Failed to write Ghidra ImportSymbolsScript file to " << ghidra_path << std::endl;
}