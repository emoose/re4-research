// RE4LFS: tool for (un)packing RE4 LFS files
// Requires xcompress64.dll DLL

#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <io.h>

typedef VOID* XMEMCOMPRESSION_CONTEXT;
typedef VOID* XMEMDECOMPRESSION_CONTEXT;

using XMemCreateCompressionContext_fn = DWORD(
  int CodecType, const void* pCodecParams, DWORD Flags, XMEMCOMPRESSION_CONTEXT* pContext);
using XMemDestroyCompressionContext_fn = void(
  XMEMCOMPRESSION_CONTEXT Context);
using XMemCompress_fn = DWORD(
  XMEMCOMPRESSION_CONTEXT Context, void* pDestination, SIZE_T* pDestSize, const void* pSource, SIZE_T SrcSize);

using XMemCreateDecompressionContext_fn = DWORD(
  int CodecType, const void* pCodecParams, DWORD Flags, XMEMDECOMPRESSION_CONTEXT* pContext);
using XMemDestroyDecompressionContext_fn = void(
  XMEMDECOMPRESSION_CONTEXT Context);
using XMemDecompress_fn = DWORD(
  XMEMDECOMPRESSION_CONTEXT Context, void* pDestination, SIZE_T* pDestSize, const void* pSource, SIZE_T SrcSize);

HMODULE XCompressHandle = NULL;

XMemCreateCompressionContext_fn* XMemCreateCompressionContext = nullptr;
XMemDestroyCompressionContext_fn* XMemDestroyCompressionContext = nullptr;
XMemCompress_fn* XMemCompress = nullptr;

XMemCreateDecompressionContext_fn* XMemCreateDecompressionContext = nullptr;
XMemDestroyDecompressionContext_fn* XMemDestroyDecompressionContext = nullptr;
XMemDecompress_fn* XMemDecompress = nullptr;

struct LFSHeader
{
    uint32_t Magic1;
    uint32_t Magic2;
    uint32_t SizeDecompressed;
    uint32_t SizeCompressed;
    uint32_t NumChunks;

    void endian_swap()
    {
      Magic1 = _byteswap_ulong(Magic1);
      Magic2 = _byteswap_ulong(Magic2);
      SizeDecompressed = _byteswap_ulong(SizeDecompressed);
      SizeCompressed = _byteswap_ulong(SizeCompressed);
      NumChunks = _byteswap_ulong(NumChunks);
    }
};

struct LFSChunk
{
    uint16_t SizeCompressed;
    uint16_t SizeDecompressed;
    uint32_t Offset;

    void endian_swap()
    {
      SizeCompressed = _byteswap_ushort(SizeCompressed);
      SizeDecompressed = _byteswap_ushort(SizeDecompressed);
      Offset = _byteswap_ulong(Offset);
    }
};

const int LFS_CHUNK_SIZE = 0x10000; // size of each decompressed chunk

struct OSModuleInfo
{
    uint32_t id;
    uint32_t next;
    uint32_t prev;
    uint32_t numSections;
    uint32_t sectionInfoOffset;
    uint32_t nameOffset;
    uint32_t nameSize;
    uint32_t version;

    void endian_swap()
    {
        id = _byteswap_ulong(id);
        next = _byteswap_ulong(next);
        prev = _byteswap_ulong(prev);
        numSections = _byteswap_ulong(numSections);
        sectionInfoOffset = _byteswap_ulong(sectionInfoOffset);
        nameOffset = _byteswap_ulong(nameOffset);
        nameSize = _byteswap_ulong(nameSize);
        version = _byteswap_ulong(version);
    }
};

struct OSModuleHeaderV1
{
    uint32_t bssSize;
    uint32_t relOffset;
    uint32_t impOffset;
    uint32_t impSize;
    uint8_t prologSection;
    uint8_t epilogSection;
    uint8_t unresolvedSection;
    uint8_t bssSection;
    uint32_t prolog;
    uint32_t epilog;
    uint32_t unresolved;

    void endian_swap()
    {
        bssSize = _byteswap_ulong(bssSize);
        relOffset = _byteswap_ulong(relOffset);
        impOffset = _byteswap_ulong(impOffset);
        impSize = _byteswap_ulong(impSize);
        prolog = _byteswap_ulong(prolog);
        epilog = _byteswap_ulong(epilog);
        unresolved = _byteswap_ulong(unresolved);
    }
};

struct OSModuleHeaderV2
{
    OSModuleHeaderV1 header_v1;
    uint32_t align;
    uint32_t bssAlign;

    void endian_swap()
    {
        header_v1.endian_swap();
        align = _byteswap_ulong(align);
        bssAlign = _byteswap_ulong(bssAlign);
    }
};

struct OSModuleHeaderV3
{
    OSModuleHeaderV2 header_v2;
    uint32_t fixSize;

    void endian_swap()
    {
        header_v2.endian_swap();
        fixSize = _byteswap_ulong(fixSize);
    }
};

void usage()
{
    printf("Usage: RE4LFS.exe [-f] [-x] <path/to/input/file> [path/to/output/file]\n");
    printf("\nOutput file path is optional, if not specified file will be output next to the input file\n");
    printf("(either with .lfs extension added or removed)\n");
    printf("\nIf input path ends in .lfs the file will be decompressed, else will be compressed as .lfs\n");
    printf("\nIf output path exists you'll be prompted whether to overwrite or not\n");
    printf("\n-f parameter will force overwriting without prompts\n");
    printf("-x parameter will create a big-endian LFS for X360\n");
    printf("-r parameter will endian-swap the DolphinOS REL header\n");
}

int LFSCompress(FILE* in_file, FILE* out_file);
int LFSDecompress(FILE* in_file, FILE* out_file);

inline bool ends_with(std::string const& value, std::string const& ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

bool endian_swap = false;
bool endian_swap_rel = false;

int main(int argc, const char* argv[])
{
    printf("RE4 LFS compression utility 1.3 - by emoose\n\n");

    if (argc < 2)
    {
        usage();
        return 1;
    }

    bool force_overwrite = false;
    const char* input_file_arg = nullptr;
    const char* output_file_arg = nullptr;
    bool decompress = false;

    for (int i = 1; i < argc; i++)
    {
        if (!_stricmp(argv[i], "-f") || !_stricmp(argv[i], "/f"))
            force_overwrite = true;
        else if (!_stricmp(argv[i], "-x") || !_stricmp(argv[i], "/x"))
            endian_swap = true;
        else if (!_stricmp(argv[i], "-r") || !_stricmp(argv[i], "/r"))
            endian_swap_rel = true;
        else if (input_file_arg == nullptr)
            input_file_arg = argv[i];
        else
            output_file_arg = argv[i];
    }

    if (!input_file_arg)
    {
        printf("Error: no input file path specified!\n\n");
        usage();
        return 1;
    }

    std::string input_file = input_file_arg;
    std::string output_file = input_file + ".lfs";
    if (output_file_arg)
        output_file = output_file_arg;

    if (ends_with(input_file, ".lfs"))
    {
        decompress = true;
        if(!output_file_arg)
            output_file = input_file.substr(0, input_file.length() - 4);
    }

    printf("Input file path: %s\n", input_file.c_str());

    FILE* in_file;
    if (fopen_s(&in_file, input_file.c_str(), "rb") != 0)
    {
        printf("Error: failed to open input file for reading!\n");
        return 3;
    }

    printf("Output file path: %s\n", output_file.c_str());

    if (GetFileAttributesA(output_file.c_str()) != 0xFFFFFFFF && !force_overwrite)
    {
        printf("\nOutput file already exists! Overwrite? (Y/N)\n");
        int input = _getch();
        if (input != 'Y' && input != 'y')
            return 1;
    }

    FILE* out_file;
    if (fopen_s(&out_file, output_file.c_str(), "wb+") != 0)
    {
        printf("Error: failed to open output file for writing!\n");
        return 4;
    }

    XCompressHandle = LoadLibrary(L"xcompress64.dll");
    if (!XCompressHandle)
    {
        printf("Error: failed to load xcompress64.dll library!\n");
        return 2;
    }

    XMemCreateCompressionContext = (XMemCreateCompressionContext_fn*)GetProcAddress(XCompressHandle, "XMemCreateCompressionContext");
    XMemDestroyCompressionContext = (XMemDestroyCompressionContext_fn*)GetProcAddress(XCompressHandle, "XMemDestroyCompressionContext");
    XMemCompress = (XMemCompress_fn*)GetProcAddress(XCompressHandle, "XMemCompress");

    XMemCreateDecompressionContext = (XMemCreateDecompressionContext_fn*)GetProcAddress(XCompressHandle, "XMemCreateDecompressionContext");
    XMemDestroyDecompressionContext = (XMemDestroyDecompressionContext_fn*)GetProcAddress(XCompressHandle, "XMemDestroyDecompressionContext");
    XMemDecompress = (XMemDecompress_fn*)GetProcAddress(XCompressHandle, "XMemDecompress");

    if (decompress)
        return LFSDecompress(in_file, out_file);
    else
        return LFSCompress(in_file, out_file);
}

int LFSDecompress(FILE* in_file, FILE* out_file)
{
    printf("\nDecompressing input file...\n");

    XMEMDECOMPRESSION_CONTEXT ctx;
    auto ret = XMemCreateDecompressionContext(1, 0, 0, &ctx);
    if (ret < 0)
    {
        printf("Error: failed to create decompression context?\n");
        return 1;
    }

    _fseeki64(in_file, 0, SEEK_END);
    uint64_t file_size = ftell(in_file);
    _fseeki64(in_file, 0, SEEK_SET);

    printf("Input file length: 0x%llX\n", file_size);

    auto data_in = std::make_unique<uint8_t[]>(file_size);
    fread(data_in.get(), 1, file_size, in_file);
    fclose(in_file);

    LFSHeader* header = (LFSHeader*)data_in.get();
    LFSChunk* chunks = (LFSChunk*)&header[1];

    if (header->Magic1 == 0x52444C58)
    {
        printf("Big-endian LFS detected, will byte-swap LFS headers\n");
        endian_swap = true;
        header->endian_swap();
    }

    if (header->Magic1 != 0x584C4452) // game only checks Magic1, so guess we'll do the same
    {
        printf("Error: LFS uses invalid Magic1 0x%X (expected 0x584C4452), aborting.\n", header->Magic1);
        return 1;
    }

    printf("LFS chunk count: %u\n", header->NumChunks);
    printf("Writing out decompressed file...\n");

    auto dec_buf = std::make_unique<uint8_t[]>(LFS_CHUNK_SIZE);
    for (uint32_t i = 0; i < header->NumChunks; i++)
    {
        LFSChunk* chunk = &chunks[i];
        if (endian_swap)
            chunk->endian_swap();

        uint8_t* comp_data = (uint8_t*)chunks + (chunk->Offset & ~1); // & with ~1 to remove any 1/compressed bit
        uint32_t comp_data_size = LFS_CHUNK_SIZE;
        if (chunk->SizeCompressed > 0)
            comp_data_size = chunk->SizeCompressed;

        SIZE_T expected_size = LFS_CHUNK_SIZE;
        if (chunk->SizeDecompressed > 0)
            expected_size = chunk->SizeDecompressed;

        SIZE_T output_size = LFS_CHUNK_SIZE;

        if ((chunk->Offset & 1) != 0)
        {
            // compressed bit is set, run XMemDecompress
            ret = XMemDecompress(ctx, dec_buf.get(), &output_size, comp_data, comp_data_size);
            if (ret < 0)
            {
                printf("Error: chunk %d failed to decompress data, output file is incomplete!\n", i);
                return 1;
            }
            if (output_size != expected_size)
            {
                printf("Error: chunk %d failed to fully decompress data (got 0x%llX bytes, expected 0x%llX), output file is incomplete!\n", i, output_size, expected_size);
                return 1;
            }
            fwrite(dec_buf.get(), 1, output_size, out_file);
        }
        else
        {
            // compressed bit not set, copy bytes to new file
            fwrite(comp_data, 1, comp_data_size, out_file);
        }
    }

    if (endian_swap_rel)
    {
        printf("Endian-swapping DolphinOS REL header...\n");
        fseek(out_file, 0, SEEK_SET);
        OSModuleInfo moduleInfo;
        fread(&moduleInfo, sizeof(moduleInfo), 1, out_file);
        printf("  OSModuleInfo.id = %d\n", moduleInfo.id);
        printf("  OSModuleInfo.version = %d\n", moduleInfo.version);

        // store version field before byteswap, since it's in little-endian
        int version = moduleInfo.version;
        moduleInfo.endian_swap();
        if (version > 0 && version < 4)
        {
            fseek(out_file, 0, SEEK_SET);
            fwrite(&moduleInfo, sizeof(moduleInfo), 1, out_file);
            int size = sizeof(moduleInfo);
            if (version == 1)
            {
                OSModuleHeaderV1 moduleHeader;
                fread(&moduleHeader, sizeof(moduleHeader), 1, out_file);
                moduleHeader.endian_swap();
                fseek(out_file, sizeof(OSModuleInfo), SEEK_SET);
                fwrite(&moduleHeader, sizeof(moduleHeader), 1, out_file);
            }
            else if (version == 2)
            {
                OSModuleHeaderV2 moduleHeader;
                fread(&moduleHeader, sizeof(moduleHeader), 1, out_file);
                moduleHeader.endian_swap();
                fseek(out_file, sizeof(OSModuleInfo), SEEK_SET);
                fwrite(&moduleHeader, sizeof(moduleHeader), 1, out_file);
            }
            else if (version == 3)
            {
                OSModuleHeaderV3 moduleHeader;
                fread(&moduleHeader, sizeof(moduleHeader), 1, out_file);
                moduleHeader.endian_swap();
                fseek(out_file, sizeof(OSModuleInfo), SEEK_SET);
                fwrite(&moduleHeader, sizeof(moduleHeader), 1, out_file);
            }

            printf("Endian-swap complete!\n");
        }
        else
        {
            printf("Error: unknown OSModuleInfo.version value %d!\n", version);
        }
    }

    fclose(out_file);

    XMemDestroyDecompressionContext(ctx);

    printf("\nLFS decompression complete, have a nice day!\n");
    return 0;
}

int LFSCompress(FILE* in_file, FILE* out_file)
{
    printf("\nCompressing input file...\n");

    XMEMCOMPRESSION_CONTEXT ctx;
    auto ret = XMemCreateCompressionContext(1, 0, 0, &ctx);
    if (ret < 0)
    {
        printf("Error: failed to create compression context?\n");
        return 1;
    }

    _fseeki64(in_file, 0, SEEK_END);
    uint64_t file_size = ftell(in_file);
    _fseeki64(in_file, 0, SEEK_SET);

    printf("Input file length: 0x%llX\n", file_size);

    uint32_t num_chunks = uint32_t((file_size + (LFS_CHUNK_SIZE - 1)) / LFS_CHUNK_SIZE);
    printf("LFS chunk count: %u\n", num_chunks);

    int header_size = sizeof(LFSHeader) + (sizeof(LFSChunk) * num_chunks);

    LFSHeader header{};
    auto chunks = std::make_unique<LFSChunk[]>(num_chunks);

    header.Magic1 = 0x584C4452;
    header.Magic2 = 0xFEEEBAAA;
    header.NumChunks = num_chunks;
    header.SizeDecompressed = (uint32_t)file_size;
    header.SizeCompressed = 0;

    if (endian_swap)
        printf("/x used, will byte-swap LFS headers before writing\n");

    printf("Writing out compressed LFS...\n");

    auto dec_buf = std::make_unique<uint8_t[]>(LFS_CHUNK_SIZE);
    auto comp_buf = std::make_unique<uint8_t[]>(LFS_CHUNK_SIZE);

    // TODO: the weird padding stuff below is because offset is aligned minus sizeof(LFSHeader), should redo stuff to remove/add that instead
    uint64_t data_offset = header_size;
    uint64_t data_remaining = file_size;
    for (uint32_t i = 0; i < num_chunks; i++)
    {
        uint64_t chunk_size = LFS_CHUNK_SIZE;
        if (chunk_size > data_remaining)
            chunk_size = data_remaining;

        LFSChunk* chunk = &chunks[i];

        fread(dec_buf.get(), 1, chunk_size, in_file);

        SIZE_T output_size = LFS_CHUNK_SIZE;
        ret = XMemCompress(ctx, comp_buf.get(), &output_size, dec_buf.get(), chunk_size);
        if (ret < 0)
        {
            printf("Error: failed to compress data, output file is incomplete!\n");
            return 1;
        }

        uint64_t data_offset_aligned = ((((data_offset - 4) + 0xF) / 0x10) * 0x10) + 4; // weird ass alignment based on offset being -4 of actual offset?
        _fseeki64(out_file, data_offset_aligned, SEEK_SET);
        fwrite(comp_buf.get(), 1, output_size, out_file);

        chunk->SizeDecompressed = uint16_t(chunk_size == LFS_CHUNK_SIZE ? 0 : chunk_size);
        chunk->SizeCompressed = uint16_t(output_size == LFS_CHUNK_SIZE ? 0 : output_size);

        chunk->Offset = uint32_t(data_offset_aligned - 0x14);
        chunk->Offset |= 1; // set compressed bit - game won't bother with XMemDecompress if this isn't set!

        header.SizeCompressed += (uint32_t)output_size;

        data_offset = data_offset_aligned + output_size;
        data_remaining -= chunk_size;

        if (endian_swap)
        {
          chunk->endian_swap();

          // TODO: x360 includes pad bytes in the SizeCompressed field, need to check if PC also needs this
          uint64_t next_data_offset_aligned = ((((data_offset - 4) + 0xF) / 0x10) * 0x10) + 4; // weird ass alignment based on offset being -4 of actual offset?
          header.SizeCompressed += uint32_t(next_data_offset_aligned - data_offset);;
        }
    }

    fclose(in_file);

    XMemDestroyCompressionContext(ctx);

    if (endian_swap)
    {
      header.endian_swap();

      // make sure to include end-of-file padding
      // TODO: this lets us match X360, need to check if it might improve PC too

      uint64_t data_offset_aligned = ((((data_offset - 4) + 0xF) / 0x10) * 0x10) + 4; // weird ass alignment based on offset being -4 of actual offset?
      _chsize_s(_fileno(out_file), data_offset_aligned);
    }

    // Write headers and finish up
    _fseeki64(out_file, 0, SEEK_SET);
    fwrite(&header, sizeof(LFSHeader), 1, out_file);
    fwrite(chunks.get(), sizeof(LFSChunk), num_chunks, out_file);
    fclose(out_file);

    printf("\nLFS compression complete, have a nice day!\n");
    return 0;
}
