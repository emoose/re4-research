// Resampling tool for XACT XWB soundbanks, by emoose
//   tested with RE4 UHD Steam version, mainly to resample the audio to better work with x3daudio1_7_hrtf, but should probably work on other games too
// 
// This mainly just handles extracting & repacking of PCM data in/out of the XWB, for the actual resampling we defer that to FFmpeg instead
// Due to this the tool only supports resampling XWB entries that use uncompressed PCM (which fortunately RE4 made sole use of)
// (tho it's probably possible to extract compressed audio from the XWB using another tool, and then re-inject it as uncompressed PCM, via some tweaks to this code)

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define WAVE_FORMAT_PCM 1

#include <vector>
#include <string>
#include <io.h>
#include <filesystem>
#include <fstream>

// winutil.cpp
void ExecuteCommandLine(std::string cmdLine, uint32_t& exitCode);
std::string GetTempDir(std::string_view root_dir);

// defs from xact3wb.h
typedef enum WAVEBANKSEGIDX
{
    WAVEBANK_SEGIDX_BANKDATA = 0,       // Bank data
    WAVEBANK_SEGIDX_ENTRYMETADATA,      // Entry meta-data
    WAVEBANK_SEGIDX_SEEKTABLES,         // Storage for seek tables for the encoded waves.
    WAVEBANK_SEGIDX_ENTRYNAMES,         // Entry friendly names
    WAVEBANK_SEGIDX_ENTRYWAVEDATA,      // Entry wave data
    WAVEBANK_SEGIDX_COUNT
} WAVEBANKSEGIDX;

struct WAVEBANKREGION {
    uint32_t dwOffset;
    uint32_t dwLength;
};
static_assert(sizeof(WAVEBANKREGION) == 8, "WAVEBANKREGION");

struct WAVEBANKHEADER {
    uint32_t dwSignature;
    uint32_t dwVersion;
    uint32_t dwHeaderVersion;
    WAVEBANKREGION Segments[WAVEBANK_SEGIDX_COUNT];
};
static_assert(sizeof(WAVEBANKHEADER) == 0x34, "WAVEBANKHEADER");

#define WAVEBANK_BANKNAME_LENGTH 64

#define WAVEBANKMINIFORMAT_TAG_PCM      0x0     // PCM data
#define WAVEBANKMINIFORMAT_TAG_XMA      0x1     // XMA data
#define WAVEBANKMINIFORMAT_TAG_ADPCM    0x2     // ADPCM data
#define WAVEBANKMINIFORMAT_TAG_WMA      0x3     // WMA data

#define WAVEBANKMINIFORMAT_BITDEPTH_8   0x0     // 8-bit data (PCM only)
#define WAVEBANKMINIFORMAT_BITDEPTH_16  0x1     // 16-bit data (PCM only)

union WAVEBANKMINIWAVEFORMAT
{
    struct
    {
        uint32_t wFormatTag : 2;        // Format tag
        uint32_t nChannels : 3;        // Channel count (1 - 6)
        uint32_t nSamplesPerSec : 18;       // Sampling rate
        uint32_t wBlockAlign : 8;        // Block alignment.  For WMA, lower 6 bits block alignment index, upper 2 bits bytes-per-second index.
        uint32_t wBitsPerSample : 1;        // Bits per sample (8 vs. 16, PCM only); WMAudio2/WMAudio3 (for WMA)
    };

    uint32_t dwValue;
};
static_assert(sizeof(WAVEBANKMINIWAVEFORMAT) == 4, "WAVEBANKMINIWAVEFORMAT");

struct WAVEBANKDATA {
    uint32_t dwFlags;
    uint32_t dwEntryCount;
    char szBankName[WAVEBANK_BANKNAME_LENGTH];
    uint32_t dwEntryMetaDataElementSize;
    uint32_t dwEntryNameElementSize;
    uint32_t dwAlignment;
    WAVEBANKMINIWAVEFORMAT CompactFormat;
    uint64_t BuildTime;
};
static_assert(sizeof(WAVEBANKDATA) == 0x60, "WAVEBANKDATA");

struct WAVEBANKSAMPLEREGION {
    uint32_t dwStartSample;
    uint32_t dwTotalSamples;
};
static_assert(sizeof(WAVEBANKSAMPLEREGION) == 8, "WAVEBANKSAMPLEREGION");

struct WAVEBANKENTRY {
    union
    {
        struct
        {
            uint32_t dwFlags : 4;
            uint32_t Duration : 28;
        };
        uint32_t dwFlagsAndDuration;
    };
    WAVEBANKMINIWAVEFORMAT Format;
    WAVEBANKREGION PlayRegion;
    WAVEBANKSAMPLEREGION LoopRegion;
};
static_assert(sizeof(WAVEBANKENTRY) == 0x18, "WAVEBANKENTRY");

// wav format from the net, surprised these aren't in windows headers anywhere...

struct WAVRIFFHEADER {
    uint32_t groupID;
    uint32_t size;
    uint32_t riffType;
};
static_assert(sizeof(WAVRIFFHEADER) == 0xC, "WAVRIFFHEADER");

struct RIFFCHUNK {
    uint32_t ID;
    uint32_t size;
};
static_assert(sizeof(RIFFCHUNK) == 0x8, "RIFFCHUNK");

struct FORMATCHUNK
{
    uint16_t wFormatTag;
    uint16_t wChannels;
    uint32_t dwSamplesPerSec;
    uint32_t dwAvgBytesPerSec;
    uint16_t wBlockAlign;
    uint16_t wBitsPerSample;
};
static_assert(sizeof(FORMATCHUNK) == 0x10, "FORMATCHUNK");

struct XACTEntry
{
    WAVEBANKENTRY info;
    uint8_t* data;
    long size;

    bool wav_export(std::string filePath)
    {
        WAVRIFFHEADER riffHeader = { .groupID = 0x46464952, .size = 0, .riffType = 0x45564157 };
        RIFFCHUNK wavFormatChunk = { .ID = 0x20746D66, .size = sizeof(FORMATCHUNK) };

        FORMATCHUNK wavFormat;
        if (info.Format.wFormatTag != WAVEBANKMINIFORMAT_TAG_PCM)
            return false; // don't support exporting other formats

        wavFormat.wFormatTag = WAVE_FORMAT_PCM;
        wavFormat.wChannels = info.Format.nChannels;
        wavFormat.dwSamplesPerSec = info.Format.nSamplesPerSec;
        wavFormat.dwAvgBytesPerSec = info.Format.nSamplesPerSec * 2;
        wavFormat.wBlockAlign = info.Format.wBlockAlign;
        wavFormat.wBitsPerSample = info.Format.wBitsPerSample == WAVEBANKMINIFORMAT_BITDEPTH_16 ? 16 : 8;

        RIFFCHUNK wavDataChunk;
        wavDataChunk.ID = 0x61746164;
        wavDataChunk.size = size;

        riffHeader.size = size + sizeof(WAVRIFFHEADER) + sizeof(RIFFCHUNK) + sizeof(FORMATCHUNK) + sizeof(RIFFCHUNK);

        std::ofstream file(filePath, std::ios::binary);
        if (!file || !file.is_open())
            return false;

        file.write((const char*)&riffHeader, sizeof(WAVRIFFHEADER));
        file.write((const char*)&wavFormatChunk, sizeof(RIFFCHUNK));
        file.write((const char*)&wavFormat, sizeof(FORMATCHUNK));
        file.write((const char*)&wavDataChunk, sizeof(RIFFCHUNK));
        file.write((const char*)data, size);

        return true;
    }

    bool wav_import(std::string filePath, bool resampleLoopPoints)
    {
        std::ifstream file(filePath, std::ios::binary);
        if (!file || !file.is_open())
            return false;

        int origSampleRate = info.Format.nSamplesPerSec;

        file.seekg(0, file.end);
        long filesize = long(file.tellg());
        file.seekg(0, file.beg);

        WAVRIFFHEADER riffHeader;
        file.read((char*)&riffHeader, sizeof(riffHeader));
        if (!file)
            return false;

        FORMATCHUNK wavFormat = { 0 };
        while (filesize > file.tellg())
        {
            RIFFCHUNK chunk;
            file.read((char*)&chunk, sizeof(RIFFCHUNK));
            if (!file)
                return false;

            if (chunk.ID == 0x20746D66) // fmt
            {
                file.read((char*)&wavFormat, sizeof(FORMATCHUNK));
                if (!file)
                    return false;

                // got the format chunk, update our entry info with it
                if (wavFormat.wFormatTag != WAVE_FORMAT_PCM)
                    return false; // don't support other formats

                if (resampleLoopPoints && (info.LoopRegion.dwStartSample || info.LoopRegion.dwTotalSamples))
                {
                    // update loop points by dividing by original sample rate, then multiply by the new one
                    // not sure how accurate this will be though
                    double loopSampleStart = double(info.LoopRegion.dwStartSample) / double(info.Format.nSamplesPerSec);
                    double loopSampleCount = double(info.LoopRegion.dwTotalSamples) / double(info.Format.nSamplesPerSec);
                    info.LoopRegion.dwStartSample = uint32_t(loopSampleStart * double(wavFormat.dwSamplesPerSec));
                    info.LoopRegion.dwTotalSamples = uint32_t(loopSampleCount * double(wavFormat.dwSamplesPerSec));
                }

                info.Format.wFormatTag = WAVEBANKMINIFORMAT_TAG_PCM;
                info.Format.nChannels = wavFormat.wChannels;
                info.Format.nSamplesPerSec = wavFormat.dwSamplesPerSec;
                info.Format.wBlockAlign = wavFormat.wBlockAlign;
                info.Format.wBitsPerSample = wavFormat.wBitsPerSample == 16 ? WAVEBANKMINIFORMAT_BITDEPTH_16 : WAVEBANKMINIFORMAT_BITDEPTH_8;

                continue;
            }
            else if (chunk.ID == 0x61746164)
            {
                // got our data chunk!
                if (!wavFormat.dwSamplesPerSec)
                    return false; // didn't have format chunk before data, can't work in these conditions

                data = (uint8_t*)realloc(data, chunk.size);
                if (!data)
                    return false;

                size = chunk.size;

                file.read((char*)data, chunk.size);
                if (!file)
                    return false;

                int bytesPerSample = wavFormat.wBitsPerSample / 8;
                info.Duration = (chunk.size / bytesPerSample) / info.Format.nChannels; // 16-bits/2-bytes per sample, divided by number of channels, = number of samples

                return true;
            }

            // unknown chunk, skip over data
            file.seekg(chunk.size, file.cur);
        }

        return false;
    }
};

class XACTWaveBank
{
public:
    FILE* file = nullptr;

    WAVEBANKHEADER header = {};
    WAVEBANKDATA bankData = {};
    std::vector<XACTEntry> entries;

    ~XACTWaveBank()
    {
        if (file)
        {
            fclose(file);
            file = nullptr;
        }

        for(XACTEntry& entry : entries)
            if (entry.data)
            {
                free(entry.data);
                entry.data = nullptr;
                entry.size = 0;
            }
    }

    bool load(std::string filePath)
    {
        fopen_s(&file, filePath.c_str(), "rb+");
        if (!file)
            return false;

        fseek(file, 0, SEEK_SET);
        fread(&header, sizeof(WAVEBANKHEADER), 1, file);

        fseek(file, header.Segments[WAVEBANK_SEGIDX_BANKDATA].dwOffset, SEEK_SET);
        fread(&bankData, sizeof(WAVEBANKDATA), 1, file);

        fseek(file, header.Segments[WAVEBANK_SEGIDX_ENTRYMETADATA].dwOffset, SEEK_SET);
        for (uint32_t i = 0; i < bankData.dwEntryCount; i++)
        {
            XACTEntry entry;
            fread(&entry.info, sizeof(WAVEBANKENTRY), 1, file);
            entries.push_back(entry);
        }

        for (uint32_t i = 0; i < entries.size(); i++)
        {
            XACTEntry& entry = entries[i];

            long pos = header.Segments[WAVEBANK_SEGIDX_ENTRYWAVEDATA].dwOffset
                + entry.info.PlayRegion.dwOffset;

            fseek(file, pos, SEEK_SET);

            auto dataBuf = (uint8_t*)malloc(entry.info.PlayRegion.dwLength);
            fread(dataBuf, 1, entry.info.PlayRegion.dwLength, file);
            entry.data = dataBuf;
            entry.size = entry.info.PlayRegion.dwLength;
        }

        return true;
    }

    bool save()
    {
        // truncate to start of entrymetadata section
        fseek(file, header.Segments[WAVEBANK_SEGIDX_ENTRYMETADATA].dwOffset, SEEK_SET);
        _chsize(_fileno(file), header.Segments[WAVEBANK_SEGIDX_ENTRYMETADATA].dwOffset);

        long pos = header.Segments[WAVEBANK_SEGIDX_ENTRYWAVEDATA].dwOffset;
        for (uint32_t i = 0; i < entries.size(); i++)
        {
            XACTEntry& entry = entries[i];

            // align pos to nearest 2048 bytes
            pos = ((pos + (2048 - 1)) / 2048) * 2048;
            fseek(file, pos, SEEK_SET);

            entry.info.PlayRegion.dwOffset = pos - header.Segments[WAVEBANK_SEGIDX_ENTRYWAVEDATA].dwOffset;
            entry.info.PlayRegion.dwLength = entry.size;

            fwrite(entry.data, 1, entry.size, file);
            pos += entry.size;
        }

        // align file to nearest 2048 bytes
        pos = ((pos + (2048 - 1)) / 2048) * 2048;
        fseek(file, pos, SEEK_SET);
        _chsize(_fileno(file), pos);

        fseek(file, header.Segments[WAVEBANK_SEGIDX_ENTRYMETADATA].dwOffset, SEEK_SET);
        for (uint32_t i = 0; i < entries.size(); i++)
        {
            XACTEntry& entry = entries[i];
            fwrite(&entry.info, sizeof(WAVEBANKENTRY), 1, file);
        }

        // update sizes in header
        header.Segments[WAVEBANK_SEGIDX_ENTRYWAVEDATA].dwLength = pos - header.Segments[WAVEBANK_SEGIDX_ENTRYWAVEDATA].dwOffset;

        fseek(file, 0, SEEK_SET);
        fwrite(&header, sizeof(WAVEBANKHEADER), 1, file);

        return true;
    }
};

// Returns FALSE if the command could not be executed or if the exit code could not be determined.
void ExecuteCommandLine(std::string cmdLine, uint32_t& exitCode)
{
    PROCESS_INFORMATION processInformation = { 0 };
    STARTUPINFOA startupInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.wShowWindow = true;

    // Create the process
    BOOL result = CreateProcessA(NULL, (LPSTR)cmdLine.c_str(),
        NULL, NULL, FALSE,
        NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW,
        NULL, NULL, &startupInfo, &processInformation);

    if (!result)
    {
        auto error_code = GetLastError();
        throw std::system_error(error_code, std::system_category(), "CreateProcessA()");
    }

    // Successfully created the process.  Wait for it to finish.
    WaitForSingleObject(processInformation.hProcess, INFINITE);

    // Get the exit code.
    result = GetExitCodeProcess(processInformation.hProcess, (DWORD*)&exitCode);

    // Close the handles.
    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);

    if (!result)
    {
        // Could not get exit code.
        auto error_code = GetLastError();
        throw std::system_error(error_code, std::system_category(), "GetExitCodeProcess()");
    }
}

std::string GetTempDir(std::string_view root_dir)
{
    while (true)
    {
        SYSTEMTIME st;
        GetSystemTime(&st);

        FILETIME ft;
        if (!SystemTimeToFileTime(&st, &ft))
        {
            auto error_code = GetLastError();
            throw std::system_error(error_code, std::system_category(), "SystemTimeToFileTime()");
        }

        ULARGE_INTEGER ft_uli{ ft.dwLowDateTime, ft.dwHighDateTime };
        auto dir_name = std::to_string(ft_uli.QuadPart);
        auto dir_name_full = std::string(root_dir) + dir_name;
        if (CreateDirectoryA(dir_name_full.c_str(), nullptr))
            return dir_name_full;

        auto error_code = GetLastError();
        if (error_code != ERROR_ALREADY_EXISTS)
            throw std::system_error(error_code, std::system_category(), "CreateDirectoryW()");
    }
}

void banner()
{
    printf("RE4 XWB quick'n'dirty resampler v0.1 - by emoose\n\n");
}

int main(int argc, const char* argv[])
{
    bool checkForBadFilesMode = false;
    int outputSampleRate = 48000;
    const char* inputPath = nullptr;
    bool loopResample = false;
    bool extract = false;

    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "/c") || !strcmp(argv[i], "-c"))
            checkForBadFilesMode = true;
        else if (!strcmp(argv[i], "/v") || !strcmp(argv[i], "-v"))
            banner();
        else if (!strcmp(argv[i], "/l") || !strcmp(argv[i], "-l"))
            loopResample = true;
        else if (!strcmp(argv[i], "/e") || !strcmp(argv[i], "-e"))
            extract = true;
        else if ((!strcmp(argv[i], "/r") || !strcmp(argv[i], "-r")) && i + 1 < argc)
        {
            const char* userSampleRate = argv[i + 1];
            outputSampleRate = std::stol(userSampleRate, 0, 0);
            i++;
        }
        else
            inputPath = argv[i];
    }

    if (argc < 2 || !inputPath)
    {
        banner();

        if (!inputPath)
            printf("No input path specified\n");

        printf("Usage: re4resample.exe [-r rate (default 48000)] [-l] [-c] [-e] <.XWB file path>\n");
        printf("Will resample the provided .XWB file to the given sample rate\n");
        printf("(note that changes are written to the input file!)\n");
        printf("-e will extract audio without resampling\n");
        printf("-l enables using an experimental loop-resampling method, to try fixing XWB entries that make use of LoopRegion\n");
        printf("   ^ not sure how well this works yet!\n");
        printf("\nMake sure ffmpeg.exe is somewhere accessible in your %%PATH%% for the resampling to work.\n");
        return 1;
    }

    XACTWaveBank waveBank;
    if (!waveBank.load(inputPath))
    {
        printf("Failed to load wave bank?\n");
        return 1;
    }

    // check for crap that we probably won't be able to handle atm
    if (checkForBadFilesMode)
    {
        if (waveBank.header.Segments[WAVEBANK_SEGIDX_SEEKTABLES].dwLength != 0)
            printf("!!! WAVEBANK_SEGIDX_SEEKTABLES in use!\n");

        int loopy = 0;
        int badformat = 0;
        for(size_t i = 0; i < waveBank.entries.size(); i++)
        {
            XACTEntry& entry = waveBank.entries[i];

            if (!loopResample && entry.info.LoopRegion.dwTotalSamples)
            {
                loopy++;
                printf("!!! entry %d uses LoopRegion!\n", int(i));
            }

            if (entry.info.Format.wFormatTag != WAVEBANKMINIFORMAT_TAG_PCM)
            {
                badformat++;
                printf("!!! entry %d uses unsupported codec %d!\n", int(i), int(entry.info.Format.wFormatTag));
            }
        }

        if (loopy)
            printf("!!! %d entries use LoopRegions, and will get skipped over for resampling\n  (use -l to try resampling loop points)\n", loopy);

        if (badformat)
            printf("!!! %d entries use unsupported codecs, and will get skipped over for resampling\n", badformat);

        return 0;
    }

    bool madeChanges = false;
    auto outDir = GetTempDir("temp");

    for (uint32_t i = 0; i < waveBank.entries.size(); i++)
    {
        auto& entry = waveBank.entries[i];

        std::string origPath = outDir + "\\temp" + std::to_string(i) + ".wav";
        std::string newPath = outDir + "\\temp_new" + std::to_string(i) + ".wav";

        if (extract)
        {
            if (!madeChanges)
            {
                // print out the filename of the XWB if we're making changes, handy for batch processing
                printf(inputPath);
                madeChanges = true;
            }
            printf("."); // dot for each entry

            entry.wav_export(origPath);
            continue;
        }

        if (entry.info.Format.nSamplesPerSec == outputSampleRate)
            continue;

        if (entry.info.LoopRegion.dwTotalSamples != 0 && !loopResample)
            continue;

        if (!madeChanges)
        {
            // print out the filename of the XWB if we're making changes, handy for batch processing
            printf(inputPath);
            madeChanges = true;
        }
        printf("."); // dot for each entry

        if (!entry.wav_export(origPath))
            printf("\n!!! export failed for entry %d\n", int(i));

        uint32_t exitCode = 0;
        std::string cmd = "ffmpeg.exe -i \"" + origPath + "\" -ar " + std::to_string(outputSampleRate) + " -y \"" + newPath + "\"";
        ExecuteCommandLine(cmd, exitCode);

        if (!entry.wav_import(newPath, loopResample))
            printf("\n!!! import failed for entry %d\n", int(i));
    }

    printf("\n");

    if (!extract)
    {
        if (madeChanges)
            waveBank.save();
        std::error_code error;
        std::filesystem::remove_all(outDir, error);
    }
}
