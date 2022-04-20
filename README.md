# re4-research
Various modding tools & research for Resident Evil 4.

* **[IDA 7.7 database](https://github.com/emoose/re4-research/issues/3)** - IDA database for RE4 UHD (Steam) version 1.1.0, with over 70% of in-use functions named, and a few structures added.

* **re4lfs.cpp** - (un)packer for RE4 LFS files, allowing you to compress your modded RE4 data to as little as 5% the size in best case!

* **re4resample.cpp** - tool for extracting & resampling XWB files used by RE4 (resampling low-sample-rate audio to a higher rate should improve any HRTF effects mixed into the audio)

* **re4sym.cpp** - parser for SYM files included with the RE4 GC debug build, allows exporting the SYM as both IDA & Ghidra scripts

* **prodg-rel.py** - IDAPython loader for PS2 "SN ProDG relocatable DLL" files, as used by the RE4 PS2 versions, will automatically name functions with whatever symbols are available in the REL.

* **ProDG-SNR2.bt** - 010 Editor template for PS2 ProDG SNR2/REL files

More tools may be added later on, who knows.

If anything here helped you in some way, maybe consider buying me a coffee at [https://ko-fi.com/emoose](https://ko-fi.com/emoose)
