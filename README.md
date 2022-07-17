# NAME

`dvplc` - Convert Dava game engine's SmartDLC DVPL files. 

# STATUS

WORK IN PROGRESS. Decoding, encoding, verifying a single file works. 

# SYNOPSIS

`dvplc MODE [OPTION] FILE | DIR [FILE | DIR] ...`

# DESCRIPTION

## MODE

`encode` - Encode source files to DVPL format

`decode` - Decode DVPL files to source files

`verify` - Verify DVPL files

## GENERAL OPTIONS

`--verbose` Verbose logging messages

`--debug` Show debug logging messages 

`--silent` Silence logging messages

`--force` Overwrite files, default is `False`

`--threads` `INT` Number of worker threads. By default the number of threads are defined automatically. 

`--replace` Delete source files after conversion

`--keep` Place converted files to the same directory as source files

`--destination` `DIR` Place converted files in to DIR and mirror the source file tree structure. All source files have to be under working dir. 

## `encode` OPTIONS

`--compression` `lz4` | `lz4_hc` | `rfc1951` | `none`

# DVPL File format

*Credits [Maddoxkkm](https://github.com/Maddoxkkm)*

Starts with stream of Byte data, can be compressed or uncompressed. The last 20 bytes in DVPL files are in the following format:

UINT32LE input size in Byte

UINT32LE compressed block size in Byte

UINT32LE compressed block crc32

UINT32LE compression Type:
* 0: no compression (format used in all uncompressed .dvpl files from SmartDLC)
* 1: LZ4 (not observed but handled by this decompressor)
* 2: LZ4_HC (format used in all compressed .dvpl files from SmartDLC)
* 3: RFC1951 (not implemented in this decompressor since it's not observed)

32-bit Magic Number represents "DVPL" literals in utf8 encoding, encoded in big-Endian.
