# NAME
`dvplc` - convert Dava game engine's SmartDLC DVPL files. 

# SYNOPSIS
`dvplc` MODE [OPTION] FILE | DIR [FILE | DIR] ...

# DESCRIPTION

## OPTIONS
 `-h` | `--help` Show help

`--verbose` Verbose logging messages

 `--debug` Show debug logging messages 

`--silent` Silence logging messages

`--force` Overwrite files, default is False

`--threads` `int`, number of worker threads. By default the number of threads are defined automatically. 

`--replace` Delete source files after successful conversion

`--keep` Keep source files (default)

`--mirror` `DIR` Mirror source files to `DIR`

## MODE
`encode` - Encode source files to DVPL format

`decode` - Decode DVPL files to source files

`verify` - Verify DVPL files

## decode OPTIONS
--compression lz4 | lz4_hc | rfc1951 | none

DVPL File format
Credits Maddoxkkm

Starts with stream of Byte data, can be compressed or uncompressed. The last 20 bytes in DVPL files are in the following format:

UINT32LE input size in Byte

UINT32LE compressed block size in Byte

UINT32LE compressed block crc32

UINT32LE compression Type

0: no compression (format used in all uncompressed .dvpl files from SmartDLC)

1: LZ4 (not observed but handled by this decompressor)

2: LZ4_HC (format used in all compressed .dvpl files from SmartDLC)

3: RFC1951 (not implemented in this decompressor since it's not observed)

32-bit Magic Number represents "DVPL" literals in utf8 encoding, encoded in big-Endian.
