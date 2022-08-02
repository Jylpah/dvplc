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

## `decode` OPTIONS
--compression lz4 | lz4_hc | rfc1951 | none

DVPL File format
Credits Maddoxkkm
=======

`dvplc` - Convert Dava game engine's SmartDLC DVPL files. 

# STATUS

Tested on Linux & Working :-) 

## TODO

* Write automated tests
* Test on other platforms 
* Write installation instructions
* Easier installation

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

UINT32LE compression Type

0: no compression (format used in all uncompressed .dvpl files from SmartDLC)

1: LZ4 (not observed but handled by this decompressor)

2: LZ4_HC (format used in all compressed .dvpl files from SmartDLC)

3: RFC1951 (not implemented in this decompressor since it's not observed)
=======
UINT32LE compression Type:
* 0: no compression (format used in all uncompressed .dvpl files from SmartDLC)
* 1: LZ4 (not observed but handled by this decompressor)
* 2: LZ4_HC (format used in all compressed .dvpl files from SmartDLC)
* 3: RFC1951 (not implemented in this decompressor since it's not observed)
