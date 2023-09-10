# NAME

`dvplc` - encode/decode/verify Dava game engine's SmartDLC DVPL files. 

# STATUS

Tested on Linux & Working :-) 

## TODO

* Test on other platforms
* Provide a proper Python package

# Installation 

*Python 3.10+ is required*

```
pip install git+https://github.com/Jylpah/dvplc.git
```
## Update

```
pip install --upgrade git+https://github.com/Jylpah/dvplc.git
``` 
or 
```
pip install --upgrade --force-reinstall git+https://github.com/Jylpah/dvplc.git
```

# SYNOPSIS

`dvplc [OPTIONS] MODE FILE | DIR [FILE | DIR] ...`

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

`--keep` Place converted files to the same directory as source files (default)

`--replace` Delete source files after conversion

`--mirror` `DIR` Mirror source tree structure to DIR and place converted files there. All source files have to be under working dir. 

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
