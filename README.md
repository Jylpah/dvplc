![CI](https://github.com/Jylpah/dvplc/actions/workflows/python-package.yml/badge.svg) [![codecov](https://codecov.io/gh/Jylpah/dvplc/graph/badge.svg?token=IDH9SJB44Q)](https://codecov.io/gh/Jylpah/dvplc)  [![CodeQL](https://github.com/Jylpah/dvplc/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Jylpah/dvplc/actions/workflows/github-code-scanning/codeql)

# dvplc

`dvplc` - [Python](https://python.org) app to encode/decode/verify Dava game engine's SmartDLC DVPL files. The file format is used in [Wargaming's](https://wargaming.net) [World of Tanks Blitz mobile](https://wotblitz.com/) game. 

# STATUS

Tested on Linux, Mac and Windows OK 

## TODO

- [ ] Provide a proper Python package

### Done

- [x] Test on other platforms: CI testing pipeline configured for MacOS and Windows


# Installation 

*Python 3.11 or later is required*

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


## `dvplc` usage

```
Usage: dvplc [OPTIONS] COMMAND [ARGS]...

  Encoder/decoder for SmartDLC DVPL files used e.g. in Wargaming's games

Options:
  -v, --verbose                   verbose logging
  --debug                         debug logging
  --silent                        silent logging
  --force / --no-force            Overwrite existing files
  --threads INTEGER               Set number of asynchronous threads  [default:
                                  5]
  --log FILE                      log to FILE
  --install-completion [bash|zsh|fish|powershell|pwsh]
                                  Install completion for the specified shell.
  --show-completion [bash|zsh|fish|powershell|pwsh]
                                  Show completion for the specified shell, to
                                  copy it or customize the installation.
  --help                          Show this message and exit.

Commands:
  decode  decode DVPL files
  encode  encode DVPL files
  verify  verify DVPL files

```
### `dvplc encode` usage

```
Usage: dvplc encode [OPTIONS] FILES

  encode DVPL files

Arguments:
  FILES  FILES to encode  [required]

Options:
  --compression [none|lz4|lz4_hc|rfc1951]
                                  Select compression to use when encoding
                                  [default: lz4]
  --replace / --no-replace        Delete source files after successful encoding
                                  [default: no-replace]
  --mirror-from DIR               mirror FILES from
  --mirror-to DIR                 Mirror converted files to DIR. Default is
                                  current dir.
  --help                          Show this message and exit.

```
### `dvplc decode` usage

```
Usage: dvplc decode [OPTIONS] FILES

  decode DVPL files

Arguments:
  FILES  FILES to decode  [required]

Options:
  --replace / --no-replace  Delete source files after successful conversion
                            [default: no-replace]
  --mirror-from DIR         Base DIR to mirror from
  --mirror-to DIR           Mirror converted files to DIR. Default is current
                            dir.
  --help                    Show this message and exit.

```
### `dvplc verify` usage

```
Usage: dvplc verify [OPTIONS] FILES

  verify DVPL files

Arguments:
  FILES  FILES to decode  [required]

Options:
  --help  Show this message and exit.

```



