#!/usr/bin/env python3

# Script convert Dava game engine's SmartDLC DVPL files
from typing import Optional, Union, Dict, Annotated, List, Literal, TypeAlias, Tuple
import logging

# import argparse
from os import remove, makedirs, path
from asyncio import Task, create_task, wait, CancelledError, gather
import aiofiles
from lz4.block import compress, decompress, LZ4BlockError  # type:ignore
import zlib
from pathlib import Path
from typer import Context, Option, Argument, Exit
from result import Ok, Err, Result, UnwrapError
from enum import StrEnum

from pyutils import FileQueue, EventCounter, AsyncTyper
from pyutils.multilevelformatter import MultilevelFormatter
from pyutils.utils import add_suffix

logging.getLogger("asyncio").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
error = logger.error
message = logger.warning
verbose = logger.info
debug = logger.debug

# Constants & defaults
MODES = ["encode", "decode", "verify"]
Mode: TypeAlias = Literal["encode", "decode", "verify"]

# fmt: off
class Compression(StrEnum):
    none            = "none"
    default         = "lz4"
    high_compression= "lz4_hc"
    RFC1951         = "rfc1951"
# fmt: on

# Compression: TypeAlias = Literal["none", "lz4", "lz4_hc", "rfc1951"]
DEFAULT_COMPRESSION: Compression = Compression.default

COMPRESSION_TYPE = dict()
for i in range(0, len(Compression)):
    COMPRESSION_TYPE[list(Compression)[i]] = i
DVPL_MARKER = "DVPL"
DVPL_FOOTER_LEN = 20
CONVERSIONS = ["keep", "replace", "mirror"]
QUEUE_LEN = 1000
THREADS = 5


# main() -------------------------------------------------------------

app = AsyncTyper()


@app.callback()
def cli(
    ctx: Context,
    print_verbose: Annotated[
        bool,
        Option(
            "--verbose",
            "-v",
            show_default=False,
            # metavar="",
            help="verbose logging",
        ),
    ] = False,
    print_debug: Annotated[
        bool,
        Option(
            "--debug",
            show_default=False,
            metavar="",
            help="debug logging",
        ),
    ] = False,
    print_silent: Annotated[
        bool,
        Option(
            "--silent",
            show_default=False,
            metavar="",
            help="silent logging",
        ),
    ] = False,
    force: Annotated[
        bool,
        Option(show_default=False, help="Overwrite existing files"),
    ] = False,
    threads: Annotated[
        int,
        Option(help="Set number of asynchronous threads"),
    ] = THREADS,
    log: Annotated[Optional[Path], Option(help="log to FILE", metavar="FILE")] = None,
) -> None:
    """Encoder/decoder for SmartDLC DVPL files used e.g. in Wargaming's games"""
    global logger

    try:
        LOG_LEVEL: int = logging.WARNING
        if print_verbose:
            LOG_LEVEL = logging.INFO
        elif print_debug:
            LOG_LEVEL = logging.DEBUG
        elif print_silent:
            LOG_LEVEL = logging.ERROR
        MultilevelFormatter.setDefaults(logger, log_file=log)
        logger.setLevel(LOG_LEVEL)

        ctx.ensure_object(dict)
        ctx.obj["force"] = force
        ctx.obj["threads"] = threads

    except Exception as err:
        error(f"error parsing command line options: {err}")
        raise Exit(code=1)


def callback_paths(value: Optional[list[Path]]) -> list[Path]:
    return value if value is not None else []


async def _gather_results(
    workers: List[Task], stats: EventCounter, ret_val: int = 0
) -> Tuple[EventCounter, int]:
    for res in await gather(*workers, return_exceptions=True):
        if isinstance(res, Ok):
            stats.merge(res.ok_value)
        elif isinstance(res, Err):
            stats.merge(res.err_value)
            ret_val = 1
        elif isinstance(res, BaseException):
            raise res
        else:
            raise ValueError(f"unknown return value: {res}")
    return stats, ret_val


@app.async_command()
async def decode(
    ctx: Context,
    replace: Annotated[
        bool, Option(help="Delete source files after successful conversion")
    ] = False,
    mirror_from: Annotated[
        Optional[Path], Option(metavar="DIR", help="Base DIR to mirror from")
    ] = None,
    mirror_to: Annotated[
        Path,
        Option(
            file_okay=False,
            metavar="DIR",
            show_default=False,
            help="Mirror converted files to DIR. Default is current dir.",
        ),
    ] = Path("."),
    files: List[Path] = Argument(
        help="FILES to decode",
        metavar="FILES",
        show_default=False,
        callback=callback_paths,
    ),
) -> None:
    """decode DVPL files"""
    debug(
        f"starting: --replace={replace} --mirror-from={mirror_from} --mirror-to={mirror_to}"
    )
    ret_val: int
    ret_val = 0
    try:
        fq = FileQueue(
            filter="*.dvpl",
            case_sensitive=False,
            base=mirror_from,
            maxsize=QUEUE_LEN,
        )
        stats = EventCounter("Files processed:")
        force: bool = ctx.obj["force"]
        workers: list[Task] = list()
        debug(f"file queue is {fq.qsize()} long")
        scanner = create_task(fq.mk_queue(files))
        for i in range(ctx.obj["threads"]):
            workers.append(
                create_task(
                    process_files(
                        fq,
                        mode="decode",
                        replace=replace,
                        force=force,
                        mirror_from=mirror_from,
                        mirror_to=mirror_to,
                    )
                )
            )
            debug(f"Process thread {str(i)} started")

        debug("Building file queue")
        await wait([scanner])
        debug("Processing files")
        await fq.join()
        stats, ret_val = await _gather_results(workers, stats, ret_val)

        message(stats.print(do_print=False))

    except Exception as err:
        error(str(err))
        raise Exit(code=2)
    raise Exit(code=ret_val)


@app.async_command()
async def encode(
    ctx: Context,
    compression: Annotated[
        Compression, Option(help="Select compression to use when encoding")
    ] = DEFAULT_COMPRESSION,
    replace: Annotated[
        bool, Option(help="Delete source files after successful encoding")
    ] = False,
    mirror_from: Annotated[
        Optional[Path], Option(metavar="DIR", help="mirror FILES from")
    ] = None,
    mirror_to: Annotated[
        Path,
        Option(
            file_okay=False,
            metavar="DIR",
            show_default=False,
            help="Mirror converted files to DIR. Default is current dir.",
        ),
    ] = Path("."),
    files: List[Path] = Argument(
        help="FILES to encode",
        metavar="FILES",
        show_default=False,
        callback=callback_paths,
    ),
) -> None:
    """encode DVPL files"""
    debug(
        f"starting: --replace={replace} --mirror-from={mirror_from} --mirror-to={mirror_to}"
    )
    ret_val: int
    ret_val = 0
    try:
        fq = FileQueue(
            filter="*.dvpl",
            exclude=True,
            case_sensitive=False,
            base=mirror_from,
            maxsize=QUEUE_LEN,
        )

        stats = EventCounter("Files processed:")
        force: bool = ctx.obj["force"]
        workers: list[Task] = list()
        debug(f"file queue is {fq.qsize()} long")
        scanner = create_task(fq.mk_queue(files))
        for i in range(ctx.obj["threads"]):
            workers.append(
                create_task(
                    process_files(
                        fq,
                        mode="encode",
                        replace=replace,
                        force=force,
                        mirror_from=mirror_from,
                        mirror_to=mirror_to,
                        compression=compression,
                    )
                )
            )
            debug(f"Process thread {str(i)} started")

        debug("Building file queue")
        await wait([scanner])
        debug("Processing files")
        await fq.join()
        stats, ret_val = await _gather_results(workers, stats, ret_val)
        message(stats.print(do_print=False))

    except Exception as err:
        error(str(err))
        raise Exit(code=2)
    raise Exit(code=ret_val)


@app.async_command()
async def verify(
    ctx: Context,
    files: List[Path] = Argument(
        help="FILES to decode",
        metavar="FILES",
        show_default=False,
        callback=callback_paths,
    ),
) -> None:
    """verify DVPL files"""
    debug("starting")
    ret_val: int
    ret_val = 0
    try:
        fq = FileQueue(
            filter="*.dvpl",
            case_sensitive=False,
            maxsize=QUEUE_LEN,
        )

        stats = EventCounter("Files processed:")
        workers: list[Task] = list()
        debug(f"file queue is {fq.qsize()} long")
        scanner = create_task(fq.mk_queue(files))
        for i in range(ctx.obj["threads"]):
            workers.append(
                create_task(
                    process_files(
                        fq,
                        mode="verify",
                    )
                )
            )
            debug(f"Process thread {str(i)} started")

        debug("Building file queue")
        await wait([scanner])
        debug("Processing files")
        await fq.join()
        stats, ret_val = await _gather_results(workers, stats, ret_val)
        message(stats.print(do_print=False))
        print(f"exit value={ret_val}")
    except Exception as err:
        error(str(err))
        raise Exit(code=4)

    raise Exit(code=ret_val)


async def process_files(
    fileQ: FileQueue,
    mode: Mode,
    replace: bool = False,
    force: bool = False,
    mirror_from: Path | None = None,
    mirror_to: Path = Path("."),
    compression: Compression = DEFAULT_COMPRESSION,
) -> Result[EventCounter, EventCounter]:
    stats = EventCounter("Files processed")
    try:
        # assert fileQ is not None and args is not None, "parameters must not be None"
        src_root: Path = Path(".")
        dst_root: Path = Path(".")
        src_file: Path
        dst_file: Path
        src_rel: Path
        action: dict[str, str] = {
            "encode": "Encoded",
            "decode": "Decoded",
            "verify": "Verified",
        }
        res_ok: bool = True

        if mirror_from is not None:
            src_root = mirror_from
            dst_root = mirror_to
            if replace:
                message("--replace is ignored with --mirror-from")

        async for src_file in fileQ:
            stats.log("Processed")
            try:
                dst_file = src_file
                result = False
                if mirror_from is not None:
                    try:
                        src_rel = src_file.relative_to(src_root)
                    except ValueError:
                        error(
                            f"source file ({src_file}) is not under source root ({src_root})"
                        )
                        stats.log("Skipped")
                        continue
                    dst_file = dst_root / src_rel
                    if not dst_file.parent.is_dir():
                        debug(f"creating dir: {dst_file.parent}")
                        makedirs(dst_file.parent)

                match mode:
                    case "encode":
                        dst_file = add_suffix(dst_file, ".dvpl")
                        verbose(f"encoding file: {dst_file}")
                        result = await encode_dvpl_file(
                            src_file,
                            dst_file,
                            compression=compression,
                            force=force,
                        )
                    case "decode":
                        dst_file = dst_file.with_suffix("")
                        verbose(f"decoding file: {src_file}")
                        result = await decode_dvpl_file(src_file, dst_file, force=force)

                    case "verify":
                        result = await verify_dvpl_file(src_file)

                if result:
                    stats.log(f"{action[mode]} OK")
                else:
                    stats.log(f"{action[mode]} FAILED")
                    res_ok = False

                if result and replace and mode != "verify":
                    debug(f"Removing source file: {src_file}")
                    remove(src_file)
            except Exception as err:
                stats.log("Errors")
                res_ok = False
                error(f"{str(err)} : {src_file}")

    except CancelledError:
        debug("Worker cancelled")
        res_ok = False
    except Exception as err:
        error(str(err))
        res_ok = False
    if res_ok:
        return Ok(stats)
    else:
        return Err(stats)


async def decode_dvpl_file(dvpl_fn: Path, output_fn: Path, force: bool = False) -> bool:
    """Encode a source file to a DVPL file"""

    assert dvpl_fn is not None, "DVPL file name is None"
    assert output_fn is not None, "output file name is None"
    assert force is not None, "--force value is None"

    try:
        output: bytes = bytes()

        if not dvpl_fn.is_file():
            raise FileNotFoundError(f"Source file not found: {dvpl_fn}")
        if dvpl_fn.suffix.lower() != ".dvpl":
            raise ValueError(f"Source file is not a DVPL file: {dvpl_fn}")
        if output_fn.suffix.lower() == ".dvpl":
            raise ValueError(f"Output file is a DVPL file: {output_fn}")
        if output_fn.exists() and not force:
            raise FileExistsError(
                f"Output file exists, use --force to overwrite {output_fn}"
            )

        ## Read encoded DVPL file
        result: Result[bytes, str]
        async with aiofiles.open(dvpl_fn, mode="rb") as ifp:
            result = decode_dvpl(await ifp.read())
            output = result.unwrap()

        # ## Write decoded file
        # if output is None:
        #     raise EncodingWarning(f"Error decoding data: {dvpl_fn} : {status}")
        async with aiofiles.open(output_fn, mode="wb") as ofp:
            debug(f"writing to file: {output_fn}")
            await ofp.write(output)
        return True
    except UnwrapError as err:
        error(f"could not decode file: {dvpl_fn}: {err}")
    except CancelledError:
        verbose("Cancelled")
    except Exception as err:
        error(str(err))
    return False


def decode_dvpl(input: bytes) -> Result[bytes, str]:
    """Decode a DVPL bytearray"""

    assert input is not None, "input value is None"
    assert isinstance(input, bytes), f"input needs to be bytes, got {type(input)}"

    try:
        footer, input = read_dvpl_footer(input)

        d_size = footer["d_size"]  # decoded (output) size
        t_type = footer["e_type"]  # encoding type
        e_crc = footer["e_crc"]  # CRC32 of endocoded (input) data
        e_length = footer["e_size"]  # encoded (input) size

        if e_length != len(input):
            raise EncodingWarning("Encoded DVPL data size differs DVPL footer info")
        if e_crc != zlib.crc32(input):
            raise EncodingWarning(
                "Encoded DVPL data CRC32 differs DVPL footer checksum"
            )
        else:
            debug(f"Encoded CRC matches {hex(e_crc)}")

        output = bytes()

        if t_type == "none":
            output = input
        elif t_type == "lz4" or t_type == "lz4_hc":
            output = decompress(input, uncompressed_size=d_size)
        elif t_type == "rfc1951":
            raise NotImplementedError("RFC1951 encoding is not supported")
        if len(output) != d_size:
            raise EncodingWarning("Decoded data size differs from DVPL footer into")

        debug("decoded CRC32: " + hex(zlib.crc32(output)))

        if output is None:
            raise ValueError(
                "DVPL decoding gave no output"
            )  # what if the encoded file is NULL size?
        if not isinstance(output, bytes):
            raise TypeError(f"Output needs to be bytes, got {type(input)}")

        return Ok(output)

    except LZ4BlockError as err:
        # if not quiet:
        #     error("LZ4 decoding error: " + str(err))
        return Err(f"LZ4 decoding error: {err}")
    except Exception as err:
        return Err(str(err))

async def open_dvpl_or_file(filename: Path) -> Result[bytes, str]:
    """Open 'filename', DVPL or not"""
    try:
        if filename.is_file() or (filename := add_suffix(filename, ".dvpl")).is_file():
            pass
        else:
            raise FileNotFoundError(f"could not find file: {filename}")
        debug("opening %s", str(filename))
        async with aiofiles.open(filename, "br") as file:
            if filename.suffix.lower() == ".dvpl":
                debug("opening DVPL file: %s", str(filename))
                return decode_dvpl(await file.read())
            else:
                debug("opening file: %s", str(filename))
                return Ok(await file.read())
    except Exception as err:
        return Err(f"could not open file: {filename}: {err}")
    

async def encode_dvpl_file(
    input_fn: Path,
    dvpl_fn: Path,
    compression: Compression = DEFAULT_COMPRESSION,
    force: bool = False,
) -> bool:
    """Encode a source file to a DVPL file"""

    assert input_fn is not None, "input file name is None"
    assert dvpl_fn is not None, "DVPL file name is None"
    assert isinstance(compression, Compression), f"Unknown compression: {compression}"
    assert force is not None, "--force is None"

    try:
        output: Optional[bytes] = None
        if not input_fn.is_file():
            raise FileNotFoundError(f"Source file not found: {input_fn}")
        if input_fn.suffix.lower() == ".dvpl":
            raise ValueError(f"Source file is a DVPL file: {input_fn}")
        if not dvpl_fn.suffix.lower() == ".dvpl":
            raise ValueError(f"Output file is not a DVPL file: {input_fn}")
        if dvpl_fn.exists() and not force:
            raise FileExistsError(
                f"Output file exists, use --force to overwrite: {dvpl_fn}"
            )

        # read source file
        output = bytes()
        result: Result[bytes, str]
        async with aiofiles.open(input_fn, mode="rb") as ifp:
            result = encode_dvpl(await ifp.read(), compression)
            output = result.unwrap()

            # raise EncodingWarning(f"Error encoding data: {status}")
        async with aiofiles.open(dvpl_fn, mode="wb") as ofp:
            debug(f"writing to file: {dvpl_fn}")
            await ofp.write(output)
        return True
    except UnwrapError as err:
        error(f"could not encode file: {dvpl_fn}: {err}")
    except CancelledError:
        verbose("Cancelled")
    except Exception as err:
        error(str(err))
    return False


def encode_dvpl(
    input: bytes, compression: Compression = DEFAULT_COMPRESSION
) -> Result[bytes, str]:
    """Encode data to a DVPL format"""

    assert isinstance(input, bytes), f"input needs to be bytes, got {type(input)}"
    assert input is not None, "input is None"
    assert isinstance(compression, Compression), f"Unknown compression: {compression}"

    try:
        output: bytes | None = None
        d_size = len(input)

        mode: str = compression.name

        if mode == Compression.RFC1951:
            raise NotImplementedError("RFC1951 compression is not supported")

        if compression != Compression.none:
            output = compress(input, mode=mode, store_size=False)
        else:
            output = input

        if output is not None:
            footer = make_dvpl_footer(output, d_size, compression)
            debug("decoded CRC32: " + hex(zlib.crc32(input)))
            if footer is not None:
                return Ok(output + footer)

    except LZ4BlockError:
        # if not quiet:
        #     error("LZ4 encoding error")
        return Err("LZ4 encoding error")
    except Exception as err:
        # if not quiet:
        #     error(str(err))
        return Err(str(err))
    return Err("Unknown error")


async def verify_dvpl_file(dvpl_fn: Path) -> bool:
    """Verify a DVPL file"""

    assert dvpl_fn is not None, "input file name is None type"

    try:
        if not path.isfile(dvpl_fn):
            raise FileNotFoundError(f"Source file not found: {dvpl_fn}")
        if dvpl_fn.suffix.lower() != ".dvpl":
            raise ValueError(f"Source file is not a DVPL file: {dvpl_fn}")

        ## Try to decode a DVPL file
        result: Result[bytes, str]
        async with aiofiles.open(dvpl_fn, mode="rb") as ifp:
            debug(f"reading file: {dvpl_fn}")
            result = decode_dvpl(await ifp.read())
        if isinstance(result, Err):
            message(f"{dvpl_fn} : ERROR: {result.err_value}")
        elif isinstance(result, Ok):
            verbose(f"{dvpl_fn} : OK")
            return True
        else:
            error("unknown error")
    except CancelledError:
        verbose("Cancelled")
    except Exception as err:
        error(str(err))
    return False


def make_dvpl_footer(encoded: bytes, d_size: int, compression: str) -> Optional[bytes]:
    """Make a 20-byte DVPL footer"""

    assert isinstance(encoded, bytes), f"input needs to be bytes, got {type(encoded)}"
    assert isinstance(compression, Compression), f"Unknown compression: {compression}"

    try:
        """Makes DVPL footer for the encoded (compressed) input"""
        if logger.getEffectiveLevel() == logging.DEBUG:
            debug("decoded size: " + str(d_size))
            debug("encoded size: " + str(len(encoded)))
            debug("encoded CRC32: " + hex(zlib.crc32(encoded)))
            debug("encoding type: " + compression)

        footer = bytearray()
        f_d_size = toUInt32LE(d_size)  # input size as UInt32LE
        f_e_size = toUInt32LE(len(encoded))  # output size as UInt32LE
        f_crc32 = toUInt32LE(zlib.crc32(encoded))  # output crc32 as UInt32LE
        f_compression = toUInt32LE(
            COMPRESSION_TYPE[compression]
        )  # output type as UInt32LE

        assert (
            (f_d_size is not None)
            and (f_e_size is not None)
            and (f_crc32 is not None)
            and (f_compression is not None)
        ), "Making DVPL footer failed"
        footer += f_d_size  # input size as UInt32LE
        footer += f_e_size  # output size as UInt32LE
        footer += f_crc32  # outout crc32 as UInt32LE
        footer += f_compression  # output type as UInt32LE
        footer += DVPL_MARKER.encode(encoding="utf-8", errors="strict")

        assert len(footer) == 20, "Footer size != 20"
        return bytes(footer)
    except Exception as err:
        error(str(err))
    return None


def read_dvpl_footer(data: bytes) -> tuple[dict, bytes]:
    """Read and check 20 byte DVPL footer"""

    assert isinstance(data, bytes), f"input needs to be bytes, got {type(data)}"

    result: Dict[str, Union[int, str]] = dict()

    if len(data) < DVPL_FOOTER_LEN:
        raise EncodingWarning("Data is too short (< 20 bytes)")

    footer = data[-DVPL_FOOTER_LEN:]

    result["marker"] = str(footer[-4:], encoding="utf-8", errors="strict")
    if result["marker"] != DVPL_MARKER:
        raise EncodingWarning("File is missing 'DVPL' marker in the end of the file.")

    f_d_size = fromUInt32LE(footer[:4])  # decoded size
    f_e_size = fromUInt32LE(footer[4:8])  # encoded size
    f_crc32 = fromUInt32LE(footer[8:12])  # encoded CRC32
    f_compression = fromUInt32LE(footer[12:16])  # encoding type

    assert (
        (f_d_size is not None)
        and (f_e_size is not None)
        and (f_crc32 is not None)
        and (f_compression is not None)
    ), "Malformed DVPL footer"
    result["d_size"] = f_d_size
    result["e_size"] = f_e_size
    result["e_crc"] = f_crc32
    assert f_compression >= 0 and f_compression < len(
        Compression
    ), "unknown compression in DVPL footer"
    result["e_type"] = list(Compression)[f_compression]

    if logger.getEffectiveLevel() == logging.DEBUG:
        debug("decoded size: " + str(result["d_size"]))
        debug("encoded size: " + str(result["e_size"]))
        if isinstance(result["e_crc"], int):
            debug("encoded CRC32: " + hex(result["e_crc"]))
        debug("encoding type: " + str(result["e_type"]))

    return result, data[:-DVPL_FOOTER_LEN]


def toUInt32LE(value: int) -> Optional[bytes]:
    """Convert an integer to 32-bit unsigned integer in Little-Endian byte-order"""
    try:
        if value is None:
            raise ValueError("None given as input")
        if value < 0:
            raise ValueError("Cannot cast negative value as unsigned int")
        return value.to_bytes(4, byteorder="little", signed=False)
    except Exception as err:
        error(str(err))
    return None


def fromUInt32LE(data: bytes) -> Optional[int]:
    """Convert a 32-bit unsigned integer in Little-Endian byte-order to integer"""
    try:
        if data is None:
            raise ValueError("None given as input")
        return int.from_bytes(data, byteorder="little", signed=False)
    except Exception as err:
        error(str(err))
    return None


# ### main()
# if __name__ == "__main__":
#     # asyncio.run(main(sys.argv[1:]), debug=True)
#     run(main())

if __name__ == "__main__":
    app()
