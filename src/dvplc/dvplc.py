#!/usr/bin/env python3

# Script convert Dava game engine's SmartDLC DVPL files
from typing import Optional, Union, Dict
import logging
import argparse
from os import cpu_count, sep, remove, getcwd, makedirs, path
import sys
from asyncio import Task, create_task, wait, CancelledError, run
import aiofiles
from lz4.block import compress, decompress, LZ4BlockError  # type:ignore
import zlib
from pathlib import Path

from pyutils import FileQueue, EventCounter
from pyutils.multilevelformatter import set_mlevel_logging

logging.getLogger("asyncio").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
error = logger.error
message = logger.warning
verbose = logger.info
debug = logger.debug

# Constants & defaults
MODES = ["encode", "decode", "verify"]
COMPRESSION = "lz4_hc"
COMPRESSIONS = ["none", "lz4", "lz4_hc", "rfc1951"]
COMPRESSION_TYPE = dict()
for i in range(0, len(COMPRESSIONS)):
    COMPRESSION_TYPE[COMPRESSIONS[i]] = i
DVPL_MARKER = "DVPL"
DVPL_FOOTER_LEN = 20
CONVERSIONS = ["keep", "replace", "mirror"]
QUEUE_LEN = 1000
THREADS = 5

# main() -------------------------------------------------------------


async def main() -> None:
    # set the directory for the script
    global logger

    try:
        # parse arguments
        parser = argparse.ArgumentParser(
            description="Encoder/decoder for SmartDLC DVPL files"
        )

        arggroup_verbosity = parser.add_mutually_exclusive_group()
        arggroup_verbosity.add_argument(
            "--debug",
            "-d",
            dest="LEVEL",
            action="store_const",
            const="DEBUG",
            help="Debug mode",
        )
        arggroup_verbosity.add_argument(
            "--verbose",
            "-v",
            dest="LEVEL",
            action="store_const",
            const="INFO",
            help="Verbose mode",
        )
        arggroup_verbosity.add_argument(
            "--silent",
            "-s",
            dest="LEVEL",
            action="store_const",
            const="CRITICAL",
            help="Silent mode",
        )
        parser.add_argument(
            "--log", type=str, metavar="LOGFILE", default=None, help="Log to LOGFILE"
        )

        parser.add_argument(
            "--force", action="store_true", default=False, help="Overwrite files"
        )
        parser.add_argument(
            "--threads",
            type=int,
            default=THREADS,
            help="Set number of asynchronous threads. Default is automatic.",
        )
        parser.add_argument(
            "--compression",
            type=str,
            choices=COMPRESSIONS,
            default=COMPRESSION,
            help="Select compression to use when encoding",
        )
        parser.add_argument(
            "mode",
            type=str,
            choices=MODES,
            metavar="encode | decode | verify",
            help="Choose encode/decode mode.",
        )

        arggroup_conversion = parser.add_mutually_exclusive_group()
        arggroup_conversion.add_argument(
            "--keep",
            dest="conversion",
            action="store_const",
            const="keep",
            help="Save converted file(s) into the same dir as source file(s) (Default)",
        )
        arggroup_conversion.add_argument(
            "--replace",
            dest="conversion",
            action="store_const",
            const="replace",
            help="Delete source files after successful conversion",
        )
        arggroup_conversion.add_argument(
            "--mirror-to",
            metavar="DIR",
            type=str,
            default=None,
            help="Mirror converted files to DIR",
        )
        parser.add_argument(
            "--base",
            metavar="DIR",
            type=str,
            default=None,
            help="Base source directory to mirror from",
        )
        parser.add_argument(
            "files",
            metavar="FILE1 [FILE2 ...]",
            type=str,
            nargs="+",
            help="Files to read. Use '-' for STDIN",
        )
        parser.set_defaults(LEVEL="WARNING", conversion="keep")

        args = parser.parse_args()

        # setup logging
        logger.setLevel(args.LEVEL)
        logger_conf: dict[int, str] = {
            logging.INFO: "%(message)s",
            logging.WARNING: "%(message)s",
            logging.ERROR: "%(levelname)s: %(message)s",
        }
        set_mlevel_logging(
            logger,
            fmts=logger_conf,
            fmt="%(levelname)s: %(funcName)s: %(message)s",
            log_file=args.log,
        )

        if args.mirror_to is not None:
            args.conversion = "mirror"
            ## FIX: If one arg, it has to be DIR and will serve as mirror source base,
            # otherwise CWD will be mirror source base and all the source files have to be under it
            # if len(args.files) == 1:
            # 	args.base = args.files[0]
            assert args.base is None or path.isdir(
                args.base
            ), f"If set --base DIR has to be a directory: {args.base}"

        logger.debug("Argumengs given: " + str(args))

        if args.mode in ["decode", "verify"]:
            fq = FileQueue(
                filter="*.dvpl",
                base=None if args.base is None else Path(args.base),
                maxsize=QUEUE_LEN,
            )
        elif args.mode == "encode":
            fq = FileQueue(
                filter="*.dvpl",
                exclude=True,
                base=None if args.base is None else Path(args.base),
                maxsize=QUEUE_LEN,
            )
        else:
            raise ValueError(f"Unknown mode: {args.mode}")

        stats = EventCounter("Files processed ----------------------------------------")
        workers: list[Task] = list()
        logger.debug(f"file queue is {fq.qsize()} long")
        scanner = create_task(fq.mk_queue(args.files))
        for i in range(args.threads):
            workers.append(create_task(process_files(fq, args)))
            logger.debug(f"Process thread {str(i)} started")

        logger.debug("Building file queue")
        await wait([scanner])
        logger.debug("Processing files")
        await fq.join()
        await stats.gather_stats(workers, merge_child=False, cancel=False)

        message(stats.print(do_print=False))

    except Exception as err:
        logger.error(str(err))
        sys.exit(1)


async def process_files(fileQ: FileQueue, args: argparse.Namespace) -> EventCounter:
    stats = EventCounter("Files processed")
    try:
        assert fileQ is not None and args is not None, "parameters must not be None"
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

        if args.conversion == "mirror":
            assert args.mirror_to is not None, "args.mirror_to is not set"
            if args.base is not None:
                src_root = Path(args.base)
            dst_root = Path(args.mirror_to)
        async for src_file in fileQ:
            # src_file = "-"
            # src_file = path.normpath(await fileQ.get())
            stats.log("Processed")
            try:
                dst_file = src_file
                result = False
                if args.conversion == "mirror":
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
                        logger.debug(f"creating dir: {dst_file.parent}")
                        makedirs(dst_file.parent)

                if args.mode == "encode":
                    dst_file = dst_file.with_suffix(".dvpl")
                    verbose(f"encoding file: {dst_file}")
                    result = await encode_dvpl_file(
                        src_file,
                        dst_file,
                        compression=args.compression,
                        force=args.force,
                    )
                    # stats.log('Encoded')
                elif args.mode == "decode":
                    dst_file = dst_file.with_suffix("")
                    verbose(f"decoding file: {src_file}")
                    result = await decode_dvpl_file(
                        src_file, dst_file, force=args.force
                    )
                    # stats.log('Decoded')
                elif args.mode == "verify":
                    result = await verify_dvpl_file(src_file)

                if result:
                    stats.log(f"{action[args.mode]} OK")
                else:
                    stats.log(f"{action[args.mode]} FAILED")

                if result and args.conversion == "replace" and args.mode != "verify":
                    logger.debug(f"Removing source file: {src_file}")
                    remove(src_file)
            except Exception as err:
                stats.log("Errors")
                logger.error(f"{str(err)} : {src_file}")

    except CancelledError:
        logger.debug("Worker cancelled")
    except Exception as err:
        logger.error(str(err))
    return stats


async def decode_dvpl_file(dvpl_fn: Path, output_fn: Path, force: bool = False) -> bool:
    """Encode a source file to a DVPL file"""

    assert dvpl_fn is not None, f"DVPL file name is None"
    assert output_fn is not None, f"output file name is None"
    assert force is not None, f"--force value is None"

    try:
        output: Optional[bytes] = None
        status = ""

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
        output = bytes()
        async with aiofiles.open(dvpl_fn, mode="rb") as ifp:
            output, status = decode_dvpl(await ifp.read())

        ## Write decoded file
        if output is None:
            raise EncodingWarning(f"Error decoding data: {dvpl_fn} : {status}")
        async with aiofiles.open(output_fn, mode="wb") as ofp:
            logger.debug(f"writing to file: {output_fn}")
            await ofp.write(output)

        return True
    except CancelledError as err:
        verbose("Cancelled")
    except Exception as err:
        logger.error(str(err))
    return False


def decode_dvpl(input: bytes, quiet: bool = False) -> tuple[Optional[bytes], str]:
    """Decode a DVPL bytearray"""

    assert input is not None, f"input value is None"
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
            logger.debug(f"Encoded CRC matches {hex(e_crc)}")

        output = bytes()

        if t_type == "none":
            output = input
        elif t_type == "lz4" or t_type == "lz4_hc":
            output = decompress(input, uncompressed_size=d_size)
        elif t_type == "rfc1951":
            raise NotImplementedError("RFC1951 encoding is not supported")
        if len(output) != d_size:
            raise EncodingWarning("Decoded data size differs from DVPL footer into")

        logger.debug("decoded CRC32: " + hex(zlib.crc32(output)))

        assert output is not None, f"Output value is None"
        assert isinstance(output, bytes), f"Output needs to be bytes, got {type(input)}"

        return output, "OK"

    except LZ4BlockError as err:
        if not quiet:
            logger.error("LZ4 decoding error: " + str(err))
        return None, "LZ4 decoding error"
    except Exception as err:
        if not quiet:
            logger.error(str(err))
        return None, str(err)


async def encode_dvpl_file(
    input_fn: Path, dvpl_fn: Path, compression: str = COMPRESSION, force: bool = False
) -> bool:
    """Encode a source file to a DVPL file"""

    assert input_fn is not None, f"input file name is None"
    assert dvpl_fn is not None, f"DVPL file name is None"
    assert compression in COMPRESSIONS, f"Unknown compression: {compression}"
    assert force is not None, f"--force is None"

    try:
        output: Optional[bytes] = None
        status = ""
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
        async with aiofiles.open(input_fn, mode="rb") as ifp:
            output, status = encode_dvpl(await ifp.read(), compression)

        ## Write dvpl file
        if output is None:
            raise EncodingWarning(f"Error encoding data: {status}")
        async with aiofiles.open(dvpl_fn, mode="wb") as ofp:
            logger.debug(f"writing to file: {dvpl_fn}")
            await ofp.write(output)
        return True
    except CancelledError as err:
        verbose("Cancelled")
    except Exception as err:
        logger.error(str(err))
    return False


def encode_dvpl(
    input: bytes, compression: str, quiet: bool = False
) -> tuple[Optional[bytes], str]:
    """Encode data to a DVPL format"""

    assert isinstance(input, bytes), f"input needs to be bytes, got {type(input)}"
    assert input is not None, f"input is None"
    assert compression in COMPRESSIONS, f"Unknown compression: {compression}"

    try:
        output: bytes | None = None
        d_size = len(input)
        if compression.startswith("lz4"):
            mode = "high_compression"
            if compression == "lz4":
                mode = "default"
            output = compress(input, mode=mode, store_size=False)
        elif compression == "none":
            output = input
        elif compression == "rfc1951":
            raise NotImplementedError("RFC1951 compression is not supported")

        if output is not None:
            footer = make_dvpl_footer(output, d_size, compression)

            logger.debug("decoded CRC32: " + hex(zlib.crc32(input)))
            if footer is not None:
                return output + footer, "OK"

    except LZ4BlockError as err:
        if not quiet:
            logger.error("LZ4 encoding error")
        return None, "LZ4 encoding error"
    except Exception as err:
        if not quiet:
            logger.error(str(err))
        return None, str(err)
    return None, "Unknown error"


async def verify_dvpl_file(dvpl_fn: Path) -> bool:
    """Verify a DVPL file"""

    assert dvpl_fn is not None, f"input file name is None type"

    try:
        output: Optional[bytes] = None
        status = ""
        if not path.isfile(dvpl_fn):
            raise FileNotFoundError(f"Source file not found: {dvpl_fn}")
        if dvpl_fn.suffix.lower() != ".dvpl":
            raise ValueError(f"Source file is not a DVPL file: {dvpl_fn}")

        ## Try to decode a DVPL file
        async with aiofiles.open(dvpl_fn, mode="rb") as ifp:
            logger.debug(f"reading file: {dvpl_fn}")
            output, status = decode_dvpl(await ifp.read(), quiet=True)
        if output is not None:
            verbose(f"{dvpl_fn} : OK")
            return True
        else:
            message(f"{dvpl_fn} : ERROR: {status}")
            return False
    except CancelledError as err:
        verbose("Cancelled")
    except Exception as err:
        logger.error(str(err))
    return False


def make_dvpl_footer(encoded: bytes, d_size: int, compression: str) -> Optional[bytes]:
    """Make a 20-byte DVPL footer"""

    assert isinstance(encoded, bytes), f"input needs to be bytes, got {type(encoded)}"
    assert compression in COMPRESSIONS, f"Unknown compression: {compression}"

    try:
        """Makes DVPL footer for the encoded (compressed) input"""
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.debug("decoded size: " + str(d_size))
            logger.debug("encoded size: " + str(len(encoded)))
            logger.debug("encoded CRC32: " + hex(zlib.crc32(encoded)))
            logger.debug("encoding type: " + compression)

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

        assert len(footer) == 20, f"Footer size != 20"
        return bytes(footer)
    except Exception as err:
        logger.error(str(err))
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
        COMPRESSIONS
    ), "unknown compression in DVPL footer"
    result["e_type"] = COMPRESSIONS[f_compression]

    if logger.getEffectiveLevel() == logging.DEBUG:
        logger.debug("decoded size: " + str(result["d_size"]))
        logger.debug("encoded size: " + str(result["e_size"]))
        if isinstance(result["e_crc"], int):
            logger.debug("encoded CRC32: " + hex(result["e_crc"]))
        logger.debug("encoding type: " + str(result["e_type"]))

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
        logger.error(str(err))
    return None


def fromUInt32LE(data: bytes) -> Optional[int]:
    """Convert a 32-bit unsigned integer in Little-Endian byte-order to integer"""
    try:
        if data is None:
            raise ValueError("None given as input")
        return int.from_bytes(data, byteorder="little", signed=False)
    except Exception as err:
        logger.error(str(err))
    return None


### main()
if __name__ == "__main__":
    # asyncio.run(main(sys.argv[1:]), debug=True)
    run(main())


def cli_main() -> None:
    return run(main())
