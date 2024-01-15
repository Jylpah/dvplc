import pytest  # type: ignore
from pytest import Config
from os.path import dirname, realpath, join as pjoin
from pathlib import Path
from result import Ok, Result
from typer.testing import CliRunner
from click.testing import Result as ClickResult
from typing import List
import logging

from dvplc import (
    Compression,
    encode_dvpl,
    decode_dvpl,
    open_dvpl_or_file,
)
from dvplc.dvplc import app

logger = logging.getLogger()
error = logger.error
message = logger.warning
verbose = logger.info
debug = logger.debug


## Test plan
# 1) mypy static typing
# 2) test encoding
# 3) test verify
# 4) test decoding

FIXTURE_DIR = dirname(realpath(__file__))

SOURCE_FILES = pytest.mark.datafiles(
    pjoin(FIXTURE_DIR, "01_source.txt"),
    pjoin(FIXTURE_DIR, "02_source.bin"),
    on_duplicate="overwrite",
)

DVPL_FILES = pytest.mark.datafiles(
    pjoin(FIXTURE_DIR, "03_source.txt.dvpl"),
    pjoin(FIXTURE_DIR, "04_source.bin.dvpl"),
    on_duplicate="overwrite",
)

OPEN_OR_DVPL_FILES = pytest.mark.datafiles(
    pjoin(FIXTURE_DIR, "01_source.txt"),
    pjoin(FIXTURE_DIR, "02_source.bin"),
    pjoin(FIXTURE_DIR, "03_source.txt.dvpl"),
    pjoin(FIXTURE_DIR, "04_source.bin.dvpl"),
    on_duplicate="overwrite",
)

VERIFY_FILES = pytest.mark.datafiles(
    pjoin(FIXTURE_DIR, "05_source.txt_fails_marker.dvpl"),
    pjoin(FIXTURE_DIR, "06_source.bin_fails_marker.dvpl"),
    pjoin(FIXTURE_DIR, "07_source.txt_fails_compression.dvpl"),
    pjoin(FIXTURE_DIR, "08_source.bin_fails_compression.dvpl"),
    pjoin(FIXTURE_DIR, "09_source.txt_fails_crc.dvpl"),
    pjoin(FIXTURE_DIR, "10_source.bin_fails_crc.dvpl"),
    pjoin(FIXTURE_DIR, "11_source.txt_fails_encoded_size.dvpl"),
    pjoin(FIXTURE_DIR, "12_source.bin_fails_encoded_size.dvpl"),
    pjoin(FIXTURE_DIR, "13_source.txt_fails_decoded_size.dvpl"),
    pjoin(FIXTURE_DIR, "14_source.bin_fails_decoded_size.dvpl"),
    on_duplicate="overwrite",
)


def pytest_configure(config: Config):
    plugin = config.pluginmanager.getplugin("mypy")
    if plugin is not None:
        plugin.mypy_argv.append("--check-untyped-defs")


@pytest.fixture
def test_source_data_0() -> bytes:
    return bytes(
        b"1234567890testsquence1234567890testsquence1234567890testsquence1234567890testsquence1234567890testsquence"
    )


@pytest.fixture
def test_checksums() -> dict[str, str]:
    res: dict[str, str] = dict()
    try:
        with open("checksum.sha256", mode="r", encoding="utf-8") as c:
            while c:
                line = c.readline()
                chksum = line.split()
                res[chksum[1]] = chksum[0]
    except Exception as err:
        logger.error(str(err))
    return res


@pytest.mark.parametrize(
    "compression,working",
    [
        ("none", True),
        ("lz4", True),
        ("lz4_hc", True),
        ("rfc1951", False),
    ],
)
@pytest.mark.asyncio
async def test_1_dvpl_encode_decode_compressions(
    test_source_data_0: bytes, compression: Compression, working: bool
) -> None:
    res: Result[bytes, str]
    res = encode_dvpl(input=test_source_data_0, compression=Compression(compression))

    assert (
        res.is_ok() == working
    ), f"unexpected encoding result, compression={compression}"

    if isinstance(res, Ok):
        res = decode_dvpl(res.ok_value)
        assert isinstance(res, Ok), "decoding failed"
        assert (
            res.ok_value == test_source_data_0
        ), f"decoding encoded data did not return the original data, compression={compression}"


@pytest.mark.parametrize(
    "args,ok",
    [
        (["encode"], True),
        (["--debug", "encode", "--replace"], True),
        (["-v", "--threads", "3", "encode"], True),
        (["--silent", "--force", "encode"], True),
    ],
)
@SOURCE_FILES
def test_2_encode_verify_file(datafiles: Path, args: list[str], ok: bool) -> None:
    input_files: List[str] = list()
    output_files: List[str] = list()

    for input in datafiles.iterdir():
        input_files.append(str(input.resolve()))
        output_files.append(str(input.resolve().with_suffix(".dvpl")))

    result: ClickResult

    args = args + input_files
    debug("running: dvplc %s", " ".join(args))
    result = CliRunner().invoke(app, args)
    assert (result.exit_code == 0) == ok, f"dvplc {' '.join(args)} failed"

    result = CliRunner().invoke(app, ["verify"] + output_files)
    assert (result.exit_code == 0) == ok, "dvplc verify failed"


@pytest.mark.parametrize(
    "args,ok",
    [
        (["decode"], True),
        (["--debug", "decode", "--replace"], True),
        (["-v", "--threads", "2", "decode"], True),
    ],
)
@DVPL_FILES
def test_3_decode_file(datafiles: Path, args: list[str], ok: bool) -> None:
    input_files: List[str] = list()
    output_files: List[str] = list()

    for input in datafiles.iterdir():
        input_files.append(str(input.resolve()))
        output_files.append(str(input.resolve().with_suffix("")))

    result: ClickResult = CliRunner().invoke(app, ["verify"] + output_files)
    assert (result.exit_code == 0) == ok, "dvplc verify failed"

    args = args + input_files
    debug("running: dvplc %s", " ".join(args))
    result = CliRunner().invoke(app, args)
    assert (result.exit_code == 0) == ok, f"dvplc {' '.join(args)} failed"


@VERIFY_FILES
def test_4_verify_file_fails(datafiles: Path) -> None:
    input_files: List[str] = list()

    for input in datafiles.iterdir():
        input_files.append(str(input.resolve()))

    result: ClickResult = CliRunner().invoke(app, ["verify"] + input_files)
    assert (
        result.exit_code != 0
    ), f"dvpl verification failed (false positive): {' '.join([ Path(file).name for file in input_files]) }"

@pytest.mark.asyncio
@OPEN_OR_DVPL_FILES
async def test_5_open_dvpl_or_file(datafiles: Path) -> None:
    for filename in datafiles.iterdir():
        debug(f"opening '{filename}'")
        assert (_ := await open_dvpl_or_file(filename)).is_ok, f"could not open file: {filename}" 
        if filename.suffix == '.dvpl':
            debug(f"opening  '{filename}' without suffix")
            assert (_ := await open_dvpl_or_file(filename.with_suffix(''))).is_ok, f"could not open file: {filename} without .dvpl suffix"