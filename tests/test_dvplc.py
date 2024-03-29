import pytest  # type: ignore
from pytest import Config
from os.path import dirname, realpath
from asyncio import run
from shutil import rmtree
from pathlib import Path
from result import Ok, Result
from typer.testing import CliRunner
from click.testing import Result as ClickResult
from typing import List, Dict
from hashlib import sha256

import logging

from queutils import FileQueue

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

FIXTURE_DIR = Path(dirname(realpath(__file__)))

SOURCE_FILES = pytest.mark.datafiles(
    FIXTURE_DIR / "01_source.txt",
    FIXTURE_DIR / "02_source.bin",
    on_duplicate="overwrite",
)

SOURCE_DIR: str = "files-src"

SOURCE_SRC_DIR = pytest.mark.datafiles(
    FIXTURE_DIR / SOURCE_DIR,
    keep_top_dir=True,
)


DVPL_FILES = pytest.mark.datafiles(
    FIXTURE_DIR / "03_source.txt.dvpl",
    FIXTURE_DIR / "04_source.bin.dvpl",
    on_duplicate="overwrite",
)

DVPL_DIR: str = "files-dvpl"

DVPL_SRC_DIR = pytest.mark.datafiles(
    FIXTURE_DIR / DVPL_DIR,
    keep_top_dir=True,
)


OPEN_OR_DVPL_FILES = pytest.mark.datafiles(
    FIXTURE_DIR / "01_source.txt",
    FIXTURE_DIR / "02_source.bin",
    FIXTURE_DIR / "03_source.txt.dvpl",
    FIXTURE_DIR / "04_source.bin.dvpl",
    on_duplicate="overwrite",
)

VERIFY_FILES = pytest.mark.datafiles(
    FIXTURE_DIR / "05_source.txt_fails_marker.dvpl",
    FIXTURE_DIR / "06_source.bin_fails_marker.dvpl",
    FIXTURE_DIR / "07_source.txt_fails_compression.dvpl",
    FIXTURE_DIR / "08_source.bin_fails_compression.dvpl",
    FIXTURE_DIR / "09_source.txt_fails_crc.dvpl",
    FIXTURE_DIR / "10_source.bin_fails_crc.dvpl",
    FIXTURE_DIR / "11_source.txt_fails_encoded_size.dvpl",
    FIXTURE_DIR / "12_source.bin_fails_encoded_size.dvpl",
    FIXTURE_DIR / "13_source.txt_fails_decoded_size.dvpl",
    FIXTURE_DIR / "14_source.bin_fails_decoded_size.dvpl",
    on_duplicate="overwrite",
)


async def files_sha256(base: Path) -> dict[Path, str]:
    fileQ = FileQueue(base, case_sensitive=False)
    await fileQ.mk_queue([Path(".")])
    hashdict: Dict[Path, str] = dict()
    async for fn in fileQ:
        with open(fn, mode="rb") as file:
            hashdict[fn.relative_to(base)] = sha256(file.read()).hexdigest()
    return hashdict


def pytest_configure(config: Config):
    plugin = config.pluginmanager.getplugin("mypy")
    if plugin is not None:
        plugin.mypy_argv.append("--check-untyped-defs")


@pytest.fixture
def test_source_data_0() -> bytes:
    return bytes(
        b"1234567890testsequence1234567890testsequence1234567890testsequence1234567890testsequence1234567890testsequence"
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


@pytest.mark.parametrize(
    "args",
    [(["verify", str((FIXTURE_DIR / DVPL_DIR).resolve())])],
)
@DVPL_SRC_DIR
def test_5_verify_tree(tmp_path: Path, datafiles: Path, args: List[str]) -> None:
    """
    test decoding a directory
    """

    result: ClickResult = CliRunner().invoke(app, args)

    assert result.exit_code == 0, "dvplc verify failed"


@SOURCE_SRC_DIR
def test_6_encode_mirror(tmp_path: Path, datafiles: Path) -> None:
    """
    test decoding a directory
    """
    DST_DIR: Path = tmp_path / "__MIRROR_DST__"

    src_dir: Path = next(datafiles.iterdir())
    if not src_dir.is_dir():
        src_dir = src_dir.parent

    chk_sums_org: Dict[Path, str] = run(files_sha256(src_dir))

    args: List[str] = [
        "--verbose",
        "encode",
        "--mirror-from",
        str(src_dir),
        "--mirror-to",
        str(DST_DIR),
        ".",
    ]
    result: ClickResult
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, "dvplc encode failed"

    args = [
        "--verbose",
        "decode",
        "--replace",
        str(DST_DIR),
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, "dvplc encode failed"

    chk_sums_res: Dict[Path, str] = run(files_sha256(DST_DIR))

    assert set(chk_sums_org.keys()) == set(
        chk_sums_res.keys()
    ), f"all files were not processed: {len(chk_sums_org)} != {len(chk_sums_res)}"

    for fn, chksum in chk_sums_res.items():
        debug("%s: %s", fn, chksum)
        assert (
            chk_sums_org[fn] == chksum
        ), f"encode-decode checksum does not match: {fn}: {chksum}"

    rmtree(DST_DIR)  # Dangerous


@DVPL_SRC_DIR
def test_7_decode_mirror(tmp_path: Path, datafiles: Path) -> None:
    """
    test decoding a directory
    """
    DST_DIR: Path = tmp_path / "__MIRROR_DST__"

    args: List[str]
    args = [
        "--verbose",
        "decode",
        "--mirror-from",
        str((tmp_path / DVPL_DIR).resolve()),
        "--mirror-to",
        str(DST_DIR),
        ".",
    ]

    result: ClickResult
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, "dvplc decode failed"

    args = [
        "--verbose",
        "encode",
        "--replace",
        str(DST_DIR),
    ]

    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, "dvplc encode failed"

    rmtree(DST_DIR)  # Dangerous


@pytest.mark.asyncio
@OPEN_OR_DVPL_FILES
async def test_8_open_dvpl_or_file(datafiles: Path) -> None:
    for filename in datafiles.iterdir():
        debug(f"opening '{filename}'")
        assert (
            _ := await open_dvpl_or_file(filename)
        ).is_ok, f"could not open file: {filename}"
        if filename.suffix == ".dvpl":
            debug(f"opening  '{filename}' without suffix")
            assert (
                _ := await open_dvpl_or_file(filename.with_suffix(""))
            ).is_ok, f"could not open file: {filename} without .dvpl suffix"
