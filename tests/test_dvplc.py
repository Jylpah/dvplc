import sys
import pytest  # type: ignore
from pytest import Config
from asyncio.log import logger
from os.path import dirname, realpath, join as pjoin
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.resolve() / "src"))

from dvplc import (
    COMPRESSION,
    encode_dvpl,
    decode_dvpl,
    encode_dvpl_file,
    verify_dvpl_file,
    decode_dvpl_file,
)

## Test plan
# 1) mypy static typing
# 2) test encoding
# 3) test verify
# 4) test decoding

FIXTURE_DIR = dirname(realpath(__file__))


def pytest_configure(config: Config):
    plugin = config.pluginmanager.getplugin("mypy")
    if plugin is not None:
        plugin.mypy_argv.append("--check-untyped-defs")


@pytest.fixture
def test_source_data_0() -> bytes:
    return bytes(b"1234567890")


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


@pytest.mark.asyncio
async def test_0_dvpl_encode_decode_passes(test_source_data_0: bytes) -> None:
    res_encode, txt = encode_dvpl(
        input=test_source_data_0, compression=COMPRESSION, quiet=True
    )
    assert txt == "OK"
    assert res_encode is not None, "encoding failed"
    res_decode, txt = decode_dvpl(res_encode, quiet=True)
    assert txt == "OK"
    assert res_decode == test_source_data_0


@pytest.mark.asyncio
@pytest.mark.datafiles(
    pjoin(FIXTURE_DIR, "01_source.txt"), pjoin(FIXTURE_DIR, "02_source.bin")
)
async def test_1_encode_file_passes(datafiles: Path) -> None:
    for input in datafiles.iterdir():
        output = input.with_suffix(".dvpl")
        print(f"Input: {input}, Output: {output}")
        assert await encode_dvpl_file(input, output), f"encoding failed: {input}"
        assert await verify_dvpl_file(output), f"dvpl verification failed: {output}"


@pytest.mark.asyncio
@pytest.mark.datafiles(
    pjoin(FIXTURE_DIR, "03_source.txt.dvpl"), pjoin(FIXTURE_DIR, "04_source.bin.dvpl")
)
async def test_2_decode_file_passes(datafiles: Path) -> None:
    for input in datafiles.iterdir():
        output = input.with_suffix("")
        print(f"Input: {input}, Output: {output}")
        assert await verify_dvpl_file(input), f"dvpl verification failed: {input}"
        assert await decode_dvpl_file(input, output), f"decoding failed: {input}"


@pytest.mark.asyncio
@pytest.mark.datafiles(
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
)
async def test_3_verify_file_fails(datafiles: Path) -> None:
    for input in datafiles.iterdir():
        print(f"Input: {input}")
        assert not await verify_dvpl_file(
            input
        ), f"dvpl verification failed (false positive): {input}"
