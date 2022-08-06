from asyncio.log import logger
import pytest

from ..dvplc import COMPRESSION, encode_dvpl, decode_dvpl

#target = __import__("dvplc.py")

## Test plan
# 1) mypy static typing
# 2) test encoding
# 3) test verify 
# 4) test decoding

@pytest.fixture
def test_source_data_0() -> bytes:
	return bytes(b'1234567890')

@pytest.fixture
def test_encode_source() -> list[str]:
	return [ '1_source.txt', '2_source.bin' ]

@pytest.fixture
def test_decode_source() -> list[str]:
	return [ '3_source.txt.dvpl', '4_source.bin.dvpl' ]

@pytest.fixture
def test_checksums() -> dict[str, str]:
	res: dict[str, str] = dict()
	try:
		with open('checksum.sha256', mode='r', encoding='utf-8') as c:
			while c:				
				line = c.readline()
				chksum = line.split()
				res[chksum[1]] = chksum[0]
	except Exception as err:
		logger.error(str(err))
	return res

	
@pytest.mark.asyncio
async def test_dvpl_encode_decode_passes(test_source_data_0):
	res_encode, txt = await encode_dvpl(input=test_source_data_0, compression=COMPRESSION, quiet=True)

	assert txt == "OK"

	res_decode, txt = await decode_dvpl(res_encode, quiet=True)

	assert txt == "OK"

	assert res_decode == test_source_data_0


@pytest.mark.asyncio
async def test_encode_file_passes():
	pass

