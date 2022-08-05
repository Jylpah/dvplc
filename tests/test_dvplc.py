import pytest

from ..dvplc import COMPRESSION, encode_dvpl, decode_dvpl

#target = __import__("dvplc.py")

## Test plan
# 1) mypy static typing
# 2) test encoding
# 3) test verify 
# 4) test decoding

@pytest.fixture
def test_source_data_1() -> bytes:
	return bytes(b'1234567890')
	
@pytest.mark.asyncio
async def test_dvpl_encode_decode_passes(test_source_data_1):
	res_encode, txt = await encode_dvpl(input=test_source_data_1, compression=COMPRESSION, quiet=True)

	assert txt == "OK"

	res_decode, txt = await decode_dvpl(res_encode, quiet=True)

	assert txt == "OK"

	assert res_decode == test_source_data_1

