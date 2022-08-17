from asyncio.log import logger
import pytest, os

from ..dvplc import COMPRESSION, encode_dvpl, decode_dvpl, encode_dvpl_file, verify_dvpl_file, decode_dvpl_file  # type: ignore

## Test plan
# 1) mypy static typing
# 2) test encoding
# 3) test verify 
# 4) test decoding

@pytest.fixture
def test_source_data_0() -> bytes:
	return bytes(b'1234567890')


FIXTURE_DIR = os.path.dirname(os.path.realpath(__file__))

def pytest_configure(config):
    plugin = config.pluginmanager.getplugin('mypy')
    plugin.mypy_argv.append('--check-untyped-defs')
	

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
async def test_0_dvpl_encode_decode_passes(test_source_data_0):
	res_encode, txt = await encode_dvpl(input=test_source_data_0, compression=COMPRESSION, quiet=True)

	assert txt == "OK"

	res_decode, txt = await decode_dvpl(res_encode, quiet=True)

	assert txt == "OK"

	assert res_decode == test_source_data_0


@pytest.mark.asyncio
@pytest.mark.datafiles(
    os.path.join(FIXTURE_DIR, '01_source.txt'),
    os.path.join(FIXTURE_DIR, '02_source.bin')
    )
async def test_1_encode_file_passes(datafiles):
	for i in datafiles.listdir():
		input = str(i)
		output = input + '.dvpl'
		print(f"Input: {input}, Output: {output}")
		assert await encode_dvpl_file(input, output), f"encoding failed: {input}"
		assert await verify_dvpl_file(output), f"dvpl verification failed: {output}"


@pytest.mark.asyncio
@pytest.mark.datafiles(
    os.path.join(FIXTURE_DIR, '03_source.txt.dvpl'),
    os.path.join(FIXTURE_DIR, '04_source.bin.dvpl')
    )
async def test_2_decode_file_passes(datafiles):
	for i in datafiles.listdir():
		input = str(i)
		output = input.removesuffix('.dvpl')
		print(f"Input: {input}, Output: {output}")
		assert await verify_dvpl_file(input), f"dvpl verification failed: {input}"
		assert await decode_dvpl_file(input, output), f"decoding failed: {input}"
		

@pytest.mark.asyncio
@pytest.mark.datafiles(    
	os.path.join(FIXTURE_DIR, '05_source.txt_fails_marker.dvpl'),
	os.path.join(FIXTURE_DIR, '06_source.bin_fails_marker.dvpl'),
	os.path.join(FIXTURE_DIR, '07_source.txt_fails_compression.dvpl'),
	os.path.join(FIXTURE_DIR, '08_source.bin_fails_compression.dvpl'),
	os.path.join(FIXTURE_DIR, '09_source.txt_fails_crc.dvpl'),
	os.path.join(FIXTURE_DIR, '10_source.bin_fails_crc.dvpl'),
	os.path.join(FIXTURE_DIR, '11_source.txt_fails_encoded_size.dvpl'),
	os.path.join(FIXTURE_DIR, '12_source.bin_fails_encoded_size.dvpl'),
	os.path.join(FIXTURE_DIR, '13_source.txt_fails_decoded_size.dvpl'),
	os.path.join(FIXTURE_DIR, '14_source.bin_fails_decoded_size.dvpl')
    )
async def test_3_verify_file_fails(datafiles):
	for i in datafiles.listdir():
		input = str(i)
		print(f"Input: {input}")
		assert not await verify_dvpl_file(input), f"dvpl verification failed (false positive): {input}"
		