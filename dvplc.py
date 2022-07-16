#!/usr/bin/env python3

# Script convert Dava game engine's SmartDLC DVPL files

from logging import critical, error, warning, debug, info 
import logging
import argparse
import os
import sys
import re
from pathlib import Path
import asyncio
import aiofiles
import aioconsole
from bson import encode
import lz4.block
import zlib

logging.basicConfig(encoding='utf-8', format='%(levelname)s:%(message)s', level=logging.DEBUG)
logging.getLogger("asyncio").setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)

# Constants & defaults
COMPRESSION 	= 'lz4_hc'
COMPRESSIONS 	= [ 'none', 'lz4', 'lz4_hc', 'rfc1951' ]
COMPRESSION_TYPE= dict()
for i in range(0, len(COMPRESSIONS)):
	COMPRESSION_TYPE[COMPRESSIONS[i]] = i
DVPL_MARKER = b'DVPL'

# main() -------------------------------------------------------------

async def main(argv):
	# set the directory for the script
	cwd = os.getcwd()
	global logger

	# Default params
	THREADS = 20


	parser = argparse.ArgumentParser(description='Encoder/decoder for SmartDLC DVPL files')
	arggroup_verbosity = parser.add_mutually_exclusive_group()
	arggroup_verbosity.add_argument('--debug',dest='LEVEL', action='store_const', const='DEBUG',  
									help='Debug mode')
	arggroup_verbosity.add_argument('--warning', dest='LEVEL', action='store_const', const='WARNING', default='WARNING',
									help='Default verbosity (warning)')
	arggroup_verbosity.add_argument('--verbose', dest='LEVEL', action='store_const', const='INFO',
									help='Verbose mode')
	arggroup_verbosity.add_argument('--silent', dest='LEVEL', action='store_const', const='CRITICAL',
									help='Silent mode')
	parser.add_argument('--force', action='store_true', default=False, help='Overwrite files')
	parser.add_argument('--threads', type=int, default=THREADS, 
						help='Set number of asynchronous threads. Default is automatic.')
	parser.add_argument('--compression', type=str, choices=COMPRESSIONS, 
						default=COMPRESSION, help='Select compression to use when encoding')
	parser.add_argument('mode', type=str, choices=['encode', 'decode', 'auto'], 
						default='auto', help="Choose encode/decode mode. Default is 'auto' that chooses the mode based on the first file found")
	parser.add_argument('files', metavar='FILE1 [FILE2 ...]', type=str, nargs='*', help='Files to read. Use \'-\' for STDIN')
	
	parser.set_defaults(LEVEL='WARNING')
	args = parser.parse_args()
	logger.setLevel(args.LEVEL)

	debug('Argumengs given: ' + str(args))

	if args.mode == 'encode':
		pass
	elif args.mode == 'decode':
		pass
	else:
		critical('Invalid mode given: ' + args.mode)
		sys.exit(1)


async def iterate_files(mode: str, cwd: str, files: list(str), options: argparse.Namespace):
	pass

async def decodeDVPL(dvpl_fn: str, output_fn: str= None, compression: str = None, force: bool = False) -> bool:
	"""Decode a DVPL file"""
	
	
	pass


async def encodeDVPL(input_fn: str, dvpl_fn: str= None, compression: str = COMPRESSION, force: bool = False) -> str:
	"""Encode a source file to a DVPL file"""
	try:
		if not os.path.isfile(input_fn):
			logger.error('Source file not found: ' + input_fn)
			return 'Source file not found'	
		if input_fn.lower.endswith('.dvpl'):
			logger.info('Source file is a DVPL file: ' + input_fn)
			return 'Source file is a DVPL file'		
		if os.path.isfile(input_fn + '.dvpl') and not force:
			logger.warning(input_fn + '.dvpl file exists, use --force to overwrite')
			return 'Encoded DVPL file exists'

		input = bytearray()
		output = bytearray()
		i_size = 0
		async with aiofiles.open(input_fn, mode='r', encoding="utf-8") as ifp:				
			input 	= await ifp.read()
			i_size 	= len(input)
			if compression == 'lz4':
				output = lz4.block.compress(input, mode='default', return_bytearray=True)
			elif compression == 'lz4_hc':
				output = lz4.block.compress(input, mode='high_compression', return_bytearray=True)
			elif compression == 'none':
				output = bytearray(input)
			elif compression == 'rfc1951':
				raise Exception('RFC1951 compression is not supported')
		
		## Write dvpl file
		async with aiofiles.open(input_fn + '.dvpl', mode='wb') as ofp:
			await ofp.write(append_dvpl_footer(output, i_size, compression))

		return True
	except asyncio.CancelledError as err:
		return False
	except Exception as err:
		error(str(err))
		return False


def append_dvpl_footer(encoded: bytearray, i_size: int, compression: str) -> bytes:
	"""Append DVPL footer to the encoded (compressed) bytearray and return bytes"""
	
	encoded.append(toUInt32LE(i_size))							# input size as UInt32LE
	encoded.append(toUInt32LE(len(encoded)))					# output size as UInt32LE
	encoded.append(zlib.crc32(bytes(encoded)))					# outout crc32 as UInt32LE
	encoded.append(toUInt32LE(COMPRESSION_TYPE[compression]))  	# output type as UInt32LE
	encoded.append(DVPL_MARKER.encode(encoding='utf-8', errors='strict'))
	
	return bytes(encoded)


def read_dvpl_footer(data: bytes) -> dict():
	"""Read and check 20 byte DVPL footer"""
	result = dict()
	try:
		footer = data[-20:]
		result['marker'] = str(data[-4:], encoding='utf-8', errors='strict')
		if result['marker'] != DVPL_MARKER:
			raise EncodingWarning("File is missig 'DVPL' marker in the end of the file.")
		result['i_size'] 	= fromUInt32LE(footer[:4])
		result['o_length'] 	= fromUInt32LE(footer[4:8])
		result['o_crc'] 	= fromUInt32LE(footer[8:12])
		result['o_type'] 	= fromUInt32LE(footer[12:16])
		
		return result
	except Exception as err:
		error(str(type(err)) + ' : '+ str(err))
		return None


def toUInt32LE(value: int) -> bytes:
	"""Convert an integer to 32-bit unsigned integer in Little-Endian byte-order"""
	return value.to_bytes(4,byteorder='little', signed=False)


def fromUInt32LE(data: bytes) -> int:
	"""Convert a 32-bit unsigned integer in Little-Endian byte-order to integer"""
	return int.from_bytes(data, byteorder='little', signed=False)


async def encodeDVPLlz4(source_fn: str, dvpl_fn: str= None, level: int = lz4.frame.COMPRESSIONLEVEL_MIN, force: bool = False) -> bool:
	try: 
		async with aiofiles.open(source_fn) as fp:
			source_size = Path(source_fn).stat().st_size
			c_ctx = lz4.frame.create_compression_context()


			data = await fp.read()  # does not handle very large files
			

	except asyncio.CancelledError as err:
		raise err
	except Exception as err:
		error('Unexpected error: ' + str(type(err)) + ' : '+ str(err))
	
	pass



### main()
if __name__ == "__main__":
   #asyncio.run(main(sys.argv[1:]), debug=True)
   asyncio.run(main(sys.argv[1:]))