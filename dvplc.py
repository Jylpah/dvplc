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

from secretstorage import ItemNotFoundException

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
DVPL_FOOTER_LEN = 20

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


async def decode_dvpl_file(dvpl_fn: str, output_fn: str, force: bool = False) -> str:
	"""Encode a source file to a DVPL file"""
	try:
		if not os.path.isfile(dvpl_fn):
			logger.error('Source file not found: ' + dvpl_fn)
			return 'Source file not found'	
		if not dvpl_fn.lower.endswith('.dvpl'):
			logger.info('Source file is not a DVPL file: ' + dvpl_fn)
			return 'Source file is a DVPL file'		
		if output_fn.lower.endswith('.dvpl'):
			logger.info('Output file is a DVPL file: ' + output_fn)
			return 'Output file is a DVPL file'
		if os.path.isfile(output_fn) and not force:
			logger.warning(output_fn + ' file exists, use --force to overwrite')
			return 'Dencoded file exists'

		output = bytearray()

		## Read encoded DVPL file
		async with aiofiles.open(dvpl_fn, mode='rb') as ifp:			 
			output = await decode_dvpl(await ifp.read())		
		
		## Write decoded file
		if output == None:
			return 'Error decoding data'
		async with aiofiles.open(output_fn, mode='wb') as ofp:			
			await ofp.write(output)

		return None
	except asyncio.CancelledError as err:
		return 'Cancelled'
	except Exception as err:
		error(str(err))
		return 'Error encoding file'


async def decode_dvpl(input: bytearray) -> bytearray:
	"""Decode a DVPL bytearray"""
	try:
		footer = read_dvpl_footer(input)

		d_size 		= footer['d_size']  # decoded (output) size
		t_type 		= footer['e_type']	# encoding type
		e_crc 		= footer['e_crc']	# CRC32 of endocoded (input) data
		e_length	= footer['e_size']	# encoded (input) size

		input = input[:-DVPL_FOOTER_LEN]
		if e_length != len(input):
			raise EncodingWarning('Encoded DVPL data size differs DVPL footer info')
		if e_crc != zlib.crc32(bytes(input)):
			raise EncodingWarning('Encoded DVPL data CRC32 differs DVPL footer checksum')
		
		output = bytearray()
		
		if t_type == 'none':
			output = input
		elif t_type == 'lz4' or t_type == 'lz4_hc':
			output = lz4.block.decompress(input, uncompressed_size = d_size, return_bytearray=True)
		elif t_type == 'rfc1951':
			raise NotImplementedError('RFC1951 encoding is not supported')
			return None
		
		if len(output) != d_size:
			raise EncodingWarning('Decoded data size differs from DVPL footer into')
		
		return output
	
	except Exception as err:
		error(str(err))
		raise err
	return None


async def encode_dvpl_file(input_fn: str, dvpl_fn: str, compression: str = COMPRESSION, force: bool = False) -> str:
	"""Encode a source file to a DVPL file"""
	try:
		if not os.path.isfile(input_fn):
			logger.error('Source file not found: ' + input_fn)
			return 'Source file not found'	
		if input_fn.lower.endswith('.dvpl'):
			logger.info('Source file is a DVPL file: ' + input_fn)
			return 'Source file is a DVPL file'
		if not dvpl_fn.lower.endswith('.dvpl'):
			logger.info('Output file is not a DVPL file: ' + input_fn)
			return 'Output file is not a DVPL file'
		if os.path.isfile(dvpl_fn) and not force:
			logger.warning(dvpl_fn + ' file exists, use --force to overwrite')
			return 'Encoded DVPL file exists'
		
		# read source file
		output = bytearray()
		async with aiofiles.open(input_fn, mode='rb') as ifp:			 
			output = await encode_dvpl(await ifp.read(), compression)		
		
		## Write dvpl file
		if output == None:
			return 'Error encoding data'
		async with aiofiles.open(dvpl_fn, mode='wb') as ofp:			
			await ofp.write(output)

		return None
	except asyncio.CancelledError as err:
		return 'Cancelled'
	except Exception as err:
		error(str(err))
		return 'Error encoding file'


async def encode_dvpl(input: bytearray, compression: str) -> bytearray:
	try:
		i_size = len(input)
		if compression == 'lz4':
			output = lz4.block.compress(input, mode='default', return_bytearray=True)
		elif compression == 'lz4_hc':
			output = lz4.block.compress(input, mode='high_compression', return_bytearray=True)
		elif compression == 'none':
			output = bytearray(input)
		elif compression == 'rfc1951':
			raise Exception('RFC1951 compression is not supported')
		return append_dvpl_footer(output, i_size, compression)
	except Exception as err:
		error(str(err))
		return None, None


def append_dvpl_footer(encoded: bytearray, i_size: int, compression: str) -> tuple:
	"""Append DVPL footer to the encoded (compressed) bytearray and return the whole bytearray"""	
	encoded.append(toUInt32LE(i_size))							# input size as UInt32LE
	encoded.append(toUInt32LE(len(encoded)))					# output size as UInt32LE
	encoded.append(zlib.crc32(bytes(encoded)))					# outout crc32 as UInt32LE
	encoded.append(toUInt32LE(COMPRESSION_TYPE[compression]))  	# output type as UInt32LE
	encoded.append(DVPL_MARKER.encode(encoding='utf-8', errors='strict'))
	
	return encoded


def read_dvpl_footer(data: bytes) -> dict():
	"""Read and check 20 byte DVPL footer"""
	result = dict()
	try:
		if len(data) < DVPL_FOOTER_LEN:
			raise EncodingWarning('Data is too short')

		footer = data[-DVPL_FOOTER_LEN:]
		result['marker'] = str(footer[-4:], encoding='utf-8', errors='strict')
		if result['marker'] != DVPL_MARKER:
			raise EncodingWarning("File is missig 'DVPL' marker in the end of the file.")
		result['d_size'] 	= fromUInt32LE(footer[:4])			# decoded size
		result['e_size'] 	= fromUInt32LE(footer[4:8])			# encoded size
		result['e_crc'] 	= fromUInt32LE(footer[8:12])		# encoded CRC32
		result['e_type'] 	= COMPRESSIONS[fromUInt32LE(footer[12:16])]  # encoding type
		
		return result
	except Exception as err:
		raise err


def toUInt32LE(value: int) -> bytes:
	"""Convert an integer to 32-bit unsigned integer in Little-Endian byte-order"""
	return value.to_bytes(4,byteorder='little', signed=False)


def fromUInt32LE(data: bytes) -> int:
	"""Convert a 32-bit unsigned integer in Little-Endian byte-order to integer"""
	return int.from_bytes(data, byteorder='little', signed=False)


### main()
if __name__ == "__main__":
   #asyncio.run(main(sys.argv[1:]), debug=True)
   asyncio.run(main(sys.argv[1:]))