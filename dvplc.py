#!/usr/bin/env python3

# Script convert Dava game engine's SmartDLC DVPL files

import logging
import argparse
import os
from shutil import ExecError
import sys
import re
from pathlib import Path
import asyncio
import aiofiles
import aioconsole
from bson import encode
from colorama import Fore
import lz4.block
import zlib

from secretstorage import ItemNotFoundException

logging.basicConfig(encoding='utf-8', format='%(levelname)s:%(funcName)s:%(message)s', level=logging.DEBUG)
logging.getLogger("asyncio").setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)

# Constants & defaults
MODES			= ['encode', 'decode', 'verify']
COMPRESSION 	= 'lz4_hc'
COMPRESSIONS 	= [ 'none', 'lz4', 'lz4_hc', 'rfc1951' ]
COMPRESSION_TYPE= dict()
for i in range(0, len(COMPRESSIONS)):
	COMPRESSION_TYPE[COMPRESSIONS[i]] = i
DVPL_MARKER 	= 'DVPL'
DVPL_FOOTER_LEN = 20
CONVERSIONS		= [ 'keep', 'replace', 'dest_dir']
QUEUE_LEN 		= 1000

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
	parser.add_argument('mode', type=str, choices=MODES, metavar='encode | decode | verify', help="Choose encode/decode mode.")

	arggroup_conversion = parser.add_mutually_exclusive_group()
	arggroup_conversion.add_argument('--replace',dest='CONVERSION', action='store_const', const='replace', 
			help='Save converted file(s) into the same dir as source file(s) and delete the source files(s)')
	arggroup_conversion.add_argument('--keep',dest='CONVERSION', action='store_const', const='keep', 
			help='Save converted file(s) into the same dir as source file(s)')
	arggroup_conversion.add_argument('--destination',type=str, nargs=1, default=None, 
			help='Save the converted files under destination directory')

	parser.add_argument('--conversion', type=str, choices=CONVERSIONS, metavar='encode | decode | verify', help="Choose encode/decode mode.")
	
	parser.add_argument('files', metavar='FILE1 [FILE2 ...]', type=str, nargs=1, help='Files to read. Use \'-\' for STDIN')
	
	parser.set_defaults(LEVEL='WARNING', CONVERSION='keep')
	args = parser.parse_args()
	logger.setLevel(args.LEVEL)
	if args.destination != None:
		args.CONVERSION = 'dest_dir'

	logger.debug('Argumengs given: ' + str(args))

	await process_files(args.mode, os.getcwd(), args)

	if args.mode == 'encode':
		await encode_dvpl_file(args.files[0], args.files[0] + '.dvpl', args.compression, force=args.force)
	elif args.mode == 'decode':
		await decode_dvpl_file(args.files[0], args.files[0].removesuffix('.dvpl'), force=args.force)
	elif args.mode == 'verify':
		await verify_dvpl_file(args.files[0])
	else:
		logger.critical('Invalid mode given: ' + args.mode)
		sys.exit(1)


async def process_files(mode: str, cwd: str, args: argparse.Namespace):
	"""Process files"""
	
	assert mode != None, "Mode is None"
	assert mode in MODES, f"Unknown mode given: {mode}"
	assert cwd != None, "Working directory is None"
	assert args != None, "Arguments given is None"
	assert args.files != None and len(args.files) > 0, "No files given to process"
	assert args.CONVERSION in CONVERSIONS, f"Unknown conversion mode: {args.CONVERSION}"
	
	try:
		queue  = asyncio.Queue(QUEUE_LEN)



	except Exception as err:
		logger.error(str(err))


async def mk_file_queue(queue : asyncio.Queue, arg_files: list, suffixes: list = None):
	"""Create queue of files to process"""

	assert suffixes == None or isinstance(suffixes, list), f"suffixes has to be None or list or strings"

	try:
		if arg_files[0] == '-':
			logger.debug('Reading file list from STDIN')
			stdin, _ = await aioconsole.get_standard_streams()
			while True:
				fn = os.path.normpath((await stdin.readline()).decode('utf-8').rstrip())
				if not fn: 
					break
				else:
					if suffixes != None (p_replayfile.match(line) != None):
						await queue.put(line)
		else:
			for fn in files:
				if fn.endswith('"'):
					fn = fn[:-1]  
				if os.path.isfile(fn) and (p_replayfile.match(fn) != None):
					await queue.put(await mkQueueItem(fn, title))
					bu.debug('File added to queue: ' + fn)
				elif os.path.isdir(fn):
					with os.scandir(fn) as dirEntry:
						for entry in dirEntry:
							try:
								bu.debug('Found: ' + entry.name)
								if entry.is_file() and (p_replayfile.match(entry.name) != None): 
									bu.debug(entry.name)
									await queue.put(await mkQueueItem(entry.path, title))
									bu.debug('File added to queue: ' + entry.path)
							except Exception as err:
								bu.error(str(err))
				else:
					bu.error('File not found: ' + fn)
				
		bu.debug('Finished')
		return None		
	
	except Exception as err:
		logger.error(str(err))

def match_suffix(filename: str, suffixes: list) -> bool:
	""""Match file name with list of suffixes"""
	return None

async def decode_dvpl_file(dvpl_fn: str, output_fn: str, force: bool = False) -> bool:
	"""Encode a source file to a DVPL file"""
	
	assert dvpl_fn != None, f"DVPL file name is None"	
	assert output_fn != None, f"output file name is None"
	assert force != None, f"--force value is None"

	try:
		if not os.path.isfile(dvpl_fn):
			raise FileNotFoundError('Source file not found: ' + dvpl_fn)
		if not dvpl_fn.lower().endswith('.dvpl'):
			raise ValueError('Source file is not a DVPL file: ' + dvpl_fn)
		if output_fn.lower().endswith('.dvpl'):	
			raise ValueError('Output file is a DVPL file: ' + output_fn)
		if os.path.isfile(output_fn) and not force:
			raise FileExistsError('Output file exists, use --force to overwrite ' + output_fn)

		## Read encoded DVPL file
		output = bytes()
		async with aiofiles.open(dvpl_fn, mode='rb') as ifp:			 
			output = await decode_dvpl(await ifp.read())	
		
		## Write decoded file
		if output == None:
			return EncodingWarning('Error decoding data')
		async with aiofiles.open(output_fn, mode='wb') as ofp:			
			await ofp.write(output)

		return True
	except asyncio.CancelledError as err:
		logger.info('Cancelled')
		return False
	except Exception as err:
		logger.error(str(err))
		return False


async def decode_dvpl(input: bytes) -> bytes:
	"""Decode a DVPL bytearray"""

	assert input != None, f"input value is None"
	assert isinstance(input, bytes), f"input needs to be bytes, got {type(input)}"

	try:		
		footer, input = read_dvpl_footer(input)

		d_size 		= footer['d_size']  # decoded (output) size
		t_type 		= footer['e_type']	# encoding type
		e_crc 		= footer['e_crc']	# CRC32 of endocoded (input) data
		e_length	= footer['e_size']	# encoded (input) size

		if e_length != len(input):
			raise EncodingWarning('Encoded DVPL data size differs DVPL footer info')
		if e_crc != zlib.crc32(input):
			raise EncodingWarning('Encoded DVPL data CRC32 differs DVPL footer checksum')
		
		output = bytes()
		
		if t_type == 'none':
			output = input
		elif t_type == 'lz4' or t_type == 'lz4_hc':
			output = lz4.block.decompress(input, uncompressed_size=d_size)
		elif t_type == 'rfc1951':
			raise NotImplementedError('RFC1951 encoding is not supported')
		if len(output) != d_size:
			raise EncodingWarning('Decoded data size differs from DVPL footer into')
		
		logger.debug('decoded CRC32: ' + hex(zlib.crc32(output)))

		assert output != None, f"Output value is None"
		assert isinstance(output, bytes), f"Output needs to be bytes, got {type(input)}"
		
		return output
	
	except lz4.block.LZ4BlockError as err:
		logger.error('LZ4 decoding error: ' + str(err))
	except Exception as err:
		logger.error(str(err))
	return None


async def encode_dvpl_file(input_fn: str, dvpl_fn: str, compression: str = COMPRESSION, force: bool = False) -> bool:
	"""Encode a source file to a DVPL file"""

	assert input_fn != None, f"input file name is None"
	assert dvpl_fn != None, f"DVPL file name is None"
	assert compression in COMPRESSIONS, f"Unknown compression: {compression}"
	assert force != None, f"--force is None"
	
	try:
		if not os.path.isfile(input_fn):
			raise FileNotFoundError('Source file not found: ' + input_fn)
		if input_fn.lower().endswith('.dvpl'):
			raise ValueError('Source file is a DVPL file: ' + input_fn)
		if not dvpl_fn.lower().endswith('.dvpl'):
			raise ValueError('Output file is not a DVPL file: ' + input_fn)
		if os.path.isfile(dvpl_fn) and not force:
			raise FileExistsError('Output file exists, use --force to overwrite: ' + dvpl_fn)
		
		# read source file
		output = bytes()
		async with aiofiles.open(input_fn, mode='rb') as ifp:			 
			output = await encode_dvpl(await ifp.read(), compression)
		
		## Write dvpl file
		if output == None:
			raise EncodingWarning('Error encoding data')
		async with aiofiles.open(dvpl_fn, mode='wb') as ofp:			
			await ofp.write(output)

		return True
	except asyncio.CancelledError as err:
		logger.info('Cancelled')
		return False
	except Exception as err:
		logger.error(str(err))
		return False


async def encode_dvpl(input: bytes, compression: str) -> bytes:
	"""Encode data to a DVPL format"""

	assert isinstance(input, bytes), f"input needs to be bytes, got {type(input)}"
	assert input != None, f"input is None"
	assert compression in COMPRESSIONS, f"Unknown compression: {compression}"

	try:
		d_size = len(input)
		if compression.startswith('lz4'):
			mode='high_compression'
			if compression == 'lz4':
				mode='default'
			output = lz4.block.compress(input, mode=mode, store_size=False)
		elif compression == 'none':
			output = input
		elif compression == 'rfc1951':
			raise NotImplementedError('RFC1951 compression is not supported')

		footer = make_dvpl_footer(output, d_size, compression)

		logger.debug('decoded CRC32: ' + hex(zlib.crc32(input)))		

		return output + footer

	except lz4.block.LZ4BlockError as err:
		logger.error('LZ4 encoding error')
	except Exception as err:		
		logger.error(str(err))	
	return None


async def verify_dvpl_file(dvpl_fn: str) -> bool:
	"""Verify a DVPL file"""

	assert dvpl_fn != None, f"input file name is None type"
	
	try:
		if not os.path.isfile(dvpl_fn):
			raise FileNotFoundError('Source file not found: ' + dvpl_fn)
		if not dvpl_fn.lower().endswith('.dvpl'):
			raise ValueError('Source file is not a DVPL file: ' + dvpl_fn)
		
		## Try to decode a DVPL file
		async with aiofiles.open(dvpl_fn, mode='rb') as ifp:			 
			_ = await decode_dvpl(await ifp.read())	
		print(dvpl_fn + ': OK')
		return True
	except asyncio.CancelledError as err:
		logger.info('Cancelled')
		return False
	except Exception as err:
		logger.error(str(err))
		return False

def make_dvpl_footer(encoded: bytes, d_size: int, compression: str) -> bytes:
	"""Make a 20-byte DVPL footer"""

	assert isinstance(encoded, bytes), f"input needs to be bytes, got {type(encoded)}"
	
	assert compression in COMPRESSIONS, f"Unknown compression: {compression}"

	try:
		"""Makes DVPL footer for the encoded (compressed) input"""
		if logger.getEffectiveLevel() == logging.DEBUG:
			logger.debug('decoded size: ' + str(d_size))
			logger.debug('encoded size: ' + str(len(encoded)))
			logger.debug('encoded CRC32: ' + hex(zlib.crc32(encoded)))
			logger.debug('encoding type: ' + compression)

		footer = bytearray()
		footer += toUInt32LE(d_size)							# input size as UInt32LE
		footer += toUInt32LE(len(encoded))						# output size as UInt32LE
		footer += toUInt32LE(zlib.crc32(encoded))				# outout crc32 as UInt32LE
		footer += toUInt32LE(COMPRESSION_TYPE[compression])  	# output type as UInt32LE
		footer += DVPL_MARKER.encode(encoding='utf-8', errors='strict')
		footer = bytes(footer)

		assert len(footer) == 20, f"Footer size != 20"

		return footer
	except Exception as err:
		logger.error(str(err))
	return None


def read_dvpl_footer(data: bytes) -> tuple[dict(), bytes]:
	"""Read and check 20 byte DVPL footer"""

	assert(isinstance(data, bytes)), f"input needs to be bytes, got {type(data)}"

	result = dict()

	if len(data) < DVPL_FOOTER_LEN:
		raise EncodingWarning('Data is too short (< 20 bytes)')

	footer = data[-DVPL_FOOTER_LEN:]
	result['marker'] = str(footer[-4:], encoding='utf-8', errors='strict')
	if result['marker'] != DVPL_MARKER:
		raise EncodingWarning("File is missig 'DVPL' marker in the end of the file.")
	result['d_size'] 	= fromUInt32LE(footer[:4])			# decoded size
	result['e_size'] 	= fromUInt32LE(footer[4:8])			# encoded size
	result['e_crc'] 	= fromUInt32LE(footer[8:12])		# encoded CRC32
	result['e_type'] 	= COMPRESSIONS[fromUInt32LE(footer[12:16])]  # encoding type
	
	if logger.getEffectiveLevel() == logging.DEBUG:
		logger.debug('decoded size: ' + str(result['d_size']))
		logger.debug('encoded size: ' + str(result['e_size']))
		logger.debug('encoded CRC32: ' + hex(result['e_crc']))
		logger.debug('encoding type: ' + result['e_type'])
	
	return result, data[:-DVPL_FOOTER_LEN]


def toUInt32LE(value: int) -> bytes:	
	"""Convert an integer to 32-bit unsigned integer in Little-Endian byte-order"""
	try:
		if value == None:
			raise ValueError('None given as input')
		if value < 0:
			raise ValueError('Cannot cast negative value as unsigned int')
		return value.to_bytes(4,byteorder='little', signed=False)
	except Exception as err:
		logger.error(str(err))
	return None


def fromUInt32LE(data: bytes) -> int:
	"""Convert a 32-bit unsigned integer in Little-Endian byte-order to integer"""
	try:
		if data == None:
			raise ValueError('None given as input')		
		return int.from_bytes(data, byteorder='little', signed=False)
	except Exception as err:
		logger.error(str(err))
	return None

def error(err: Exception):
	logger.error(str(err))
	raise err

def warning(err: Exception): 
	logger.warning(str(err))
	raise err

### main()
if __name__ == "__main__":
   #asyncio.run(main(sys.argv[1:]), debug=True)
   asyncio.run(main(sys.argv[1:]))