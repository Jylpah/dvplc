#!/usr/bin/env python3

# Script convert Dava game engine's SmartDLC DVPL files

from genericpath import isdir
import logging
import argparse
from os import cpu_count, sep, remove, getcwd, makedirs, path
import sys
import re
from pathlib import Path
import asyncio
import aiofiles
import aioconsole
import lz4.block
import zlib
from blitzutils.filequeue import FileQueue

logging.basicConfig(encoding='utf-8', format='%(levelname)s: %(message)s', level=logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)
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
CONVERSIONS		= [ 'keep', 'replace', 'mirror']
QUEUE_LEN 		= 1000
THREADS 		= 5
if cpu_count() != None:
	THREADS = cpu_count()

# main() -------------------------------------------------------------

async def main(argv):
	# set the directory for the script
	global logger
	cwd = getcwd()

	try:

		parser = argparse.ArgumentParser(description='Encoder/decoder for SmartDLC DVPL files')
		arggroup_verbosity = parser.add_mutually_exclusive_group()
		arggroup_verbosity.add_argument('--debug',dest='LEVEL', action='store_const', const='DEBUG',  
										help='Debug mode')
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
		arggroup_conversion.add_argument('--replace',dest='conversion', action='store_const', const='replace', 
				help='Save converted file(s) into the same dir as source file(s) and delete the source files(s)')
		arggroup_conversion.add_argument('--keep',dest='conversion', action='store_const', const='keep', 
				help='Save converted file(s) into the same dir as source file(s) (Default)')
		arggroup_conversion.add_argument('--mirror', metavar="DIR", type=str, default=None, 
				help='Mirror converted files into destination directory')

		parser.add_argument('files', metavar='FILE1 [FILE2 ...]', type=str, nargs='+', help='Files to read. Use \'-\' for STDIN')
		parser.set_defaults(LEVEL='WARNING', conversion='keep')
		args = parser.parse_args()

		logger.setLevel(args.LEVEL)
		if args.LEVEL == logging.INFO:
			logging.basicConfig(encoding='utf-8', format='%(levelname)s: %(message)s')
		if args.LEVEL == logging.DEBUG:
			logging.basicConfig(encoding='utf-8', format='%(levelname)s: %(funcName)s: %(message)s')

		if args.mirror != None:
			args.conversion = 'mirror'
			if len(args.files) != 1:
				raise argparse.ArgumentError("More than file arguments given with --mirror")
			elif not path.isdir(args.files[0]):
				raise argparse.ArgumentError("when using --mirror, file argument has to be a directory")

		logger.debug('Argumengs given: ' + str(args))

		if args.mode in ['decode', 'verify']:
				fq = FileQueue(filter="*.dvpl", maxsize=QUEUE_LEN)
		elif args.mode == 'encode':
			fq = FileQueue(filter="*.dvpl", exclude=True, maxsize=QUEUE_LEN)
		
		workers = list()

		workers.append(asyncio.create_task(fq.mk_queue(args.files)))
		for i in range(args.threads):
			workers.append(asyncio.create_task(process_files(fq, args)))
			logger.debug(f"Process thread {str(i)} started")

		logger.debug('Building file queue')
		await asyncio.wait([workers[0]])
		logger.debug('Processing files')
		await fq.join()
		logger.debug('Cancelling workers')
		for worker in workers:
			worker.cancel()	

	except Exception as err:
		logger.error(str(err))
		sys.exit(1)


async def process_files(fileQ: FileQueue, args : argparse.Namespace):
	try:
		cwd = getcwd()
		source_root = ''
		target_root = ''
		if args.conversion == 'mirror':
			assert args.mirror != None, "args.mirror is None"
			source_root = path.normpath(args.files[0]) + sep
			target_root = path.normpath(args.mirror)

		while True:
			source = await fileQ.get()
			try:				
				target = source
				result = False
				if args.conversion == 'mirror':
					target = sep.join([target_root, source.removeprefix(source_root)])
					targetdir = path.dirname(target)
					if not path.isdir(targetdir):
						logger.info(f"creating dir: {targetdir}")
						makedirs(targetdir)					
				if args.mode == 'encode':
					target = target + '.dvpl'
					result = await encode_dvpl_file(source, target, compression=args.compression, force=args.force)
				elif args.mode == 'decode':
					target = target.removesuffix('.dvpl')
					result = await decode_dvpl_file(source, target, force=args.force)
				elif args.mode == 'verify':
					result = await verify_dvpl_file(source)
				if result and args.conversion == 'replace' and args.mode != 'verify':
					logger.debug(f"Removing source file: {source}")
					remove(source)				
			except Exception as err:
				logger.error(str(err))
			finally:
				fileQ.task_done()
	
	except asyncio.CancelledError:		
		logger.debug('Worker cancelled')		
	except Exception as err:
		logger.error(str(err))
	return None


async def decode_dvpl_file(dvpl_fn: str, output_fn: str, force: bool = False) -> bool:
	"""Encode a source file to a DVPL file"""
	
	assert dvpl_fn != None, f"DVPL file name is None"	
	assert output_fn != None, f"output file name is None"
	assert force != None, f"--force value is None"

	try:
		if not path.isfile(dvpl_fn):
			raise FileNotFoundError('Source file not found: ' + dvpl_fn)
		if not dvpl_fn.lower().endswith('.dvpl'):
			raise ValueError('Source file is not a DVPL file: ' + dvpl_fn)
		if output_fn.lower().endswith('.dvpl'):	
			raise ValueError('Output file is a DVPL file: ' + output_fn)
		if path.isfile(output_fn) and not force:
			raise FileExistsError('Output file exists, use --force to overwrite ' + output_fn)

		## Read encoded DVPL file
		output = bytes()
		async with aiofiles.open(dvpl_fn, mode='rb') as ifp:
			logger.info(f"decoding file: {dvpl_fn}")				 
			output = await decode_dvpl(await ifp.read())	
		
		## Write decoded file
		if output == None:
			return EncodingWarning('Error decoding data')
		async with aiofiles.open(output_fn, mode='wb') as ofp:
			logger.debug(f"writing to file: {output_fn}")	
			await ofp.write(output)

		return True
	except asyncio.CancelledError as err:
		logger.info('Cancelled')		
	except Exception as err:
		logger.error(str(err))		
	return False


async def decode_dvpl(input: bytes, quiet: bool = False) -> bytes:
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
		else:
			logger.debug(f"Encoded CRC matches {hex(e_crc)}")
		
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
		if not quiet:
			logger.error('LZ4 decoding error: ' + str(err))
	except Exception as err:
		if not quiet:
			logger.error(str(err))
	return None


async def encode_dvpl_file(input_fn: str, dvpl_fn: str, compression: str = COMPRESSION, force: bool = False) -> bool:
	"""Encode a source file to a DVPL file"""

	assert input_fn != None, f"input file name is None"
	assert dvpl_fn != None, f"DVPL file name is None"
	assert compression in COMPRESSIONS, f"Unknown compression: {compression}"
	assert force != None, f"--force is None"
	
	try:
		if not path.isfile(input_fn):
			raise FileNotFoundError('Source file not found: ' + input_fn)
		if input_fn.lower().endswith('.dvpl'):
			raise ValueError('Source file is a DVPL file: ' + input_fn)
		if not dvpl_fn.lower().endswith('.dvpl'):
			raise ValueError('Output file is not a DVPL file: ' + input_fn)
		if path.isfile(dvpl_fn) and not force:
			raise FileExistsError('Output file exists, use --force to overwrite: ' + dvpl_fn)
		
		# read source file
		output = bytes()
		async with aiofiles.open(input_fn, mode='rb') as ifp:
			logger.info(f"encoding file: {input_fn}")
			output = await encode_dvpl(await ifp.read(), compression)
		
		## Write dvpl file
		if output == None:
			raise EncodingWarning('Error encoding data')
		async with aiofiles.open(dvpl_fn, mode='wb') as ofp:
			logger.debug(f"writing to file: {dvpl_fn}")	
			await ofp.write(output)

		return True
	except asyncio.CancelledError as err:
		logger.info('Cancelled')		
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
		if not path.isfile(dvpl_fn):
			raise FileNotFoundError('Source file not found: ' + dvpl_fn)
		if not dvpl_fn.lower().endswith('.dvpl'):
			raise ValueError('Source file is not a DVPL file: ' + dvpl_fn)
		
		## Try to decode a DVPL file
		async with aiofiles.open(dvpl_fn, mode='rb') as ifp:
			logger.debug(f"reading file: {dvpl_fn}")
			ret = await decode_dvpl(await ifp.read(), quiet=True)	
		if ret != None:
			logger.info(dvpl_fn + ': OK')
		else:
			print(dvpl_fn + ': ERROR')
		return True
	except asyncio.CancelledError as err:
		logger.info('Cancelled')
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