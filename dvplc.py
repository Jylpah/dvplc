#!/usr/bin/env python3

# Script convert Dava game engine's SmartDLC DVPL files

from typing import Optional, Union, Dict
import logging
import argparse
from os import cpu_count, sep, remove, getcwd, makedirs, path
import sys
import re
import asyncio
import aiofiles
import aioconsole
import lz4.block
import zlib
from blitzutils.filequeue import FileQueue
from blitzutils.eventlogger import EventLogger

logging.basicConfig(encoding='utf-8', format='%(levelname)s: %(funcName)s: %(message)s', level=logging.WARNING)
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
#cpus = cpu_count()
#if cpus is not None:
#	THREADS = cpus

# main() -------------------------------------------------------------

async def main(argv: list[str]):
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
		arggroup_conversion.add_argument('--keep',dest='conversion', action='store_const', const='keep', 
				help='Save converted file(s) into the same dir as source file(s) (Default)')
		arggroup_conversion.add_argument('--replace',dest='conversion', action='store_const', const='replace', 
				help='Delete source files after successful conversion')		
		arggroup_conversion.add_argument('--mirror', metavar="DIR", type=str, default=None, 
				help='Mirror converted files under DIR')

		parser.add_argument('files', metavar='FILE1 [FILE2 ...]', type=str, nargs='+', help='Files to read. Use \'-\' for STDIN')
		parser.set_defaults(LEVEL='WARNING', conversion='keep')
		args = parser.parse_args()

		if args.LEVEL == logging.INFO:
			logging.basicConfig(encoding='utf-8', format='%(levelname)s: %(message)s')
		if args.LEVEL == logging.DEBUG:
			logging.basicConfig(encoding='utf-8', format='%(levelname)s: %(funcName)s: %(message)s')
		logger.setLevel(args.LEVEL)

		if args.mirror is not None:
			args.conversion = 'mirror'
			if len(args.files) != 1:
				raise argparse.ArgumentError(argument=args.mirror, message="More than one file argument given")
		## is this needed?
			elif not path.isdir(args.files[0]):
				raise argparse.ArgumentError(argument=args.mirror, message="File argument has to be a directory")

		logger.debug('Argumengs given: ' + str(args))

		if args.mode in ['decode', 'verify']:
				fq = FileQueue(filter="*.dvpl", maxsize=QUEUE_LEN)
		elif args.mode == 'encode':
			fq = FileQueue(filter="*.dvpl", exclude=True, maxsize=QUEUE_LEN)
		
		workers = list()
		logger.debug(f"file queue is {str(fq.qsize())} long")
		scanner = asyncio.create_task(fq.mk_queue(args.files))
		for i in range(args.threads):
			workers.append(asyncio.create_task(process_files(fq, args)))
			logger.debug(f"Process thread {str(i)} started")

		logger.debug('Building file queue')
		await asyncio.wait([scanner])
		logger.debug('Processing files')
		await fq.join()
		# await fq.get_stats()
		logger.debug('Cancelling workers')
		for worker in workers:
			worker.cancel()	

	except Exception as err:
		logger.error(str(err))
		sys.exit(1)


async def process_files(fileQ: FileQueue, args : argparse.Namespace) -> EventLogger:
	try:
		assert fileQ is not None and args is not None, "parameters must not be None"
		action : dict[str, str] = { 'encode': 'encoding', 'decode': 'decoding', 'verify': 'verification' }
		source_root: str = ''
		target_root: str = ''
		el = EventLogger('Files processed')
		if args.conversion == 'mirror':
			assert args.mirror is not None, "args.mirror is None"
			source_root = path.normpath(args.files[0]) + sep
			target_root = path.normpath(args.mirror)
		while True:
			source = await fileQ.get()
			el.log('Files read')
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
					el.log('Files encoded')
				elif args.mode == 'decode':
					target = target.removesuffix('.dvpl')
					result = await decode_dvpl_file(source, target, force=args.force)
					el.log('Files decoded')
				elif args.mode == 'verify':
					result = await verify_dvpl_file(source)
				if result:
					el.log(f'File {action[args.mode]} OK')
				else:
					el.log(f'File {action[args.mode]} FAILED')
				if result and args.conversion == 'replace' and args.mode != 'verify':
					logger.debug(f"Removing source file: {source}")
					remove(source)				
			except Exception as err:
				el.log('Errors')
				logger.error(str(err))
			finally:
				fileQ.task_done()
	
	except asyncio.CancelledError:		
		logger.debug('Worker cancelled')		
	except Exception as err:
		logger.error(str(err))
	return el
	


async def decode_dvpl_file(dvpl_fn: str, output_fn: str, force: bool = False) -> bool:
	"""Encode a source file to a DVPL file"""
	
	assert dvpl_fn is not None, f"DVPL file name is None"	
	assert output_fn is not None, f"output file name is None"
	assert force is not None, f"--force value is None"

	try:
		output : Optional[bytes] = None
		status = ''

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
			output, status = await decode_dvpl(await ifp.read())	
		
		## Write decoded file
		if output is None:
			raise EncodingWarning(f"Error decoding data: {dvpl_fn} : {status}")
		async with aiofiles.open(output_fn, mode='wb') as ofp:
			logger.debug(f"writing to file: {output_fn}")	
			await ofp.write(output)

		return True
	except asyncio.CancelledError as err:
		logger.info('Cancelled')		
	except Exception as err:
		logger.error(str(err))		
	return False


async def decode_dvpl(input: bytes, quiet: bool = False) -> tuple[Optional[bytes], str]:
	"""Decode a DVPL bytearray"""

	assert input is not None, f"input value is None"
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

		assert output is not None, f"Output value is None"
		assert isinstance(output, bytes), f"Output needs to be bytes, got {type(input)}"
		
		return output, "OK"
	
	except lz4.block.LZ4BlockError as err:
		if not quiet:
			logger.error('LZ4 decoding error: ' + str(err))
		return None, 'LZ4 decoding error'
	except Exception as err:
		if not quiet:
			logger.error(str(err))
		return None, str(err)


async def encode_dvpl_file(input_fn: str, dvpl_fn: str, compression: str = COMPRESSION, force: bool = False) -> bool:
	"""Encode a source file to a DVPL file"""

	assert input_fn is not None, f"input file name is None"
	assert dvpl_fn is not None, f"DVPL file name is None"
	assert compression in COMPRESSIONS, f"Unknown compression: {compression}"
	assert force is not None, f"--force is None"
	
	try:
		output : Optional[bytes] = None
		status = ''
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
			output, status = await encode_dvpl(await ifp.read(), compression)
		
		## Write dvpl file
		if output is None:
			raise EncodingWarning(f"Error encoding data: {status}")
		async with aiofiles.open(dvpl_fn, mode='wb') as ofp:
			logger.debug(f"writing to file: {dvpl_fn}")	
			await ofp.write(output)
		return True
	except asyncio.CancelledError as err:
		logger.info('Cancelled')		
	except Exception as err:
		logger.error(str(err))
	return False


async def encode_dvpl(input: bytes, compression: str, quiet: bool = False) -> tuple[Optional[bytes], str]:
	"""Encode data to a DVPL format"""

	assert isinstance(input, bytes), f"input needs to be bytes, got {type(input)}"
	assert input is not None, f"input is None"
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

		return output + footer, "OK"

	except lz4.block.LZ4BlockError as err:
		if not quiet:
			logger.error('LZ4 encoding error')
		return None, 'LZ4 encoding error'
	except Exception as err:		
		if not quiet:
			logger.error(str(err))	
		return None, str(err)


async def verify_dvpl_file(dvpl_fn: str) -> bool:
	"""Verify a DVPL file"""

	assert dvpl_fn is not None, f"input file name is None type"
	
	try:
		output : Optional[bytes] = None
		status = ''
		if not path.isfile(dvpl_fn):
			raise FileNotFoundError('Source file not found: ' + dvpl_fn)
		if not dvpl_fn.lower().endswith('.dvpl'):
			raise ValueError('Source file is not a DVPL file: ' + dvpl_fn)
		
		## Try to decode a DVPL file
		async with aiofiles.open(dvpl_fn, mode='rb') as ifp:
			logger.debug(f"reading file: {dvpl_fn}")
			output, status = await decode_dvpl(await ifp.read(), quiet=True)	
		if output is not None:
			if logger.getEffectiveLevel() < logging.CRITICAL:
				print(dvpl_fn + ': OK')
			return True
		else:
			print(f"{dvpl_fn} : ERROR: {status}")
			return False
	except asyncio.CancelledError as err:
		logger.info('Cancelled')
	except Exception as err:
		logger.error(str(err))
	return False


def make_dvpl_footer(encoded: bytes, d_size: int, compression: str) -> Optional[bytes]:
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
		f_d_size 	= toUInt32LE(d_size)							# input size as UInt32LE
		f_e_size 	= toUInt32LE(len(encoded))						# output size as UInt32LE
		f_crc32		= toUInt32LE(zlib.crc32(encoded))				# output crc32 as UInt32LE
		f_compression = toUInt32LE(COMPRESSION_TYPE[compression])  	# output type as UInt32LE

		assert (f_d_size is not None) and (f_e_size is not None) and (f_crc32 is not None) and (f_compression is not None), \
				"Making DVPL footer failed"
		footer += f_d_size							# input size as UInt32LE
		footer += f_e_size					# output size as UInt32LE
		footer += f_crc32				# outout crc32 as UInt32LE
		footer += f_compression  	# output type as UInt32LE
		footer += DVPL_MARKER.encode(encoding='utf-8', errors='strict')

		assert len(footer) == 20, f"Footer size != 20"
		return bytes(footer)
	except Exception as err:
		logger.error(str(err))
	return None


def read_dvpl_footer(data: bytes) -> tuple[dict, bytes]:
	"""Read and check 20 byte DVPL footer"""

	assert(isinstance(data, bytes)), f"input needs to be bytes, got {type(data)}"

	result : Dict[str, Union[int, str]] = dict()

	if len(data) < DVPL_FOOTER_LEN:
		raise EncodingWarning('Data is too short (< 20 bytes)')

	footer = data[-DVPL_FOOTER_LEN:]
	
	result['marker'] = str(footer[-4:], encoding='utf-8', errors='strict')
	if result['marker'] != DVPL_MARKER:
		raise EncodingWarning("File is missing 'DVPL' marker in the end of the file.")
		
	f_d_size 	= fromUInt32LE(footer[:4])			# decoded size
	f_e_size 	= fromUInt32LE(footer[4:8])			# encoded size
	f_crc32		= fromUInt32LE(footer[8:12])		# encoded CRC32
	f_compression = fromUInt32LE(footer[12:16]) # encoding type

	assert (f_d_size is not None) and (f_e_size is not None) and (f_crc32 is not None) and (f_compression is not None), \
				"Malformed DVPL footer"
	result['d_size'] 	= f_d_size
	result['e_size'] 	= f_e_size
	result['e_crc'] 	= f_crc32
	assert f_compression >= 0 and f_compression < len(COMPRESSIONS), "unknown compression in DVPL footer"
	result['e_type'] 	= COMPRESSIONS[f_compression] 
	
	if logger.getEffectiveLevel() == logging.DEBUG:
		logger.debug('decoded size: ' + str(result['d_size']))		
		logger.debug('encoded size: ' + str(result['e_size']))
		if isinstance(result['e_crc'], int):
			logger.debug('encoded CRC32: ' + hex(result['e_crc']))
		logger.debug('encoding type: ' + str(result['e_type']))
	
	return result, data[:-DVPL_FOOTER_LEN]


def toUInt32LE(value: int) -> Optional[bytes]:	
	"""Convert an integer to 32-bit unsigned integer in Little-Endian byte-order"""
	try:
		if value is None:
			raise ValueError('None given as input')
		if value < 0:
			raise ValueError('Cannot cast negative value as unsigned int')
		return value.to_bytes(4,byteorder='little', signed=False)
	except Exception as err:
		logger.error(str(err))
	return None


def fromUInt32LE(data: bytes) -> Optional[int]:
	"""Convert a 32-bit unsigned integer in Little-Endian byte-order to integer"""
	try:
		if data is None:
			raise ValueError('None given as input')		
		return int.from_bytes(data, byteorder='little', signed=False)
	except Exception as err:
		logger.error(str(err))
	return None

### main()
if __name__ == "__main__":
   #asyncio.run(main(sys.argv[1:]), debug=True)
   asyncio.run(main(sys.argv[1:]))