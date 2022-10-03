## -----------------------------------------------------------
#### Class FileQueue(asyncio.Queue)
#
#  Class to build async Queue of files based on arguments given. 
#  Supports filtering
#
## -----------------------------------------------------------

import logging
import asyncio
import aioconsole
from os 			import scandir, path
from fnmatch 		import fnmatch
from typing			import Optional

logger = logging.getLogger(__name__)

# inherit from asyncio.Queue? 
class FileQueue(asyncio.Queue):
	"""
	Class to create create a async queue of files based on given dirs files given as 
	arguments. Filters based on file names. 
	"""

	def __init__(self, base: Optional[str] = None, maxsize: int = 0, filter: str = '*', 
				exclude: bool = False, case_sensitive: bool = False):
		assert maxsize >= 0, "maxsize has to be >= 0"
		assert case_sensitive is not None, "case_sensitive cannot be None"
		assert filter is not None, "filter cannot be None"

		logger.debug(f"maxsize={str(maxsize)}, filter='{filter}'") 
		super().__init__(maxsize)
		self._base:		Optional[str]= base
		self._done: 			bool = False
		self._case_sensitive: 	bool = False
		self._exclude: 			bool = False
		self._count:			int = 0
		self.set_filter(filter=filter, exclude=exclude, case_sensitive=case_sensitive)


	def set_filter(self, filter: str = None, exclude: bool = None, case_sensitive: bool = None ):
		"""set filtering logic. Only set (!= None) params are changed"""
		if case_sensitive is not None:
			self._case_sensitive = case_sensitive
		if exclude is not None:
			self._exclude 		= exclude
		if filter is not None:
			if self._case_sensitive:
				self._filter = filter.lower()
			else:
				self._filter = filter
		logger.debug(f"filter={str(self._filter)} exclude={str(self._exclude)}, case_sensitive={str(self._case_sensitive)}")


	async def mk_queue(self, files: list[str]) -> bool:
		"""Create file queue from arguments given
			'-' denotes for STDIN
		"""
		assert files is not None and len(files) > 0, "No files given to process"

		try:		
			if files[0] == '-':
				stdin, _ = await aioconsole.get_standard_streams()
				while True:
					line = (await stdin.readline()).decode('utf-8').removesuffix("\n")
					if not line: 
						break
					else:
						if self._base is None:
							await self.put(line)
						else:
							await self.put(path.join(self._base, line))
			else:
				for file in files:
					if self._base is None:
						await self.put(file)
					else:
						await self.put(path.join(self._base, file))
					
			return True
		except Exception as err:
			logger.error(str(err))
		return False

	
	async def put(self, filename: str) -> None:
		"""Recursive function to build process queueu. Sanitize filename"""
		assert filename is not None and len(filename) > 0, "None/zero-length filename given as input"
		
		try:			
			# filename = path.normpath(filename)   # string operation
			if  path.isdir(filename):
				with scandir(filename) as dirEntry:
					for entry in dirEntry:
						await self.put(entry.path)		
			elif path.isfile(filename) and self._match(filename):
				logger.debug(f"Adding file to queue: {filename}")
				await super().put(filename)
				self._count += 1
		except Exception as err:
			logger.error(str(err))
		return None


	def count(self) -> int:
		"""Return the number of items added to the queue"""
		return self._count


	def _match(self, filename: str) -> bool:
		""""Match file name with filter
		
		https://docs.python.org/3/library/fnmatch.html
		"""
		assert filename is not None, "None provided as filename"
		try:
			filename = path.basename(filename)

			if self._case_sensitive:
				filename = filename.lower()
			
			m = fnmatch(filename, self._filter)
			if self._exclude:
				return not m
			else:
				return m
		except Exception as err:
			logger.error(str(err))
		return False
