import logging, sys
from typing import Literal, Optional

def set_mlevel_logging(logger: logging.Logger, fmts: dict[int, str]=None, fmt: Optional[str]=None, datefmt: Optional[str]=None, 
					style:Literal['%', '{', '$'] ='%', validate: bool=True, log_file: str = None):
	"""Setup logging"""
	if fmts is not None:
		multi_formatter = MultilevelFormatter(fmt=fmt, fmts=fmts, datefmt=datefmt, style=style, validate=validate )
		stream_handler = logging.StreamHandler(sys.stdout)
		stream_handler.setFormatter(multi_formatter)		
		logger.addHandler(stream_handler)

	if log_file is not None:
		file_handler 	= logging.FileHandler(log_file)			
		log_formatter 	= logging.Formatter(fmt=fmt, style=style, validate=validate)
		file_handler.setFormatter(log_formatter)
		logger.addHandler(file_handler)

class MultilevelFormatter(logging.Formatter):
		
	_levels: list[int] = [logging.NOTSET, logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL]

	def __init__(self, fmts: dict[int, str], fmt: Optional[str]=None, datefmt: Optional[str]=None, 
					style:Literal['%', '{', '$'] ='%', validate: bool=True, *, defaults = None):
		assert fmts is not None, "styles cannot be None"
		
		self._formatters: dict[int, logging.Formatter] = dict()
		for level in self._levels:
			self._formatters[level] = logging.Formatter(fmt=fmt, datefmt=datefmt, style=style, validate=validate, defaults=defaults)
		
		for level in fmts.keys():
			self._formatters[level] = logging.Formatter(fmt=fmts[level], style=style)

		
	def format(self, record: logging.LogRecord) -> str:
		try:
			return self._formatters[record.levelno].format(record)			
		except Exception as err:
			logging.error(str(err))
			return str(err)


	def formatTime(self, record: logging.LogRecord, datefmt: Optional[str]=None):
		try:
			return self._formatters[record.levelno].formatTime(record = record, datefmt=datefmt)			
		except Exception as err:
			logging.error(str(err))
			return str(err)