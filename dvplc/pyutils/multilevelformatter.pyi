import logging
from typing import Optional, Literal

def set_mlevel_logging(logger: logging.Logger, fmts: dict[int, str]=None, fmt: Optional[str]=None, datefmt: Optional[str]=None, 
					style:Literal['%', '{', '$'] ='%', validate: bool=True, log_file: str = None): ...


class MultilevelFormatter(logging.Formatter): 

	def __init__(self, fmts: dict[int, str], fmt: Optional[str]=None, datefmt: Optional[str]=None, 
					style:Literal['%', '{', '$'] ='%', validate: bool=True, *, defaults = None): ...

	def format(self, record: logging.LogRecord) -> str: ...

	def formatTime(self, record: logging.LogRecord, datefmt: Optional[str]=None): ...