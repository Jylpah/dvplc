## -----------------------------------------------------------
#### Class EventLogger()
# Class to log/count events, pass them to parent function 
# and merge the results
## -----------------------------------------------------------

from collections 	import defaultdict
from typing 		import Callable, Optional, Union

import time
import logging 

logger = logging.getLogger(__name__)

message = logger.warning
verbose = logger.info

FuncTypeFormatter 	= Callable[[str], str]
FuncTypeFormatterParam = Optional[FuncTypeFormatter]
class EventLogger():
	"""Count events for categories"""
	def __init__(self, name: str = '', totals: Optional[str] = None, categories: list[str] = list(), errors: list[str] = list(), 
				int_format: FuncTypeFormatterParam = None, float_format: FuncTypeFormatterParam = None):
		assert name is not None, "param 'name' cannot be None"
		assert categories is not None, "param 'categories' cannot be None"
		assert errors is not None, "param 'errors' cannot be None"
		
		self.name		: str = name
		self._log		: defaultdict[str, int] = defaultdict(self._def_value_zero)
		self._error_cats: list[str] = errors
		self._error_status: bool = False
		self._totals = totals
		
		# formatters
		self._format_int 	: FuncTypeFormatter = self._default_int_formatter
		self._format_float 	: FuncTypeFormatter = self._default_float_formatter
		if int_format is not None:
			self._format_int = int_format
		if float_format is not None:
			self._format_float = float_format
		
		# init categories
		for cat in categories:
			self.log(cat, 0)


	@classmethod
	def _def_value_zero(cls) -> int:
		return 0

	
	def _default_int_formatter(self, category: str) -> str:
		assert category is not None, "param 'category' cannot be None"
		return f"{category:40}: {self.get_value(category)}"


	def _default_float_formatter(self, category: str) -> str:
		assert category is not None, "param 'category' cannot be None"
		return f"{category:40}: {self.get_value(category):.2f}"
	

	def log(self, category: str, count: int = 1) -> None:
		assert category is not None, 'category cannot be None'
		assert count is not None, 'count cannot be None'

		self._log[category] += count
		if category in self._error_cats:
			self._error_status = True
		return None


	def get_long_cat(self, category: str) -> str:
		assert category is not None, "param 'category' cannot be None"
		return f"{self.name}: {category}"


	def _get_str(self, category: str) -> str:
		assert category is not None, 'category cannot be None'
		return self._format_int(category)
		

	def get_value(self, category: str) -> int:
		assert category is not None, "param 'category' cannot be None"
		try:
			return self._log[category]
		except:
			logger.error(f"invalid categgory: {category}")
			return 0

	
	def get_values(self) -> dict[str, int]:
		return self._log 


	def sum(self, categories: list[str]) -> int:
		ret = 0
		for cat in categories:
			ret += self.get_value(cat)
		return ret
		

	def get_categories(self) -> list[str]:
		return list(self._log.keys())

	
	def get_error_status(self) -> bool:
		return self._error_status
	

	def merge(self, B: 'EventLogger') -> bool:
		"""Merge two EventLogger instances together"""
		assert isinstance(B, EventLogger), f"input is not type of 'EventLogger' but: {type(B)}"
		
		try:
			if not isinstance(B, EventLogger):
				logger.error(f"input is not type of 'EventLogger' but: {type(B)}")
				return False			
			for cat in B.get_categories():
				value: int = B.get_value(cat)
				self.log(cat, value)
				if self._totals is not None:
					self.log(f"{self._totals}: {cat}", value)				
				self._error_status = self._error_status or B.get_error_status()
			return True
		except Exception as err:
			logger.error(str(err))
		return False
		

	def merge_child(self, B: 'EventLogger') -> bool:
		"""Merge two EventLogger instances together"""
		assert isinstance(B, EventLogger), f"input is not type of 'EventLogger' but: {type(B)}"
		
		try:
			for cat in B.get_categories():
				value: int = B.get_value(cat)
				self.log(B.get_long_cat(cat), value)
				if self._totals is not None:
					self.log(f"{self._totals}: {cat}", value)				
			self._error_status = self._error_status or B.get_error_status()
			return True
		except Exception as err:
			logger.error(str(err))
		return False


	def get_header(self) -> str:
		return f"{self.name}" + (': ERROR occured' if self.get_error_status() else '')


	def print(self, do_print : bool = True) -> Optional[str]: 
		try:
			if do_print:
				message(self.get_header())
				for cat in sorted(self._log):
					message(self._get_str(cat))
				return None
			else:
				ret = self.get_header()
				for cat in sorted(self._log):
					ret += f"\n{self._get_str(cat)}"
				return ret
		except Exception as err:
			logger.error(str(err))
		return None 