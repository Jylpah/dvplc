# static typing for EventCounter

from typing import Optional, Callable

FuncTypeFormatter 	= Callable[[str], str]
FuncTypeFormatterParam = Optional[FuncTypeFormatter]

class EventCounter():

	def __init__(self, name: str = '', totals: Optional[str] = None, categories: list[str] = list(), errors: list[str] = list(), 
					int_format: FuncTypeFormatterParam = None, float_format: FuncTypeFormatterParam = None): ...

	def _def_value_zero(cls) -> int: ...

	def _default_int_formatter(self, category: str) -> str: ...

	def _default_float_formatter(self, category: str) -> str: ...

	def log(self, category: str, count: int = 1) -> None: ...

	def get_long_cat(self, category: str) -> str: ...

	def _get_str(self, category: str) -> str: ...

	def get_value(self, category: str) -> int: ...

	def get_values(self) -> dict[str, int]: ...

	def sum(self, categories: list[str]) -> int: ...

	def get_categories(self) -> list[str]: ...

	def get_error_status(self) -> bool: ...

	def merge(self, B: 'EventCounter') -> bool: ...

	def merge_child(self, B: 'EventCounter') -> bool: ...

	def get_header(self) -> str: ...

	def print(self, do_print : bool = True) -> Optional[str]:  ...