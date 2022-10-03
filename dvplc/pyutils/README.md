# pyutils

Python util library

# MODULES 

* `FileQueue(asyncio.Queue)`: Class to build file queue to process from command line arguments or STDIN (`-`)
* `ThrottledClientSession(aiohttp.ClientSession)`: Rate-throttled client session class inherited from aiohttp.ClientSession)
* `MultiLevelFormatter(logging.Formatter)`: Different message formats per logging level
* `EventLogger()`: Count / log statistics and merge different `EventLogger()` instances to provide aggregated stats
