import atexit
import ctypes
import json
import logging
import os
import platform
from typing import Any, Dict, List, Union, Callable

log = logging.getLogger("GOBRIDGE")

JSONType = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]

FileDir = os.path.dirname(os.path.realpath(__file__))

WINDOWS = platform.system() == "Windows"
LIB_EXT = "dll" if WINDOWS else "so"

devLibPath = os.path.join(FileDir, "libbtcwallet", "libbtcwallet."+LIB_EXT)

if os.path.isfile(devLibPath):
    lib = ctypes.cdll.LoadLibrary(devLibPath)
else:
    lib = ctypes.cdll.LoadLibrary("libbtcwallet."+LIB_EXT)


goFreeCharPtr = lib.FreeCharPtr
goFreeCharPtr.argtypes = [ctypes.c_char_p]

goCall = lib.Call
goCall.restype = ctypes.c_void_p
goCall.argtypes = [ctypes.c_char_p]


def Go(funcName: str, params: JSONType) -> JSONType:
    b = GoRaw(funcName, params)
    return json.loads(b or 'true')  # empty response indicates success


def GoRaw(funcName: str, params: JSONType) -> bytes:
    b = json.dumps(dict(
        function=funcName,
        params=params,
    ))
    r = goCall(b.encode("utf-8"))
    try:
        return ctypes.cast(r, ctypes.c_char_p).value
    except Exception as e:
        log.error("Go error: %s", e)
    finally:
        goFreeCharPtr(ctypes.cast(r, ctypes.c_char_p))


def delink():
    Go("exit", "")


feeders = []

logFeedID = 0


def registerFeeder(f: Callable[[bytes], None]):
    feeders.append(f)


@ctypes.CFUNCTYPE(None, ctypes.c_char_p)
def feedRelay(msgB: bytes):
    msg = json.loads(msgB)
    feedID = msg["feedID"]
    if feedID == logFeedID:
        log.info(msg["payload"])
        return
    for feeder in feeders:
        feeder(msg)


lib.Feed(feedRelay)

# Extra 'exit' calls are free, so call it prodigiously.
atexit.register(delink)
