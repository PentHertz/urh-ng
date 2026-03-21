"""
Signal Hound BB60 series API wrapper for URH.

Pure Python wrapper using ctypes — no Cython compilation needed.
Requires libbb_api.so (Linux) or bb_api.dll (Windows) to be installed.
"""

import ctypes
import ctypes.util
import numpy as np
from urh.util.Logger import logger

# Try to load the library
_lib = None
_handle = ctypes.c_int(-1)
_is_open = False
_sample_rate = 40e6
_center_freq = 433.92e6
_ref_level = -30.0
_decimation = 1

# Constants from bb_api.h
BB_STREAMING = 4
BB_STREAM_IQ = 0x0
BB_AUTO_GAIN = -1
BB_AUTO_ATTEN = -1
BB_MIN_DECIMATION = 1
BB_MAX_DECIMATION = 8192
BB_MAX_DEVICES = 8

# IQ buffer size
IQ_BLOCK_SIZE = 16384


def _load_lib():
    global _lib
    if _lib is not None:
        return True
    lib_name = ctypes.util.find_library("bb_api")
    if lib_name is None:
        # Try common paths
        import platform

        if platform.system() == "Linux":
            for path in [
                "libbb_api.so",
                "/usr/lib/libbb_api.so",
                "/usr/local/lib/libbb_api.so",
            ]:
                try:
                    _lib = ctypes.CDLL(path)
                    return True
                except OSError:
                    continue
        return False
    try:
        _lib = ctypes.CDLL(lib_name)
        return True
    except OSError:
        return False


def get_device_list():
    """Return list of connected Signal Hound device serial numbers."""
    if not _load_lib():
        return []
    serials = (ctypes.c_int * BB_MAX_DEVICES)()
    count = ctypes.c_int(0)
    ret = _lib.bbGetSerialNumberList(serials, ctypes.byref(count))
    if ret != 0:
        return []
    return [f"SignalHound {serials[i]}" for i in range(count.value)]


def open_device():
    """Open the first available Signal Hound device."""
    global _handle, _is_open
    if _is_open:
        return 0
    if not _load_lib():
        return -1
    handle = ctypes.c_int(-1)
    ret = _lib.bbOpenDevice(ctypes.byref(handle))
    if ret == 0:
        _handle = handle
        _is_open = True
        logger.info(f"Signal Hound opened (handle={handle.value})")
    else:
        logger.error(f"Signal Hound open failed: {ret}")
    return ret


def open_device_by_serial(serial):
    """Open a specific Signal Hound device by serial number."""
    global _handle, _is_open
    if _is_open:
        return 0
    if not _load_lib():
        return -1
    handle = ctypes.c_int(-1)
    ret = _lib.bbOpenDeviceBySerialNumber(ctypes.byref(handle), ctypes.c_int(serial))
    if ret == 0:
        _handle = handle
        _is_open = True
    return ret


def close_device():
    """Close the device."""
    global _is_open
    if not _is_open:
        return 0
    ret = _lib.bbCloseDevice(_handle)
    if ret == 0:
        _is_open = False
    return ret


def set_center_frequency(freq_hz):
    """Set center frequency for IQ streaming."""
    global _center_freq
    if not _is_open:
        return -1
    _center_freq = float(freq_hz)
    return _lib.bbConfigureIQCenter(_handle, ctypes.c_double(_center_freq))


def set_sample_rate(sample_rate):
    """Set IQ sample rate by computing decimation from 40 MS/s base."""
    global _sample_rate, _decimation
    if not _is_open:
        return -1
    base_rate = 40e6
    dec = max(1, int(base_rate / sample_rate))
    # Round to nearest power of 2
    dec = 1 << (dec - 1).bit_length() if dec > 1 else 1
    dec = max(BB_MIN_DECIMATION, min(BB_MAX_DECIMATION, dec))
    _decimation = dec
    _sample_rate = base_rate / dec
    bw = _sample_rate * 0.8  # 80% of sample rate
    return _lib.bbConfigureIQ(_handle, ctypes.c_int(dec), ctypes.c_double(bw))


def set_ref_level(ref_level_dbm):
    """Set reference level in dBm."""
    global _ref_level
    if not _is_open:
        return -1
    _ref_level = float(ref_level_dbm)
    ret = _lib.bbConfigureRefLevel(_handle, ctypes.c_double(_ref_level))
    if ret != 0:
        return ret
    return _lib.bbConfigureGainAtten(
        _handle, ctypes.c_int(BB_AUTO_GAIN), ctypes.c_int(BB_AUTO_ATTEN)
    )


def start_rx():
    """Start IQ streaming."""
    if not _is_open:
        return -1
    return _lib.bbInitiate(
        _handle,
        ctypes.c_uint32(BB_STREAMING),
        ctypes.c_uint32(BB_STREAM_IQ),
    )


def stop_rx():
    """Stop streaming."""
    if not _is_open:
        return 0
    return _lib.bbAbort(_handle)


def get_iq_data():
    """Fetch a block of IQ data as interleaved float32 bytes."""
    if not _is_open:
        return b""
    iq = np.zeros(IQ_BLOCK_SIZE, dtype=np.complex64)
    data_remaining = ctypes.c_int(0)
    sample_loss = ctypes.c_int(0)
    sec = ctypes.c_int(0)
    nano = ctypes.c_int(0)
    ret = _lib.bbGetIQUnpacked(
        _handle,
        iq.ctypes.data_as(ctypes.c_void_p),
        ctypes.c_int(IQ_BLOCK_SIZE),
        ctypes.c_void_p(0),  # no triggers
        ctypes.c_int(0),  # trigger count
        ctypes.c_int(0),  # don't purge
        ctypes.byref(data_remaining),
        ctypes.byref(sample_loss),
        ctypes.byref(sec),
        ctypes.byref(nano),
    )
    if ret != 0:
        return b""
    # Convert complex64 to interleaved float32
    interleaved = np.empty(IQ_BLOCK_SIZE * 2, dtype=np.float32)
    interleaved[0::2] = iq.real
    interleaved[1::2] = iq.imag
    return interleaved.tobytes()


def get_sample_rate():
    """Query current IQ sample rate."""
    return _sample_rate
