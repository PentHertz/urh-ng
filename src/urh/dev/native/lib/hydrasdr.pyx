cimport urh.dev.native.lib.chydrasdr as chydrasdr
from libc.stdlib cimport malloc, free
from libc.stdint cimport uint32_t, uint64_t
import time
from cpython cimport array
import array
# noinspection PyUnresolvedReferences
from cython.view cimport array as cvarray  # needed for converting of malloc array to python array
from urh.util.Logger import logger


ctypedef unsigned char uint8_t

cdef chydrasdr.hydrasdr_device* _c_device
cdef object f

cdef int _c_callback_recv(chydrasdr.hydrasdr_transfer*transfer) noexcept with gil:
    global f
    try:
        (<object> f)(<float [:2*transfer.sample_count]>transfer.samples)
    except OSError as e:
        logger.warning("Cython-HydraSDR:" + str(e))
    return 0

cpdef list get_device_list():
    cdef int count = chydrasdr.hydrasdr_list_devices(NULL, 0)
    if count <= 0:
        return []
    cdef uint64_t* serials = <uint64_t*>malloc(count * sizeof(uint64_t))
    if serials == NULL:
        return []
    chydrasdr.hydrasdr_list_devices(serials, count)
    result = []
    for i in range(count):
        result.append("HydraSDR {:08X}{:08X}".format(
            <uint32_t>(serials[i] >> 32),
            <uint32_t>(serials[i] & 0xFFFFFFFF)))
    free(serials)
    return result

cpdef open_by_serial(uint64_t serial_number):
    return chydrasdr.hydrasdr_open_sn(&_c_device, serial_number)

cpdef open():
    return chydrasdr.hydrasdr_open(&_c_device)

cpdef close():
    return chydrasdr.hydrasdr_close(_c_device)

cpdef array.array get_sample_rates():
    cdef uint32_t count = 0
    result = chydrasdr.hydrasdr_get_samplerates(_c_device, &count, 0)
    if result != chydrasdr.hydrasdr_error.HYDRASDR_SUCCESS:
        return array.array('I', [])

    cdef array.array sample_rates = array.array('I', [0]*count)
    result = chydrasdr.hydrasdr_get_samplerates(_c_device, &sample_rates.data.as_uints[0], count)

    if result == chydrasdr.hydrasdr_error.HYDRASDR_SUCCESS:
        return sample_rates
    else:
        return array.array('I', [])

cpdef int set_sample_rate(uint32_t sample_rate):
    """
    Parameter samplerate can be either the index of a samplerate or directly its value in Hz within the list
    """
    return chydrasdr.hydrasdr_set_samplerate(_c_device, sample_rate)

cpdef int set_center_frequency(uint64_t freq_hz):
    """
    Parameter freq_hz in Hz (uint64_t since API v1.1.0)
    """
    return chydrasdr.hydrasdr_set_freq(_c_device, freq_hz)

cpdef int set_baseband_gain(uint8_t lna_gain):
    """
    Shall be between 0 and 15
    """
    return chydrasdr.hydrasdr_set_lna_gain(_c_device, lna_gain)

cpdef int set_rf_gain(uint8_t mixer_gain):
    """
    Shall be between 0 and 15
    """
    return chydrasdr.hydrasdr_set_mixer_gain(_c_device, mixer_gain)

cpdef int set_if_rx_gain(uint8_t vga_gain):
    """
    Shall be between 0 and 15
    """
    return chydrasdr.hydrasdr_set_vga_gain(_c_device, vga_gain)

cpdef array.array get_bandwidths():
    """Query available hardware bandwidths."""
    cdef uint32_t count = 0
    result = chydrasdr.hydrasdr_get_bandwidths(_c_device, &count, 0)
    if result != chydrasdr.hydrasdr_error.HYDRASDR_SUCCESS:
        return array.array('I', [])

    cdef array.array bws = array.array('I', [0]*count)
    result = chydrasdr.hydrasdr_get_bandwidths(_c_device, &bws.data.as_uints[0], count)

    if result == chydrasdr.hydrasdr_error.HYDRASDR_SUCCESS:
        return bws
    else:
        return array.array('I', [])

cpdef int set_bandwidth(uint32_t bandwidth):
    """
    Set bandwidth. If the exact value is not supported, pick the
    closest available hardware bandwidth.
    """
    # First try the exact value
    cdef int ret = chydrasdr.hydrasdr_set_bandwidth(_c_device, bandwidth)
    if ret == chydrasdr.hydrasdr_error.HYDRASDR_SUCCESS:
        return ret

    # Exact value failed — query available bandwidths and pick closest
    cdef uint32_t count = 0
    chydrasdr.hydrasdr_get_bandwidths(_c_device, &count, 0)
    if count == 0:
        # No bandwidths available — device manages BW internally
        logger.info(f"HydraSDR: bandwidth {bandwidth} not settable, using device default")
        return 0

    cdef array.array bws = array.array('I', [0]*count)
    chydrasdr.hydrasdr_get_bandwidths(_c_device, &bws.data.as_uints[0], count)

    # Find closest
    cdef uint32_t best = bws[0]
    cdef uint32_t best_diff = abs(<int>(bandwidth - best))
    for i in range(1, count):
        diff = abs(<int>(bandwidth - bws[i]))
        if diff < best_diff:
            best = bws[i]
            best_diff = diff

    if best != bandwidth:
        logger.info(f"HydraSDR: bandwidth {bandwidth} -> {best} (closest available)")

    return chydrasdr.hydrasdr_set_bandwidth(_c_device, best)

cpdef int set_sample_type_iq():
    return chydrasdr.hydrasdr_set_sample_type(_c_device, chydrasdr.hydrasdr_sample_type.HYDRASDR_SAMPLE_FLOAT32_IQ)

cpdef int set_decimation_mode(int mode):
    """
    0 = LOW_BANDWIDTH (default), 1 = HIGH_DEFINITION
    """
    return chydrasdr.hydrasdr_set_decimation_mode(_c_device, <chydrasdr.hydrasdr_decimation_mode>mode)

cpdef int start_rx(callback):
    global f
    f = callback
    chydrasdr.hydrasdr_set_sample_type(_c_device, chydrasdr.hydrasdr_sample_type.HYDRASDR_SAMPLE_FLOAT32_IQ)
    return chydrasdr.hydrasdr_start_rx(_c_device, _c_callback_recv, NULL)

cpdef int stop_rx():
    time.sleep(0.01)
    return chydrasdr.hydrasdr_stop_rx(_c_device)

cpdef str error_name(chydrasdr.hydrasdr_error error_code):
    cdef const char* c_error_name = chydrasdr.hydrasdr_error_name(error_code)
    return c_error_name.decode('UTF-8')
