ctypedef unsigned char uint8_t
ctypedef short int16_t
ctypedef unsigned short uint16_t
ctypedef unsigned int uint32_t
ctypedef unsigned long long uint64_t

cdef extern from "libhydrasdr/hydrasdr.h":
    enum hydrasdr_error:
        HYDRASDR_SUCCESS = 0
        HYDRASDR_TRUE = 1
        HYDRASDR_ERROR_INVALID_PARAM = -2
        HYDRASDR_ERROR_NOT_FOUND = -5
        HYDRASDR_ERROR_BUSY = -6
        HYDRASDR_ERROR_NO_MEM = -11
        HYDRASDR_ERROR_LIBUSB = -1000
        HYDRASDR_ERROR_THREAD = -1001
        HYDRASDR_ERROR_STREAMING_THREAD_ERR = -1002
        HYDRASDR_ERROR_STREAMING_STOPPED = -1003
        HYDRASDR_ERROR_OTHER = -9999

    enum hydrasdr_board_id:
        HYDRASDR_BOARD_ID_PROTO_HYDRASDR = 0
        HYDRASDR_BOARD_ID_INVALID = 0xFF

    enum hydrasdr_sample_type:
        HYDRASDR_SAMPLE_FLOAT32_IQ = 0    # 2 * 32bit float per sample
        HYDRASDR_SAMPLE_FLOAT32_REAL = 1  # 1 * 32bit float per sample
        HYDRASDR_SAMPLE_INT16_IQ = 2      # 2 * 16bit int per sample
        HYDRASDR_SAMPLE_INT16_REAL = 3    # 1 * 16bit int per sample
        HYDRASDR_SAMPLE_UINT16_REAL = 4   # 1 * 16bit unsigned int per sample
        HYDRASDR_SAMPLE_RAW = 5           # Raw packed samples from the device
        HYDRASDR_SAMPLE_END = 6           # Number of supported sample types

    enum hydrasdr_decimation_mode:
        HYDRASDR_DEC_MODE_LOW_BANDWIDTH = 0
        HYDRASDR_DEC_MODE_HIGH_DEFINITION = 1

    enum hydrasdr_gain_type_t:
        HYDRASDR_GAIN_TYPE_LNA = 0
        HYDRASDR_GAIN_TYPE_RF = 1
        HYDRASDR_GAIN_TYPE_MIXER = 2
        HYDRASDR_GAIN_TYPE_FILTER = 3
        HYDRASDR_GAIN_TYPE_VGA = 4
        HYDRASDR_GAIN_TYPE_LINEARITY = 5
        HYDRASDR_GAIN_TYPE_SENSITIVITY = 6
        HYDRASDR_GAIN_TYPE_LNA_AGC = 7
        HYDRASDR_GAIN_TYPE_RF_AGC = 8
        HYDRASDR_GAIN_TYPE_MIXER_AGC = 9
        HYDRASDR_GAIN_TYPE_FILTER_AGC = 10
        HYDRASDR_GAIN_TYPE_COUNT = 11

    enum hydrasdr_rf_port_t:
        HYDRASDR_RF_PORT_RX0 = 0
        HYDRASDR_RF_PORT_RX1 = 1
        HYDRASDR_RF_PORT_RX2 = 2
        HYDRASDR_RF_PORT_MAX = 31

    struct hydrasdr_device

    ctypedef struct hydrasdr_transfer:
        hydrasdr_device* device
        void* ctx
        void* samples
        int sample_count
        uint64_t dropped_samples
        hydrasdr_sample_type sample_type

    ctypedef struct hydrasdr_read_partid_serialno_t:
        uint32_t part_id[2]
        uint32_t serial_no[4]

    ctypedef struct hydrasdr_lib_version_t:
        uint32_t major_version
        uint32_t minor_version
        uint32_t revision

    ctypedef struct hydrasdr_gain_info_t:
        uint8_t type
        uint8_t value
        uint8_t min_value
        uint8_t max_value
        uint8_t step_value
        uint8_t default_value
        uint8_t flags
        uint8_t reserved

    ctypedef int (*hydrasdr_sample_block_cb_fn)(hydrasdr_transfer* transfer)

    void hydrasdr_lib_version(hydrasdr_lib_version_t* lib_version)
    int hydrasdr_list_devices(uint64_t* serials, int count)
    int hydrasdr_open_sn(hydrasdr_device** device, uint64_t serial_number)
    int hydrasdr_open(hydrasdr_device** device)
    int hydrasdr_close(hydrasdr_device* device)

    int hydrasdr_get_samplerates(hydrasdr_device* device, uint32_t* buffer, const uint32_t len)
    int hydrasdr_set_samplerate(hydrasdr_device* device, uint32_t samplerate)

    int hydrasdr_set_decimation_mode(hydrasdr_device* device, hydrasdr_decimation_mode mode)
    int hydrasdr_get_decimation_mode(hydrasdr_device* device, hydrasdr_decimation_mode* mode)

    int hydrasdr_get_bandwidths(hydrasdr_device* device, uint32_t* buffer, const uint32_t len)
    int hydrasdr_set_bandwidth(hydrasdr_device* device, uint32_t bandwidth)

    int hydrasdr_set_conversion_filter_float32(hydrasdr_device* device, const float *kernel, const uint32_t len)
    int hydrasdr_set_conversion_filter_int16(hydrasdr_device* device, const int16_t *kernel, const uint32_t len)

    int hydrasdr_start_rx(hydrasdr_device* device, hydrasdr_sample_block_cb_fn callback, void* rx_ctx)
    int hydrasdr_stop_rx(hydrasdr_device* device)

    int hydrasdr_is_streaming(hydrasdr_device* device)

    int hydrasdr_si5351c_write(hydrasdr_device* device, uint8_t register_number, uint8_t value)
    int hydrasdr_si5351c_read(hydrasdr_device* device, uint8_t register_number, uint8_t* value)

    int hydrasdr_config_write(hydrasdr_device* device, const uint8_t page_index, const uint16_t length, unsigned char *data)
    int hydrasdr_config_read(hydrasdr_device* device, const uint8_t page_index, const uint16_t length, unsigned char *data)

    int hydrasdr_rf_frontend_write(hydrasdr_device* device, uint16_t register_address, uint32_t value)
    int hydrasdr_rf_frontend_read(hydrasdr_device* device, uint16_t register_address, uint32_t* value)

    int hydrasdr_board_id_read(hydrasdr_device* device, uint8_t* value)
    int hydrasdr_version_string_read(hydrasdr_device* device, char* version, uint8_t length)

    int hydrasdr_board_partid_serialno_read(hydrasdr_device* device, hydrasdr_read_partid_serialno_t* read_partid_serialno)

    int hydrasdr_set_sample_type(hydrasdr_device* device, hydrasdr_sample_type sample_type)

    # Parameter freq_hz: uint64_t since v1.1.0 (was uint32_t in v1.0.x)
    int hydrasdr_set_freq(hydrasdr_device* device, const uint64_t freq_hz)

    # Unified gain API (v1.1.0+)
    int hydrasdr_set_gain(hydrasdr_device* device, hydrasdr_gain_type_t type, uint8_t value)
    int hydrasdr_get_gain(hydrasdr_device* device, hydrasdr_gain_type_t type, hydrasdr_gain_info_t* info)
    int hydrasdr_get_all_gains(hydrasdr_device* device, hydrasdr_gain_info_t* gains, uint8_t* count)

    # Legacy gain functions (deprecated since v1.1.0, still functional)
    int hydrasdr_set_lna_gain(hydrasdr_device* device, uint8_t value)
    int hydrasdr_set_mixer_gain(hydrasdr_device* device, uint8_t value)
    int hydrasdr_set_vga_gain(hydrasdr_device* device, uint8_t value)
    int hydrasdr_set_lna_agc(hydrasdr_device* device, uint8_t value)
    int hydrasdr_set_mixer_agc(hydrasdr_device* device, uint8_t value)
    int hydrasdr_set_linearity_gain(hydrasdr_device* device, uint8_t value)
    int hydrasdr_set_sensitivity_gain(hydrasdr_device* device, uint8_t value)

    int hydrasdr_set_rf_bias(hydrasdr_device* dev, uint8_t value)
    int hydrasdr_set_packing(hydrasdr_device* device, uint8_t value)
    int hydrasdr_set_rf_port(hydrasdr_device* device, hydrasdr_rf_port_t rf_port)

    const char* hydrasdr_error_name(hydrasdr_error errcode)
    const char* hydrasdr_board_id_name(hydrasdr_board_id board_id)

    int hydrasdr_spiflash_erase_sector(hydrasdr_device* device, const uint16_t sector_num)
    int hydrasdr_reset(hydrasdr_device* device)
