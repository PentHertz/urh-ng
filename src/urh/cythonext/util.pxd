ctypedef fused iq:
    # Use "signed char" instead of plain "char" here: the C standard leaves the
    # signedness of a bare char up to the platform (x86 defaults to signed,
    # ARM/AArch64 defaults to unsigned). Our int8 sample data is always meant
    # to be signed (see IQArray.from_file/.tofile), so pin it explicitly or
    # this whole fused-type specialization silently reinterprets negative
    # sample bytes as large positive values on ARM builds.
    signed char
    unsigned char
    short
    unsigned short
    float

ctypedef iq[:, ::1] IQ

from libc.stdint cimport uint64_t, uint8_t, int64_t

cpdef uint64_t bit_array_to_number(uint8_t[:] bits, int64_t end, int64_t start=*) nogil