"""
Signal Hound BB60C/BB60D IQ streaming integration for URH.

Uses the BB series API (bb_api) for IQ streaming.
Supports BB60A, BB60C, BB60D devices.

Frequency range: 9 kHz - 6.4 GHz
IQ sample rate: 40 MS/s / decimation (1-8192)
"""

import numpy as np
from collections import OrderedDict
from multiprocessing.connection import Connection

from urh.dev.native.Device import Device
from urh.util.Logger import logger


class SignalHound(Device):
    ASYNCHRONOUS = False
    DATA_TYPE = np.float32

    DEVICE_METHODS = Device.DEVICE_METHODS.copy()
    DEVICE_METHODS.update(
        {
            Device.Command.SET_FREQUENCY.name: "set_center_frequency",
            Device.Command.SET_SAMPLE_RATE.name: "set_sample_rate",
            Device.Command.SET_RF_GAIN.name: "set_ref_level",
        }
    )
    del DEVICE_METHODS[Device.Command.SET_BANDWIDTH.name]

    try:
        from urh.dev.native.lib import signalhound

        DEVICE_LIB = signalhound
    except ImportError:
        DEVICE_LIB = None

    @property
    def has_multi_device_support(self):
        return True

    @classmethod
    def get_device_list(cls):
        if cls.DEVICE_LIB is None:
            return []
        return cls.DEVICE_LIB.get_device_list()

    @classmethod
    def setup_device(cls, ctrl_connection: Connection, device_identifier):
        if cls.DEVICE_LIB is None:
            ctrl_connection.send("OPEN: library not found")
            return False
        if device_identifier:
            try:
                serial = int(device_identifier.replace("SignalHound ", ""))
                ret = cls.DEVICE_LIB.open_device_by_serial(serial)
            except (ValueError, TypeError):
                ret = cls.DEVICE_LIB.open_device()
        else:
            ret = cls.DEVICE_LIB.open_device()
        ctrl_connection.send("OPEN:" + str(ret))
        return ret == 0

    @classmethod
    def shutdown_device(cls, ctrl_connection, is_tx=False):
        logger.debug("SignalHound: closing device")
        ret = cls.DEVICE_LIB.stop_rx()
        ctrl_connection.send("Stop RX:" + str(ret))
        ret = cls.DEVICE_LIB.close_device()
        ctrl_connection.send("EXIT:" + str(ret))
        return True

    @classmethod
    def prepare_sync_receive(cls, ctrl_connection: Connection):
        ret = cls.DEVICE_LIB.start_rx()
        ctrl_connection.send("Start RX:" + str(ret))
        return ret

    @classmethod
    def receive_sync(cls, data_conn: Connection):
        data = cls.DEVICE_LIB.get_iq_data()
        if data is not None and len(data) > 0:
            data_conn.send_bytes(data)

    def __init__(
        self,
        center_freq,
        sample_rate,
        bandwidth,
        gain,
        if_gain=0,
        baseband_gain=0,
        resume_on_full_receive_buffer=False,
    ):
        super().__init__(
            center_freq=center_freq,
            sample_rate=sample_rate,
            bandwidth=bandwidth,
            gain=gain,
            if_gain=if_gain,
            baseband_gain=baseband_gain,
            resume_on_full_receive_buffer=resume_on_full_receive_buffer,
        )
        self.bandwidth_is_adjustable = False

    @property
    def device_parameters(self) -> OrderedDict:
        return OrderedDict(
            [
                (self.Command.SET_FREQUENCY.name, self.frequency),
                (self.Command.SET_SAMPLE_RATE.name, self.sample_rate),
                (self.Command.SET_RF_GAIN.name, self.gain),
                ("identifier", self.device_serial),
            ]
        )

    @staticmethod
    def bytes_to_iq(buffer) -> np.ndarray:
        return np.frombuffer(buffer, dtype=np.float32).reshape((-1, 2), order="C")
