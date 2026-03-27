import numpy as np
import time
from collections import OrderedDict

from urh.dev.native.Device import Device
from urh.dev.native.lib import hydrasdr
from urh.util.Logger import logger
from multiprocessing.connection import Connection


class HydraSDR(Device):
    DEVICE_LIB = hydrasdr
    ASYNCHRONOUS = True
    DEVICE_METHODS = Device.DEVICE_METHODS.copy()
    DEVICE_METHODS.update(
        {
            Device.Command.SET_FREQUENCY.name: "set_center_frequency",
            Device.Command.SET_BANDWIDTH.name: "set_bandwidth",
        }
    )

    DATA_TYPE = np.float32

    @property
    def has_multi_device_support(self):
        return True

    @classmethod
    def get_device_list(cls):
        return hydrasdr.get_device_list()

    @classmethod
    def setup_device(cls, ctrl_connection: Connection, device_identifier):
        if device_identifier:
            # Parse serial from "HydraSDR XXXXXXXXYYYYYYYY" format
            try:
                hex_str = device_identifier.replace("HydraSDR ", "").strip()
                serial = int(hex_str, 16)
                ret = hydrasdr.open_by_serial(serial)
            except (ValueError, TypeError):
                logger.warning(
                    f"HydraSDR: Could not parse "
                    f"'{device_identifier}', "
                    f"opening first device"
                )
                ret = hydrasdr.open()
        else:
            ret = hydrasdr.open()
        ctrl_connection.send("OPEN:" + str(ret))
        if ret == 0:
            # Set sample type early so the library builds the correct virtual rate table
            # before set_samplerate is called during init_device
            hydrasdr.set_sample_type_iq()
        return ret == 0

    @classmethod
    def shutdown_device(cls, ctrl_connection, is_tx=False):
        logger.debug("HydraSDR: closing device")
        ret = hydrasdr.stop_rx()
        ctrl_connection.send("Stop RX:" + str(ret))

        ret = hydrasdr.close()
        ctrl_connection.send("EXIT:" + str(ret))

        return True

    @classmethod
    def enter_async_receive_mode(
        cls, data_connection: Connection, ctrl_connection: Connection
    ):
        ret = hydrasdr.start_rx(data_connection.send_bytes)
        ctrl_connection.send("Start RX MODE:" + str(ret))
        return ret

    def __init__(
        self,
        center_freq,
        sample_rate,
        bandwidth,
        gain,
        if_gain=1,
        baseband_gain=1,
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
        self.success = 0

        self.bandwidth_is_adjustable = True

    @property
    def device_parameters(self) -> OrderedDict:
        return OrderedDict(
            [
                (self.Command.SET_FREQUENCY.name, self.frequency),
                (self.Command.SET_SAMPLE_RATE.name, self.sample_rate),
                (self.Command.SET_BANDWIDTH.name, self.bandwidth),
                (self.Command.SET_RF_GAIN.name, self.gain),
                (self.Command.SET_IF_GAIN.name, self.if_gain),
                (self.Command.SET_BB_GAIN.name, self.baseband_gain),
                ("identifier", self.device_serial),
            ]
        )

    @staticmethod
    def bytes_to_iq(buffer) -> np.ndarray:
        return np.frombuffer(
            buffer, dtype=np.float32
        ).reshape((-1, 2), order="C")
