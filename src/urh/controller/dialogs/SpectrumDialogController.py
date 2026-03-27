import numpy as np
from PyQt6.QtCore import QTimer, pyqtSlot, Qt
from PyQt6.QtGui import (
    QWheelEvent, QIcon, QPixmap, QResizeEvent, QPen, QColor,
    QPainterPath, QBrush, QFont,
)
from PyQt6.QtWidgets import (
    QGraphicsScene, QGraphicsView, QVBoxLayout,
    QHBoxLayout, QWidget, QLabel, QProgressBar, QFrame,
    QSpinBox,
)

from urh.controller.dialogs.SendRecvDialog import SendRecvDialog
from urh.dev.VirtualDevice import VirtualDevice, Mode
from urh.signalprocessing.Spectrogram import Spectrogram
from urh.ui.painting.FFTSceneManager import FFTSceneManager


class SpectrumDialogController(SendRecvDialog):
    def __init__(self, project_manager, parent=None, testing_mode=False):
        super().__init__(
            project_manager, is_tx=False, parent=parent, testing_mode=testing_mode
        )

        self.graphics_view = self.ui.graphicsViewFFT
        self.update_interval = 1
        self.ui.stackedWidget.setCurrentWidget(self.ui.page_spectrum)
        self.hide_receive_ui_items()
        self.hide_send_ui_items()

        self.setWindowTitle("Spectrum Analyzer")
        self.setWindowIcon(QIcon(":/icons/icons/spectrum.svg"))
        self.ui.btnStart.setToolTip(self.tr("Start"))
        self.ui.btnStop.setToolTip(self.tr("Stop"))

        self.scene_manager = FFTSceneManager(
            parent=self, graphic_view=self.graphics_view
        )
        self.graphics_view.setScene(self.scene_manager.scene)
        self.graphics_view.scene_manager = self.scene_manager

        self.ui.graphicsViewSpectrogram.setScene(QGraphicsScene())
        self.__clear_spectrogram()

        self._mod_counter = 0
        self.__setup_extras()

        self.gain_timer = QTimer(self)
        self.gain_timer.setSingleShot(True)
        self.if_gain_timer = QTimer(self)
        self.if_gain_timer.setSingleShot(True)
        self.bb_gain_timer = QTimer(self)
        self.bb_gain_timer.setSingleShot(True)

        self.create_connects()
        self.device_settings_widget.update_for_new_device(overwrite_settings=False)


    # ── Extra views ──────────────────────────────────────────

    def __setup_extras(self):
        layout = self.ui.page_spectrum.layout()

        row = QWidget()
        rl = QHBoxLayout(row)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(2)

        self._time_view = QGraphicsView()
        self._time_scene = QGraphicsScene()
        self._time_view.setScene(self._time_scene)
        self._time_view.setMaximumHeight(120)
        self._time_view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._time_view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        rl.addWidget(self._time_view, 2)

        self._const_view = QGraphicsView()
        self._const_scene = QGraphicsScene()
        self._const_view.setScene(self._const_scene)
        self._const_view.setMaximumHeight(120)
        self._const_view.setFixedWidth(120)
        self._const_view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._const_view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        rl.addWidget(self._const_view, 0)

        layout.addWidget(row)

        # Modulation bar
        bar = QFrame()
        bar.setMaximumHeight(28)
        h = QHBoxLayout(bar)
        h.setContentsMargins(4, 0, 4, 0)
        h.setSpacing(6)

        self._mod_label = QLabel("--")
        self._mod_label.setFont(QFont("Monospace", 9, QFont.Weight.Bold))
        self._mod_label.setFixedWidth(32)
        h.addWidget(self._mod_label)

        self._mod_bars = {}
        for name, color in [
            ("OOK", "#4CAF50"), ("ASK", "#FF9800"),
            ("FSK", "#2196F3"), ("PSK", "#9C27B0"),
        ]:
            lbl = QLabel(name)
            lbl.setFixedWidth(24)
            lbl.setStyleSheet(f"color:{color};font-size:9px;")
            pb = QProgressBar()
            pb.setRange(0, 100)
            pb.setValue(0)
            pb.setFixedHeight(10)
            pb.setFixedWidth(50)
            pb.setTextVisible(False)
            pb.setStyleSheet(
                f"QProgressBar::chunk{{background:{color};}}"
                "QProgressBar{background:#222;border:none;}"
            )
            h.addWidget(lbl)
            h.addWidget(pb)
            self._mod_bars[name] = pb

        h.addWidget(QLabel(" Trig:"))
        self._trigger_spin = QSpinBox()
        self._trigger_spin.setRange(-120, 0)
        self._trigger_spin.setValue(-40)
        self._trigger_spin.setSuffix(" dB")
        self._trigger_spin.setFixedWidth(72)
        h.addWidget(self._trigger_spin)

        h.addStretch()

        layout.addWidget(bar)

    # ── Spectrogram ──────────────────────────────────────────

    def __clear_spectrogram(self):
        self.ui.graphicsViewSpectrogram.scene().clear()
        ws = Spectrogram.DEFAULT_FFT_WINDOW_SIZE
        self.ui.graphicsViewSpectrogram.scene().setSceneRect(0, 0, ws, 20 * ws)
        self.spectrogram_y_pos = 0
        self.ui.graphicsViewSpectrogram.fitInView(
            self.ui.graphicsViewSpectrogram.sceneRect()
        )

    def __update_spectrogram(self):
        spectrogram = Spectrogram(self.device.data)
        spectrogram.data_min = -80
        spectrogram.data_max = 10
        scene = self.ui.graphicsViewSpectrogram.scene()
        pixmap = QPixmap.fromImage(
            spectrogram.create_spectrogram_image(transpose=True)
        )
        item = scene.addPixmap(pixmap)
        item.moveBy(0, self.spectrogram_y_pos)
        self.spectrogram_y_pos += pixmap.height()
        if self.spectrogram_y_pos >= scene.sceneRect().height():
            scene.setSceneRect(
                0, 0, Spectrogram.DEFAULT_FFT_WINDOW_SIZE,
                self.spectrogram_y_pos,
            )
            self.ui.graphicsViewSpectrogram.ensureVisible(item)

    # ── Time Domain ──────────────────────────────────────────

    def __update_time(self, iq):
        if iq is None or len(iq) < 2:
            return
        try:
            self._time_scene.clear()
            w = max(self._time_view.viewport().width(), 40)
            h = max(self._time_view.viewport().height(), 40)
            mid = h / 2.0
            i_d = np.real(iq).astype(np.float64)
            q_d = np.imag(iq).astype(np.float64)
            pk = max(float(np.max(np.abs(i_d))), float(np.max(np.abs(q_d))), 1e-10)
            sy = (h * 0.44) / pk
            sx = w / max(len(iq) - 1, 1)
            step = max(1, len(iq) // w)
            for data, col in [(i_d, QColor(0, 200, 255)), (q_d, QColor(255, 140, 0))]:
                p = QPainterPath()
                p.moveTo(0, mid - float(data[0]) * sy)
                for j in range(step, len(data), step):
                    p.lineTo(j * sx, mid - float(data[j]) * sy)
                self._time_scene.addPath(p, QPen(col, 1))
            self._time_scene.addLine(
                0, mid, w, mid,
                QPen(QColor(80, 80, 80), 0.5, Qt.PenStyle.DashLine),
            )
            self._time_scene.setSceneRect(0, 0, w, h)
            self._time_view.fitInView(0, 0, w, h, Qt.AspectRatioMode.IgnoreAspectRatio)
        except Exception:
            pass

    # ── Constellation ────────────────────────────────────────

    def __update_const(self, iq):
        if iq is None or len(iq) < 2:
            return
        try:
            self._const_scene.clear()
            sz = max(self._const_view.viewport().width(), 40)
            cx = cy = sz / 2.0
            i_d = np.real(iq).astype(np.float64)
            q_d = np.imag(iq).astype(np.float64)
            pk = max(float(np.max(np.abs(i_d))), float(np.max(np.abs(q_d))), 1e-10)
            sc = (sz * 0.44) / pk
            pg = QPen(QColor(60, 60, 60), 0.5, Qt.PenStyle.DashLine)
            self._const_scene.addLine(0, cy, sz, cy, pg)
            self._const_scene.addLine(cx, 0, cx, sz, pg)
            br = QBrush(QColor(0, 255, 100, 140))
            pn = QPen(Qt.PenStyle.NoPen)
            step = max(1, len(iq) // 512)
            for j in range(0, len(iq), step):
                self._const_scene.addEllipse(
                    cx + float(i_d[j]) * sc - 1,
                    cy - float(q_d[j]) * sc - 1,
                    2, 2, pn, br,
                )
            self._const_scene.setSceneRect(0, 0, sz, sz)
            self._const_view.fitInView(0, 0, sz, sz, Qt.AspectRatioMode.IgnoreAspectRatio)
        except Exception:
            pass

    # ── Modulation detection ─────────────────────────────────

    def __update_mod(self, iq, fft_x, fft_y):
        """Detect modulation using IQ samples AND the already-computed FFT."""
        self._mod_counter += 1
        if self._mod_counter % 6 != 0:
            return
        if iq is None or len(iq) < 4:
            return
        try:
            mag = np.abs(iq)
            mx = float(np.max(mag))
            if mx < 1e-10:
                return

            pwr_db = float(20 * np.log10(mx + 1e-20))
            if pwr_db < self._trigger_spin.value():
                self._mod_label.setText("--")
                self._mod_label.setStyleSheet("color:gray;")
                for b in self._mod_bars.values():
                    b.setValue(0)
                return

            mn = mag / mx
            zero_r = float(np.sum(mn < 0.1)) / len(iq)
            amp_cv = float(np.std(mn)) / (float(np.mean(mn)) + 1e-10)

            # ── FSK detection from the REAL FFT data ──
            # Use the already-computed FFT (same data the display shows).
            # This is the most reliable FSK indicator: two visible peaks.
            nfp = 0
            if fft_y is not None and len(fft_y) > 4:
                fft_db = 20 * np.log10(np.where(fft_y > 0, fft_y, 1e-20))
                fft_max_db = float(np.max(fft_db))
                # Peaks must be within 30dB of max and at least 2% of FFT width apart
                peak_thr = fft_max_db - 30
                min_dist = max(len(fft_db) // 50, 2)
                peaks = []
                for i in range(1, len(fft_db) - 1):
                    if (
                        fft_db[i] > fft_db[i - 1]
                        and fft_db[i] > fft_db[i + 1]
                        and fft_db[i] > peak_thr
                    ):
                        if all(abs(i - p) >= min_dist for p in peaks):
                            peaks.append(i)
                nfp = len(peaks)

            # ── Instantaneous frequency histogram ──
            ph = np.diff(np.unwrap(np.angle(iq)))
            fp = 0
            if len(ph) > 4:
                nbins = min(32, max(4, len(ph) // 4))
                hist, _ = np.histogram(ph, bins=nbins)
                hs = np.convolve(hist.astype(float), [1, 3, 1], mode="same")
                thr = float(np.max(hs)) * 0.12
                for i in range(1, len(hs) - 1):
                    if hs[i] > hs[i - 1] and hs[i] > hs[i + 1] and hs[i] > thr:
                        fp += 1

            # ── PSK: only sharp jumps close to pi/2 or pi ──
            # FSK has smooth phase ramps, PSK has abrupt discontinuities.
            # Use second derivative of phase to distinguish:
            # PSK jumps create spikes in |diff(diff(phase))|
            psk_score_raw = 0
            if len(ph) > 4:
                ph2 = np.diff(ph)  # second derivative
                # Sharp jumps: |ph2| > 1.5 (FSK ramps give |ph2| ~ 0)
                n_sharp = int(np.sum(np.abs(ph2) > 1.5))
                psk_score_raw = n_sharp / max(len(ph2), 1)

            # ── Constellation shape analysis ──
            # FSK: ring/circle (constant amplitude, varying phase)
            # PSK: discrete clusters
            # OOK/ASK: radial spread through origin
            passes_origin = float(np.sum(mn < 0.15)) / len(iq)

            # ── Scoring ──
            ook = min(100, int(zero_r * 300 + max(0, amp_cv - 0.20) * 120))
            ask = 0
            if zero_r < 0.08:
                ask = min(100, int(max(0, amp_cv - 0.12) * 200))

            fsk = 0
            if amp_cv < 0.30:
                fsk_base = 0
                if nfp >= 2:
                    fsk_base += 55  # two FFT peaks = strong FSK
                if fp >= 2:
                    fsk_base += 40  # two freq histogram peaks
                if passes_origin < 0.05:
                    fsk_base += 10  # doesn't pass through 0 = constant envelope
                fsk_base += int(max(0, 0.20 - amp_cv) * 20)
                fsk = min(100, fsk_base)

            psk = 0
            # PSK only if NO FSK features and sharp phase discontinuities
            if amp_cv < 0.30 and nfp < 2 and fp < 2 and fsk < 20:
                psk = min(100, int(
                    psk_score_raw * 600
                    + max(0, 0.15 - amp_cv) * 50
                ))

            tot = ook + ask + fsk + psk
            if tot > 0:
                ook, ask, fsk, psk = (int(v * 100 / tot) for v in (ook, ask, fsk, psk))

            self._mod_bars["OOK"].setValue(ook)
            self._mod_bars["ASK"].setValue(ask)
            self._mod_bars["FSK"].setValue(fsk)
            self._mod_bars["PSK"].setValue(psk)

            sc = {"OOK": ook, "ASK": ask, "FSK": fsk, "PSK": psk}
            dom = max(sc, key=sc.get)
            self._mod_label.setText(dom)
            cl = {"OOK": "#4CAF50", "ASK": "#FF9800", "FSK": "#2196F3", "PSK": "#9C27B0"}
            self._mod_label.setStyleSheet(f"color:{cl[dom]};")
        except Exception:
            pass

    # ── Main update ──────────────────────────────────────────

    def update_view(self):
        if super().update_view():
            x, y = self.device.spectrum
            if x is None or y is None:
                return

            # FFT display (original, untouched)
            self.scene_manager.scene.frequencies = x
            self.scene_manager.plot_data = y
            self.scene_manager.init_scene()
            self.scene_manager.show_full_scene()
            self.graphics_view.fitInView(self.graphics_view.sceneRect())

            # Spectrogram
            try:
                self.__update_spectrogram()
            except MemoryError:
                self.__clear_spectrogram()
                self.__update_spectrogram()

            # Get IQ samples from device buffer.
            # In spectrum mode, receive_buffer is circular. Use
            # current_index to find which portion has real data
            # (the rest may be zero-padded from initialization).
            iq = np.array([], dtype=np.complex64)
            iq_info = ""
            try:
                d = self.device.data
                if d is not None and len(d) > 0:
                    # Get the write position in the circular buffer
                    ci = 0
                    try:
                        ci = self.device.current_index
                    except Exception:
                        ci = len(d)

                    if ci <= 0:
                        # current_index=0 means buffer just wrapped —
                        # entire buffer has valid data from previous fill
                        ci = len(d)

                    # Extract the filled portion as complex64
                    filled = d[:ci]
                    if hasattr(filled, "as_complex64"):
                        iq = filled.as_complex64()
                    elif isinstance(filled, np.ndarray) and np.iscomplexobj(filled):
                        iq = np.array(filled, dtype=np.complex64)
                    elif isinstance(filled, np.ndarray) and filled.ndim == 2:
                        iq = filled[:, 0].astype(np.float32) + 1j * filled[:, 1].astype(np.float32)
                    elif isinstance(filled, np.ndarray):
                        iq = filled[0::2].astype(np.float32) + 1j * filled[1::2].astype(np.float32)

                    # Limit to last 2048 samples for performance
                    if len(iq) > 2048:
                        iq = iq[-2048:]

                    iq_info = f"IQ:{len(iq)} ci:{ci}"
                else:
                    iq_info = "IQ:no data"
            except Exception as e:
                iq_info = f"IQ:err {type(e).__name__}"
                iq = np.array([], dtype=np.complex64)

            # Time domain + constellation + modulation
            if len(iq) >= 2:
                self.__update_time(iq)
                self.__update_const(iq)
                self.__update_mod(iq, x, y)

    # ── Unchanged overrides ──────────────────────────────────

    def _eliminate_graphic_view(self):
        super()._eliminate_graphic_view()
        sg = self.ui.graphicsViewSpectrogram
        if sg and sg.scene() is not None:
            sg.scene().clear()
            sg.scene().setParent(None)
            sg.setScene(None)
        self.ui.graphicsViewSpectrogram = None

    def create_connects(self):
        super().create_connects()
        self.graphics_view.freq_clicked.connect(self.on_graphics_view_freq_clicked)
        self.graphics_view.wheel_event_triggered.connect(
            self.on_graphics_view_wheel_event_triggered
        )
        self.device_settings_widget.ui.sliderGain.valueChanged.connect(
            self.on_slider_gain_value_changed
        )
        self.device_settings_widget.ui.sliderBasebandGain.valueChanged.connect(
            self.on_slider_baseband_gain_value_changed
        )
        self.device_settings_widget.ui.sliderIFGain.valueChanged.connect(
            self.on_slider_if_gain_value_changed
        )
        self.device_settings_widget.ui.spinBoxFreq.editingFinished.connect(
            self.on_spinbox_frequency_editing_finished
        )
        self.gain_timer.timeout.connect(
            self.device_settings_widget.ui.spinBoxGain.editingFinished.emit
        )
        self.if_gain_timer.timeout.connect(
            self.device_settings_widget.ui.spinBoxIFGain.editingFinished.emit
        )
        self.bb_gain_timer.timeout.connect(
            self.device_settings_widget.ui.spinBoxBasebandGain.editingFinished.emit
        )

    def resizeEvent(self, event: QResizeEvent):
        sg = self.ui.graphicsViewSpectrogram
        if sg and sg.sceneRect():
            sg.fitInView(sg.sceneRect())

    def init_device(self):
        self.device = VirtualDevice(
            self.backend_handler,
            self.selected_device_name,
            Mode.spectrum,
            device_ip="192.168.10.2",
            parent=self,
        )
        self._create_device_connects()

    @pyqtSlot(QWheelEvent)
    def on_graphics_view_wheel_event_triggered(self, event: QWheelEvent):
        self.ui.sliderYscale.wheelEvent(event)

    @pyqtSlot(float)
    def on_graphics_view_freq_clicked(self, freq: float):
        self.device_settings_widget.ui.spinBoxFreq.setValue(freq)
        self.device_settings_widget.ui.spinBoxFreq.editingFinished.emit()

    @pyqtSlot()
    def on_spinbox_frequency_editing_finished(self):
        frequency = self.device_settings_widget.ui.spinBoxFreq.value()
        self.device.frequency = frequency
        self.scene_manager.scene.center_freq = frequency
        self.scene_manager.clear_path()
        self.scene_manager.clear_peak()

    @pyqtSlot()
    def on_start_clicked(self):
        super().on_start_clicked()
        self.device.start()

    @pyqtSlot()
    def on_device_started(self):
        self.ui.graphicsViewSpectrogram.fitInView(
            self.ui.graphicsViewSpectrogram.scene().sceneRect()
        )
        super().on_device_started()
        self.device_settings_widget.ui.spinBoxPort.setEnabled(False)
        self.device_settings_widget.ui.lineEditIP.setEnabled(False)
        self.device_settings_widget.ui.cbDevice.setEnabled(False)
        self.ui.btnStart.setEnabled(False)

    @pyqtSlot()
    def on_device_stopped(self):
        self.device_settings_widget.ui.spinBoxPort.setEnabled(True)
        self.device_settings_widget.ui.lineEditIP.setEnabled(True)
        self.device_settings_widget.ui.cbDevice.setEnabled(True)
        super().on_device_stopped()

    @pyqtSlot()
    def on_clear_clicked(self):
        self.__clear_spectrogram()
        self.scene_manager.clear_path()
        self.scene_manager.clear_peak()
        self._time_scene.clear()
        self._const_scene.clear()

    @pyqtSlot(int)
    def on_slider_gain_value_changed(self, value: int):
        self.gain_timer.start(250)

    @pyqtSlot(int)
    def on_slider_if_gain_value_changed(self, value: int):
        self.if_gain_timer.start(250)

    @pyqtSlot(int)
    def on_slider_baseband_gain_value_changed(self, value: int):
        self.bb_gain_timer.start(250)
