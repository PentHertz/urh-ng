from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QGroupBox,
    QFormLayout,
    QTextEdit,
    QProgressBar,
    QMessageBox,
    QTabWidget,
    QWidget,
)

from urh.util.KeeLoq import (
    decrypt,
    encrypt,
    encode_packet,
    decode_packet,
    normal_learning,
    secure_learning,
    magic_xor_learning,
    faac_learning,
    bruteforce_manufacturer_key,
    find_manufacturer_key_from_device_key,
    LEARNING_MODES,
    COMMON_MANUFACTURER_KEYS,
    MANUFACTURER_CODES,
)
from urh.util.CryptoToolkit import (
    tea_encrypt,
    tea_decrypt,
    aes128_encrypt,
    aes128_decrypt,
    aut64_encrypt,
    aut64_decrypt,
    kia_v5_mixer_decrypt,
    mitsubishi_v0_scramble,
    mitsubishi_v0_descramble,
    ford_v0_calculate_crc,
    ford_v0_calculate_bs,
    crc8,
    crc16_ccitt,
    CIPHER_INFO,
    VAG_TEA_KEY,
)


class BruteforceThread(QThread):
    progress = pyqtSignal(int, str)
    found = pyqtSignal(int, dict, str)
    finished_signal = pyqtSignal()

    def __init__(
        self, encrypted, serial, learning_modes,
        key_start, key_end, encrypted2=None,
    ):
        super().__init__()
        self.encrypted = encrypted
        self.encrypted2 = encrypted2
        self.serial = serial
        self.learning_modes = learning_modes
        self.key_start = key_start
        self.key_end = key_end
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        tried = 0
        expected_disc = self.serial & 0x3FF
        for key in range(self.key_start, self.key_end):
            if self._stop:
                break
            for mode in self.learning_modes:
                r1 = decode_packet(
                    self.encrypted, self.serial, key, mode,
                )
                tried += 1
                if r1["disc"] != expected_disc:
                    continue
                if self.encrypted2 is not None:
                    r2 = decode_packet(
                        self.encrypted2, self.serial,
                        key, mode,
                    )
                    if r2["disc"] != expected_disc:
                        continue
                    diff = abs(
                        r2["counter"] - r1["counter"]
                    )
                    if diff == 0 or diff > 100:
                        continue
                r1["serial_match"] = True
                self.found.emit(key, r1, mode)
                return
            if tried % 50000 == 0:
                self.progress.emit(tried, f"0x{key:016X}")
        self.finished_signal.emit()


class KeeLoqDialog(QDialog):
    """KeeLoq decoder and encoder with key bruteforce."""

    def __init__(
        self, parent=None, encrypted=0, serial=0,
        cipher_hint="",
    ):
        super().__init__(parent)
        self.setWindowTitle("Crypto Toolkit")
        self.setMinimumSize(680, 720)
        self._bruteforce_thread = None
        self._encrypted = encrypted
        self._serial = serial
        self._cipher_hint = cipher_hint
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        self._last_decode = None
        self._tabs = QTabWidget()
        self._tabs.addTab(
            self._build_decoder_tab(), "KeeLoq Decoder"
        )
        self._tabs.addTab(
            self._build_encoder_tab(), "KeeLoq Encoder"
        )
        self._tabs.addTab(
            self._build_crypto_tab(), "Crypto Toolkit"
        )
        layout.addWidget(self._tabs)

        # Shared results
        res_group = QGroupBox("Results")
        res_layout = QVBoxLayout(res_group)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        res_layout.addWidget(self.result_text)
        layout.addWidget(res_group)

        # Auto-select tab based on cipher hint
        if self._cipher_hint:
            if self._cipher_hint == "KeeLoq":
                self._tabs.setCurrentIndex(0)
            else:
                # Go to Crypto Toolkit tab and select cipher
                self._tabs.setCurrentIndex(2)
                for i in range(self.combo_cipher.count()):
                    if self.combo_cipher.itemData(i) == self._cipher_hint:
                        self.combo_cipher.setCurrentIndex(i)
                        break
                # Pre-fill data from encrypted field
                if self._encrypted:
                    self.edit_crypto_data.setText(
                        f"{self._encrypted:08X}"
                    )

    # ── Decoder Tab ──────────────────────────────────

    def _build_decoder_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Packet data
        input_group = QGroupBox("Packet Data (LSB/BE hex)")
        form = QFormLayout(input_group)
        self.edit_encrypted = QLineEdit(
            f"{self._encrypted:08X}"
        )
        self.edit_encrypted.setPlaceholderText("32-bit (hex)")
        form.addRow("Encrypted #1:", self.edit_encrypted)
        self.edit_encrypted2 = QLineEdit()
        self.edit_encrypted2.setPlaceholderText(
            "2nd capture for bruteforce (optional)"
        )
        form.addRow("Encrypted #2:", self.edit_encrypted2)
        self.edit_serial = QLineEdit(
            f"{self._serial:07X}"
        )
        self.edit_serial.setPlaceholderText("28-bit (hex)")
        form.addRow("Serial/ID:", self.edit_serial)
        layout.addWidget(input_group)

        # Decrypt
        key_group = QGroupBox("Decrypt")
        key_layout = QVBoxLayout(key_group)

        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Key type:"))
        self.combo_key_type = QComboBox()
        self.combo_key_type.addItem(
            "Device Key (direct)", "device"
        )
        self.combo_key_type.addItem(
            "Manufacturer Key (derive)", "manufacturer"
        )
        type_row.addWidget(self.combo_key_type)
        key_layout.addLayout(type_row)

        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("Learning:"))
        self.combo_learning = QComboBox()
        for mid, mname in LEARNING_MODES.items():
            self.combo_learning.addItem(mname, mid)
        mode_row.addWidget(self.combo_learning)
        key_layout.addLayout(mode_row)

        kr = QHBoxLayout()
        kr.addWidget(QLabel("Key (hex):"))
        self.edit_key = QLineEdit()
        self.edit_key.setPlaceholderText("64-bit (hex)")
        kr.addWidget(self.edit_key)
        key_layout.addLayout(kr)

        preset_row = QHBoxLayout()
        self.combo_preset = QComboBox()
        self.combo_preset.addItem("Known keys...")
        for name, key in COMMON_MANUFACTURER_KEYS.items():
            self.combo_preset.addItem(
                f"{name} (0x{key:016X})", key
            )
        self.combo_preset.currentIndexChanged.connect(
            self._on_preset_selected
        )
        preset_row.addWidget(self.combo_preset)
        key_layout.addLayout(preset_row)

        btn_row = QHBoxLayout()
        self.btn_decrypt = QPushButton("Decrypt")
        self.btn_decrypt.clicked.connect(self.on_decrypt)
        btn_row.addWidget(self.btn_decrypt)
        self.btn_try_all = QPushButton("Try All Common Keys")
        self.btn_try_all.clicked.connect(self.on_try_all)
        btn_row.addWidget(self.btn_try_all)
        self.btn_find_mfg = QPushButton("Find Mfg Key")
        self.btn_find_mfg.clicked.connect(
            self.on_find_mfg_key
        )
        btn_row.addWidget(self.btn_find_mfg)
        self.btn_to_encoder = QPushButton(
            "Copy to Encoder >>>"
        )
        self.btn_to_encoder.clicked.connect(
            self.on_copy_to_encoder
        )
        self.btn_to_encoder.setEnabled(False)
        btn_row.addWidget(self.btn_to_encoder)
        key_layout.addLayout(btn_row)

        layout.addWidget(key_group)

        # Bruteforce
        bf_group = QGroupBox(
            "Bruteforce (use 2 captures for reliability)"
        )
        bf_layout = QVBoxLayout(bf_group)
        rr = QHBoxLayout()
        rr.addWidget(QLabel("Range:"))
        self.edit_start = QLineEdit("0000000000000000")
        self.edit_start.setMaximumWidth(140)
        rr.addWidget(self.edit_start)
        rr.addWidget(QLabel("-"))
        self.edit_end = QLineEdit("000000000000FFFF")
        self.edit_end.setMaximumWidth(140)
        rr.addWidget(self.edit_end)
        bf_layout.addLayout(rr)
        bbr = QHBoxLayout()
        self.btn_bf = QPushButton("Bruteforce (all modes)")
        self.btn_bf.clicked.connect(self.on_bruteforce)
        bbr.addWidget(self.btn_bf)
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.on_stop)
        bbr.addWidget(self.btn_stop)
        bf_layout.addLayout(bbr)
        self.progress = QProgressBar()
        self.progress.setFormat("Idle")
        bf_layout.addWidget(self.progress)
        layout.addWidget(bf_group)

        return tab

    # ── Encoder Tab ──────────────────────────────────

    def _build_encoder_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        form = QFormLayout()
        self.edit_enc_serial = QLineEdit(
            f"{self._serial:07X}"
        )
        self.edit_enc_serial.setPlaceholderText(
            "28-bit (hex)"
        )
        form.addRow("Serial (hex):", self.edit_enc_serial)

        self.edit_enc_button = QLineEdit("2")
        self.edit_enc_button.setPlaceholderText("0-15")
        self.edit_enc_button.setMaximumWidth(60)
        form.addRow(
            "Button (status bits):", self.edit_enc_button
        )

        self.edit_enc_counter = QLineEdit("1")
        self.edit_enc_counter.setPlaceholderText("0-65535")
        self.edit_enc_counter.setMaximumWidth(100)
        form.addRow("Counter:", self.edit_enc_counter)

        self.edit_enc_ovr = QLineEdit("0")
        self.edit_enc_ovr.setPlaceholderText("0-3")
        self.edit_enc_ovr.setMaximumWidth(40)
        form.addRow("OVR (overflow):", self.edit_enc_ovr)

        self.edit_enc_disc = QLineEdit("")
        self.edit_enc_disc.setPlaceholderText(
            "auto = serial & 0x3FF"
        )
        self.edit_enc_disc.setMaximumWidth(80)
        form.addRow("DISC (hex):", self.edit_enc_disc)

        self.edit_enc_key = QLineEdit()
        self.edit_enc_key.setPlaceholderText("64-bit (hex)")
        form.addRow("Key (hex):", self.edit_enc_key)
        layout.addLayout(form)

        kt_row = QHBoxLayout()
        kt_row.addWidget(QLabel("Key type:"))
        self.combo_enc_key_type = QComboBox()
        self.combo_enc_key_type.addItem(
            "Device Key", "device"
        )
        self.combo_enc_key_type.addItem(
            "Manufacturer Key", "manufacturer"
        )
        kt_row.addWidget(self.combo_enc_key_type)
        kt_row.addWidget(QLabel("Learning:"))
        self.combo_enc_learning = QComboBox()
        for mid, mname in LEARNING_MODES.items():
            self.combo_enc_learning.addItem(mname, mid)
        kt_row.addWidget(self.combo_enc_learning)
        layout.addLayout(kt_row)

        self.btn_encode = QPushButton(
            "Encrypt / Generate Packet"
        )
        self.btn_encode.clicked.connect(self.on_encode)
        layout.addWidget(self.btn_encode)

        layout.addStretch()
        return tab

    # ── Crypto Toolkit Tab ───────────────────────────

    def _build_crypto_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Cipher selector
        cipher_row = QHBoxLayout()
        cipher_row.addWidget(QLabel("Cipher:"))
        self.combo_cipher = QComboBox()
        for cid, info in CIPHER_INFO.items():
            self.combo_cipher.addItem(
                f"{info['name']} — {info['used_by']}", cid
            )
        self.combo_cipher.currentIndexChanged.connect(
            self._on_cipher_changed
        )
        cipher_row.addWidget(self.combo_cipher)
        layout.addLayout(cipher_row)

        # Direction
        dir_row = QHBoxLayout()
        dir_row.addWidget(QLabel("Operation:"))
        self.combo_crypto_dir = QComboBox()
        self.combo_crypto_dir.addItem("Decrypt", "decrypt")
        self.combo_crypto_dir.addItem("Encrypt", "encrypt")
        dir_row.addWidget(self.combo_crypto_dir)
        layout.addLayout(dir_row)

        # Input
        form = QFormLayout()
        self.edit_crypto_data = QLineEdit()
        self.edit_crypto_data.setPlaceholderText("hex bytes")
        form.addRow("Data (hex):", self.edit_crypto_data)

        self.edit_crypto_key = QLineEdit()
        self.edit_crypto_key.setPlaceholderText("hex bytes")
        form.addRow("Key (hex):", self.edit_crypto_key)

        self.edit_crypto_extra = QLineEdit()
        self.edit_crypto_extra.setPlaceholderText(
            "optional (counter, IV, etc.)"
        )
        form.addRow("Extra (hex):", self.edit_crypto_extra)
        layout.addLayout(form)

        # Known keys
        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("Known keys:"))
        self.combo_crypto_preset = QComboBox()
        self.combo_crypto_preset.addItem("None")
        self.combo_crypto_preset.addItem(
            "VAG TEA: 0B46502D 5E253718 2BF93A19 622C1206",
            "0B46502D5E2537182BF93A19622C1206",
        )
        self.combo_crypto_preset.currentIndexChanged.connect(
            self._on_crypto_preset
        )
        preset_row.addWidget(self.combo_crypto_preset)
        layout.addLayout(preset_row)

        self.btn_crypto_run = QPushButton("Run")
        self.btn_crypto_run.clicked.connect(self.on_crypto_run)
        layout.addWidget(self.btn_crypto_run)

        # Info label
        self.lbl_cipher_info = QLabel("")
        self.lbl_cipher_info.setWordWrap(True)
        layout.addWidget(self.lbl_cipher_info)
        self._on_cipher_changed(0)

        layout.addStretch()
        return tab

    def _on_cipher_changed(self, _):
        cid = self.combo_cipher.currentData()
        if cid and cid in CIPHER_INFO:
            info = CIPHER_INFO[cid]
            self.lbl_cipher_info.setText(
                f"Key: {info['key_bits']} bits, "
                f"Block: {info['block_bits']} bits"
            )

    def _on_crypto_preset(self, index):
        if index > 0:
            val = self.combo_crypto_preset.itemData(index)
            if val:
                self.edit_crypto_key.setText(val)

    def on_crypto_run(self):
        cid = self.combo_cipher.currentData()
        direction = self.combo_crypto_dir.currentData()
        data_hex = self.edit_crypto_data.text().strip()
        key_hex = self.edit_crypto_key.text().strip()
        extra_hex = self.edit_crypto_extra.text().strip()

        try:
            data_bytes = bytes.fromhex(
                data_hex.replace(" ", "")
            )
        except ValueError:
            QMessageBox.warning(
                self, "Error", "Invalid data (hex)"
            )
            return

        key_bytes = b""
        if key_hex:
            try:
                key_bytes = bytes.fromhex(
                    key_hex.replace(" ", "")
                )
            except ValueError:
                QMessageBox.warning(
                    self, "Error", "Invalid key (hex)"
                )
                return

        lines = [f"Cipher: {CIPHER_INFO.get(cid, {}).get('name', cid)}"]
        lines.append(f"Operation: {direction}")
        lines.append(f"Data in:  {data_bytes.hex()}")
        if key_bytes:
            lines.append(f"Key:      {key_bytes.hex()}")
        lines.append("")

        try:
            result = self._run_cipher(
                cid, direction, data_bytes,
                key_bytes, extra_hex,
            )
            lines.append(f"Result:   {result}")
        except Exception as e:
            lines.append(f"Error: {e}")

        self.result_text.setPlainText("\n".join(lines))

    def _run_cipher(
        self, cid, direction, data, key, extra
    ):
        if cid == "TEA":
            if len(data) != 8:
                raise ValueError("TEA needs 8 bytes data")
            if len(key) != 16:
                raise ValueError("TEA needs 16 bytes key")
            v0 = int.from_bytes(data[:4], "big")
            v1 = int.from_bytes(data[4:], "big")
            k = [
                int.from_bytes(key[i:i + 4], "big")
                for i in range(0, 16, 4)
            ]
            if direction == "decrypt":
                r0, r1 = tea_decrypt(v0, v1, k)
            else:
                r0, r1 = tea_encrypt(v0, v1, k)
            return f"{r0:08X} {r1:08X}"

        elif cid == "AES-128":
            if len(data) != 16:
                raise ValueError("AES needs 16 bytes data")
            if len(key) != 16:
                raise ValueError("AES needs 16 bytes key")
            if direction == "decrypt":
                r = aes128_decrypt(list(data), list(key))
            else:
                r = aes128_encrypt(list(data), list(key))
            return bytes(r).hex()

        elif cid == "AUT64":
            if len(data) != 8:
                raise ValueError("AUT64 needs 8 bytes data")
            if len(key) != 8:
                raise ValueError("AUT64 needs 8 bytes key")
            # Default identity S-box and P-box
            sbox = list(range(16))
            pbox = list(range(8))
            if direction == "decrypt":
                r = aut64_decrypt(
                    list(data), list(key), sbox, pbox
                )
            else:
                r = aut64_encrypt(
                    list(data), list(key), sbox, pbox
                )
            return bytes(r).hex()

        elif cid == "KIA-V5-Mixer":
            if len(data) != 4:
                raise ValueError("Mixer needs 4 bytes data")
            if len(key) != 8:
                raise ValueError("Mixer needs 8 bytes key")
            enc_val = int.from_bytes(data, "big")
            counter = kia_v5_mixer_decrypt(
                enc_val, list(key)
            )
            return f"Counter: {counter} (0x{counter:04X})"

        elif cid == "Mitsubishi-XOR":
            if len(data) < 8:
                raise ValueError("Need at least 8 bytes")
            cnt = 0
            if extra:
                cnt = int(extra, 16)
            if direction == "decrypt":
                r = mitsubishi_v0_descramble(
                    list(data), cnt
                )
            else:
                r = mitsubishi_v0_scramble(
                    list(data), cnt
                )
            return bytes(r).hex()

        elif cid == "Ford-GF2-CRC":
            if len(data) < 9:
                # Pad to 9 bytes
                data = data + b"\x00" * (9 - len(data))
            c = ford_v0_calculate_crc(list(data))
            return f"CRC: 0x{c:02X}"

        elif cid == "KeeLoq":
            if len(data) != 4:
                raise ValueError(
                    "KeeLoq needs 4 bytes data"
                )
            if len(key) != 8:
                raise ValueError(
                    "KeeLoq needs 8 bytes key"
                )
            from urh.util.KeeLoq import (
                encrypt as kl_enc,
                decrypt as kl_dec,
            )

            d = int.from_bytes(data, "big")
            k = int.from_bytes(key, "big")
            if direction == "decrypt":
                r = kl_dec(d, k)
            else:
                r = kl_enc(d, k)
            return f"0x{r:08X}"

        else:
            raise ValueError(f"Unknown cipher: {cid}")

    # ── Handlers ─────────────────────────────────────

    def on_copy_to_encoder(self):
        """Copy last decode result to encoder tab fields."""
        d = self._last_decode
        if not d:
            return
        self.edit_enc_serial.setText(
            f"{d['serial']:07X}"
        )
        self.edit_enc_button.setText(str(d["button"]))
        self.edit_enc_counter.setText(
            str(d["counter"] + 1)
        )
        self.edit_enc_ovr.setText(str(d["ovr"]))
        self.edit_enc_disc.setText(
            f"{d['disc']:03X}"
        )
        self.edit_enc_key.setText(
            f"{d['device_key']:016X}"
        )
        self.combo_enc_key_type.setCurrentIndex(0)
        self._tabs.setCurrentIndex(1)

    def _on_preset_selected(self, index):
        if index > 0:
            key = self.combo_preset.itemData(index)
            self.edit_key.setText(f"{key:016X}")
            self.combo_key_type.setCurrentIndex(1)

    def _parse_packet(self):
        try:
            enc = int(
                self.edit_encrypted.text().strip(), 16
            )
        except ValueError:
            QMessageBox.warning(
                self, "Error", "Invalid encrypted (hex)"
            )
            return None
        try:
            ser = int(
                self.edit_serial.text().strip(), 16
            )
        except ValueError:
            QMessageBox.warning(
                self, "Error", "Invalid serial (hex)"
            )
            return None
        return enc, ser

    def on_decrypt(self):
        pkt = self._parse_packet()
        if not pkt:
            return
        enc, ser = pkt
        try:
            key = int(self.edit_key.text().strip(), 16)
        except ValueError:
            QMessageBox.warning(
                self, "Error", "Invalid key (hex)"
            )
            return
        key_type = self.combo_key_type.currentData()
        mode = self.combo_learning.currentData()

        if key_type == "device":
            decrypted = decrypt(enc, key)
            result = {
                "button": (decrypted >> 28) & 0xF,
                "ovr": (decrypted >> 26) & 0x3,
                "disc": (decrypted >> 16) & 0x3FF,
                "counter": decrypted & 0xFFFF,
                "raw": decrypted,
                "device_key": key,
                "valid": ((decrypted >> 16) & 0x3FF)
                == (ser & 0x3FF),
            }
            self._show_full_result(
                enc, ser, "device", result
            )
        else:
            result = decode_packet(enc, ser, key, mode)
            self._show_full_result(
                enc, ser, "manufacturer", result,
                mfg_key=key, mode=mode,
            )

    def on_find_mfg_key(self):
        pkt = self._parse_packet()
        if not pkt:
            return
        _, ser = pkt
        try:
            dev_key = int(
                self.edit_key.text().strip(), 16
            )
        except ValueError:
            QMessageBox.warning(
                self, "Error",
                "Enter device key in the Key field",
            )
            return

        lines = [
            f"Finding manufacturer key for:",
            f"  Device key: 0x{dev_key:016X}",
            f"  Serial: 0x{ser:07X}",
            "",
        ]

        for mode_name, mode_fn, mode_id in [
            ("Simple", lambda s, k: k, "simple"),
            ("Normal", normal_learning, "normal"),
            ("Magic XOR", magic_xor_learning, "magic_xor"),
        ]:
            lines.append(f"Checking {mode_name}...")
            for name, mfg in COMMON_MANUFACTURER_KEYS.items():
                if mode_id == "simple":
                    derived = mfg
                else:
                    derived = mode_fn(ser, mfg)
                if derived == dev_key:
                    lines.append(f"  FOUND: {name}")
                    lines.append(
                        f"  Mfg Key: 0x{mfg:016X}"
                    )
                    lines.append(f"  Mode: {mode_name}")
                    self.result_text.setPlainText(
                        "\n".join(lines)
                    )
                    return
            lines.append("  No match")

        lines.append("")
        lines.append("Not found in common keys.")
        lines.append(
            "Use Device Key mode to decrypt directly."
        )
        self.result_text.setPlainText("\n".join(lines))

    def on_try_all(self):
        pkt = self._parse_packet()
        if not pkt:
            return
        enc, ser = pkt

        lines = [
            "Trying all common keys x all modes...\n"
        ]
        found = False
        for name, key in COMMON_MANUFACTURER_KEYS.items():
            for mid, mname in LEARNING_MODES.items():
                result = decode_packet(
                    enc, ser, key, mid
                )
                if result["valid"]:
                    found = True
                    lines.append(
                        f"MATCH: {name} + {mname}"
                    )
                    lines.append(
                        f"  Mfg: 0x{key:016X}"
                    )
                    lines.append(
                        f"  Dev: "
                        f"0x{result['device_key']:016X}"
                    )
                    lines.append(
                        f"  Btn={result['button']}"
                        f" Cnt={result['counter']}"
                    )
                    lines.append("")
        if not found:
            lines.append("No match. Try device key or bruteforce.")
        self.result_text.setPlainText("\n".join(lines))

    def on_bruteforce(self):
        pkt = self._parse_packet()
        if not pkt:
            return
        enc, ser = pkt
        enc2 = None
        t = self.edit_encrypted2.text().strip()
        if t:
            try:
                enc2 = int(t, 16)
            except ValueError:
                QMessageBox.warning(
                    self, "Error", "Invalid Encrypted #2"
                )
                return
        else:
            r = QMessageBox.question(
                self, "Single capture",
                "No 2nd capture. Results may have "
                "false positives.\nContinue?",
                QMessageBox.StandardButton.Yes
                | QMessageBox.StandardButton.No,
            )
            if r != QMessageBox.StandardButton.Yes:
                return
        try:
            start = int(self.edit_start.text().strip(), 16)
            end = int(self.edit_end.text().strip(), 16)
        except ValueError:
            QMessageBox.warning(
                self, "Error", "Invalid range"
            )
            return
        if end <= start:
            QMessageBox.warning(
                self, "Error", "End > start required"
            )
            return

        modes = list(LEARNING_MODES.keys())
        total = (end - start) * len(modes)
        self.progress.setRange(0, total)
        self.progress.setValue(0)
        self.progress.setFormat("Bruteforcing...")
        self.btn_bf.setEnabled(False)
        self.btn_stop.setEnabled(True)

        self._bruteforce_thread = BruteforceThread(
            enc, ser, modes, start, end, enc2,
        )
        self._bruteforce_thread.progress.connect(
            self._on_bf_progress
        )
        self._bruteforce_thread.found.connect(
            self._on_bf_found
        )
        self._bruteforce_thread.finished_signal.connect(
            self._on_bf_done
        )
        self._bruteforce_thread.start()

    def on_stop(self):
        if self._bruteforce_thread:
            self._bruteforce_thread.stop()

    def _on_bf_progress(self, tried, key_str):
        self.progress.setValue(tried)
        self.progress.setFormat(
            f"{tried:,} tried... {key_str}"
        )

    def _on_bf_found(self, key, result, mode):
        self.progress.setFormat("KEY FOUND!")
        self.progress.setValue(self.progress.maximum())
        self.btn_bf.setEnabled(True)
        self.btn_stop.setEnabled(False)
        pkt = self._parse_packet()
        enc, ser = pkt
        self._show_full_result(
            enc, ser, "manufacturer", result,
            mfg_key=key, mode=mode,
        )
        self.edit_key.setText(f"{key:016X}")

    def _on_bf_done(self):
        self.progress.setFormat("Not found")
        self.btn_bf.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.result_text.append("\nKey not found in range.")

    def on_encode(self):
        try:
            ser = int(
                self.edit_enc_serial.text().strip(), 16
            )
            btn = int(
                self.edit_enc_button.text().strip()
            )
            cnt = int(
                self.edit_enc_counter.text().strip()
            )
            ovr = int(
                self.edit_enc_ovr.text().strip()
            )
            key = int(
                self.edit_enc_key.text().strip(), 16
            )
        except ValueError:
            QMessageBox.warning(
                self, "Error", "Invalid parameters"
            )
            return

        # DISC: if empty, use serial & 0x3FF
        disc_text = self.edit_enc_disc.text().strip()
        if disc_text:
            try:
                disc = int(disc_text, 16)
            except ValueError:
                QMessageBox.warning(
                    self, "Error", "Invalid DISC (hex)"
                )
                return
        else:
            disc = None  # encode_packet defaults to serial & 0x3FF

        key_type = self.combo_enc_key_type.currentData()
        mode = self.combo_enc_learning.currentData()

        result = encode_packet(
            ser, btn, cnt, key,
            key_type=key_type,
            learning_mode=mode,
            ovr=ovr,
            disc=disc,
        )

        # Build PWM raw bits
        preamble = "10" * 12
        gap = "0" * 10
        pwm = ""
        for b in result["packet_bits"]:
            pwm += "100" if b == "1" else "110"
        raw_bits = preamble + gap + pwm

        lines = [
            "=== Encoded KeeLoq Packet ===",
            "",
            f"Serial:       0x{result['serial']:07X}",
            f"Button:       {result['button']}"
            f" (bits {result['button']:04b})",
            f"Counter:      {result['counter']}"
            f" (0x{result['counter']:04X})",
            "",
        ]
        if key_type == "manufacturer":
            lines.append(f"Mfg Key:      0x{key:016X}")
            lines.append(
                f"Learning:     "
                f"{LEARNING_MODES.get(mode, mode)}"
            )
        lines.extend([
            f"Device Key:   "
            f"0x{result['device_key']:016X}",
            "",
            f"PlainText:    "
            f"0x{result['plaintext']:08X}",
            f"CipherText:   "
            f"0x{result['encrypted']:08X}",
            f"Fixed Part:   "
            f"0x{result['fixed_part']:010X}",
            "",
            f"Packet (66 bits LSB):",
            f"  {result['packet_bits']}",
            "",
            f"PWM raw ({len(raw_bits)} bits):",
            f"  {raw_bits}",
            "",
            "Paste PWM raw bits into URH Generator to"
            " transmit.",
        ])
        self.result_text.setPlainText("\n".join(lines))

    # ── Output ───────────────────────────────────────

    def _show_full_result(
        self, encrypted, serial, key_type, result,
        mfg_key=None, mode=None,
    ):
        button = result["button"]
        ovr = result.get("ovr", 0)
        disc = result.get("disc", result.get("serial_low", 0) & 0x3FF)
        counter = result["counter"]
        decrypted = result["raw"]
        device_key = result["device_key"]
        valid = result.get("valid", disc == (serial & 0x3FF))

        # Store for "Copy to Encoder"
        self._last_decode = {
            "serial": serial,
            "button": button,
            "ovr": ovr,
            "disc": disc,
            "counter": counter,
            "device_key": device_key,
        }
        self.btn_to_encoder.setEnabled(True)

        lines = []
        if key_type == "manufacturer" and mfg_key is not None:
            lines.append(f"Mfg Key:      0x{mfg_key:016X}")
            lines.append(
                f"Learning:     "
                f"{LEARNING_MODES.get(mode, mode)}"
            )
        lines.append(f"Device Key:   0x{device_key:016X}")
        lines.append("")
        lines.append(f"CipherText:   0x{encrypted:08X}")
        lines.append(f"Serial:       0x{serial:07X}")

        # Fixed part: button(4) + vlow(1) + repeat(1) + serial(28)
        # Use button status for top nibble
        fixed = (button << 28) | serial
        lines.append(f"Fixed Part:   0x{fixed:010X}")
        lines.append("")
        lines.append(f"PlainText:    0x{decrypted:08X}")
        lines.append(
            f"Counter:      {counter} (0x{counter:04X})"
        )

        # Button: raw status and remapped
        btn_remap = (
            ((button & 0x8))
            | ((button & 0x1) << 2)
            | (button & 0x2)
            | ((button & 0x4) >> 2)
        )
        lines.append(
            f"Button:       value={btn_remap}"
            f" status={button}"
            f" (S3S0S1S2={button:04b})"
        )
        lines.append(f"OVR:          {ovr}")
        lines.append(
            f"DISC:         0x{disc:03X}"
            f" {'(VALID)' if valid else '(MISMATCH)'}"
        )
        lines.append("")
        lines.append("Cipher:       KeeLoq")
        lines.append("Encoder:      PWM")
        self.result_text.setPlainText("\n".join(lines))
