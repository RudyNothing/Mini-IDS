import os
import time
import asyncio
import threading
import traceback
import numpy as np
from queue import Queue

print("[DEBUG] Loaded packet_sniffer.py from:", __file__)

# Force TShark path for Windows
os.environ["TSHARK_PATH"] = r"D:\Program Files\Wireshark\tshark.exe"

import pyshark
from fusion_engine import FusionEngine


FEATURE_NAMES = [
    "Total Fwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Fwd Packet Length Max",
    "Flow IAT Mean",
    "Flow IAT Min",
    "Flow IAT Max",
    "Packet Length Mean",
    "Average Packet Size"
]

FLOW_TIMEOUT = 1.0
MAX_FLOW_AGE = 180
PACKET_THRESHOLD = 40  # instant detection trigger for bursts


# ======================================================
# FLOW BUFFER
# ======================================================
class FlowBuffer:
    def __init__(self, key, ts):
        self.key = key
        self.start_ts = ts
        self.last_ts = ts
        self.pkts_fwd = 0
        self.pkts_bwd = 0
        self.bytes_fwd = 0
        self.bytes_bwd = 0
        self.pkt_lengths_fwd = []
        self.pkt_lengths_bwd = []
        self.timestamps = []
        self.first_win_fwd = None
        self.first_win_bwd = None

    def update(self, direction, pkt_len, ts, win=None):
        self.last_ts = ts
        self.timestamps.append(ts)

        if direction == "fwd":
            self.pkts_fwd += 1
            self.bytes_fwd += pkt_len
            self.pkt_lengths_fwd.append(pkt_len)
            if self.first_win_fwd is None and win:
                self.first_win_fwd = win
        else:
            self.pkts_bwd += 1
            self.bytes_bwd += pkt_len
            self.pkt_lengths_bwd.append(pkt_len)
            if self.first_win_bwd is None and win:
                self.first_win_bwd = win

    def total_pkts(self):
        return self.pkts_fwd + self.pkts_bwd

    def total_bytes(self):
        return self.bytes_fwd + self.bytes_bwd


# ======================================================
# PACKET SNIFFER (PyShark)
# ======================================================
class PacketSniffer:
    def __init__(self, interface="8", flow_timeout=FLOW_TIMEOUT,
                 feature_names=FEATURE_NAMES, model_path="models/rf_baseline.joblib",
                 strict=True, packet_count=0):

        self.interface = interface     # NOW USES INDEX (e.g., "8")
        self.packet_count = packet_count
        self.flow_timeout = flow_timeout
        self.fusion = FusionEngine(model_path=model_path, strict=strict)

        self.flows = {}
        self.lock = threading.Lock()
        self.queue = Queue()

        self._running = False
        self._thread = None
        self._cleanup_thread = None


    # ----------------------------------------------------------
    # Flow key
    # ----------------------------------------------------------
    def _flow_key_from_packet(self, pkt):
        try:
            ip = pkt.ip
            src = ip.src
            dst = ip.dst
            proto = pkt.highest_layer
        except:
            return None

        # Ports
        try:
            if hasattr(pkt, "tcp"):
                sp = int(pkt.tcp.srcport)
                dp = int(pkt.tcp.dstport)
                proto = "TCP"
            elif hasattr(pkt, "udp"):
                sp = int(pkt.udp.srcport)
                dp = int(pkt.udp.dstport)
                proto = "UDP"
            else:
                sp = -1
                dp = -1
        except:
            sp, dp = -1, -1

        return (src, dst, sp, dp, proto)


    # ----------------------------------------------------------
    # Packet direction
    # ----------------------------------------------------------
    def _packet_direction(self, pkt, key):
        try:
            return "fwd" if pkt.ip.src == key[0] else "bwd"
        except:
            return "fwd"


    # ----------------------------------------------------------
    # Feature extraction
    # ----------------------------------------------------------
    def _compute_flow_features(self, f: FlowBuffer):
        m = lambda x: float(np.mean(x)) if len(x) else 0.0
        mi = lambda x: float(np.min(x)) if len(x) else 0.0
        ma = lambda x: float(np.max(x)) if len(x) else 0.0

        iats = []
        if len(f.timestamps) > 1:
            t = np.sort(np.array(f.timestamps))
            iats = np.diff(t).tolist()

        avg_pkt_size = f.total_bytes() / f.total_pkts() if f.total_pkts() else 0.0

        return np.array([
            f.pkts_fwd,
            m(f.pkt_lengths_fwd),
            m(f.pkt_lengths_bwd),
            float(f.first_win_fwd or 0),
            float(f.first_win_bwd or 0),
            ma(f.pkt_lengths_fwd),
            m(iats),
            mi(iats),
            ma(iats),
            m(f.pkt_lengths_fwd + f.pkt_lengths_bwd),
            avg_pkt_size
        ])


    # ----------------------------------------------------------
    # Close flow + detect
    # ----------------------------------------------------------
    def _close_flow_and_detect(self, key):
        with self.lock:
            f = self.flows.pop(key, None)

        if f is None:
            return

        feats = self._compute_flow_features(f)
        result = self.fusion.fuse(feats, FEATURE_NAMES)

        result.update({
            "flow_key": key,
            "start_ts": f.start_ts,
            "end_ts": f.last_ts,
            "total_pkts": f.total_pkts(),
            "total_bytes": f.total_bytes()
        })

        self.queue.put(result)


    # ----------------------------------------------------------
    # Cleanup thread
    # ----------------------------------------------------------
    def _periodic_flush(self):
        while self._running:
            try:
                now = time.time()
                expired = []

                with self.lock:
                    for k, f in list(self.flows.items()):
                        if now - f.last_ts >= FLOW_TIMEOUT:
                            expired.append(k)

                for k in expired:
                    self._close_flow_and_detect(k)

                time.sleep(0.25)

            except:
                traceback.print_exc()


    # ----------------------------------------------------------
    # PyShark packet loop (RELIABLE)
    # ----------------------------------------------------------

    def _pkt_loop(self):
        print(f"[INFO] Using pyshark sync LiveCapture on interface index {self.interface}")

        try:
            capture = pyshark.LiveCapture(interface=self.interface)

            # Synchronous packet iteration → NO asyncio → NO event loop required
            for pkt in capture.sniff_continuously():

                if not self._running:
                    break

                try:
                    key = self._flow_key_from_packet(pkt)
                    if key is None:
                        continue

                    direction = self._packet_direction(pkt, key)
                    ts = time.time()

                    pkt_len = 0
                    try:
                        pkt_len = int(pkt.length)
                    except:
                        pass

                    win = None
                    if hasattr(pkt, "tcp"):
                        try:
                            win = int(pkt.tcp.window_size_value)
                        except:
                            win = None

                    with self.lock:
                        if key not in self.flows:
                            self.flows[key] = FlowBuffer(key, ts)

                        f = self.flows[key]
                        f.update(direction, pkt_len, ts, win)

                        # Instant detection threshold
                        if f.total_pkts() >= PACKET_THRESHOLD:
                            self._close_flow_and_detect(key)
                            continue

                except Exception as e:
                    print("[WARN] Packet parse failed:", e)

        except Exception as e:
            print("[ERROR] pyshark capture failed:", e)



    # ----------------------------------------------------------
    # Start
    # ----------------------------------------------------------
    def start(self):
        if self._running:
            return

        self._running = True

        self._thread = threading.Thread(target=self._pkt_loop, daemon=True)
        self._thread.start()

        self._cleanup_thread = threading.Thread(target=self._periodic_flush, daemon=True)
        self._cleanup_thread.start()

        print("[INFO] Packet sniffer started.")


    # ----------------------------------------------------------
    # Stop
    # ----------------------------------------------------------
    def stop(self):
        self._running = False

        keys = list(self.flows.keys())
        for k in keys:
            self._close_flow_and_detect(k)

        print("[INFO] Packet sniffer stopped.")
