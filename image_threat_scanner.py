"""
IMG4N6 scanner core (v2)
========================
Rewritten for correctness, performance and evidence quality.

Key changes vs v1:
- Every file is read from disk exactly ONCE; all analyzers receive the bytes.
- YARA rules are compiled once by the caller and passed in.
- AI detection is provenance-first: ComfyUI / A1111 / InvokeAI / NovelAI embed
  their prompt+workflow in PNG text chunks or EXIF UserComment. C2PA / Content
  Credentials markers are also detected. Statistical heuristics are retained
  but capped so they can never claim more than LOW/MEDIUM confidence alone.
- "modern threat" regexes run only on metadata/appended segments, never on
  decoded pixel/compressed data (which caused constant false positives).
- Polyglot detection checks magic numbers at offset 0 and handles tiny files.
- New forensic modules: ELA (error level analysis), EXIF-thumbnail mismatch,
  GPS extraction, perceptual hashing for duplicate detection.
- The pseudo-scientific "blockchain_hash_validation" was removed.
- logging instead of print().
"""

import io
import os
import re
import json
import math
import struct
import base64
import hashlib
import logging
import threading
from collections import Counter
from datetime import datetime

import numpy as np
import cv2
import requests
from PIL import Image, ImageChops
from PIL.ExifTags import TAGS, GPSTAGS

try:
    import imagehash
except ImportError:  # optional
    imagehash = None

try:
    import piexif
except ImportError:  # optional
    piexif = None

log = logging.getLogger("img4n6.scanner")

Image.MAX_IMAGE_PIXELS = 200_000_000  # decompression-bomb guard (~200 MP)

LOSSLESS_EXTS = {".png", ".bmp", ".tiff", ".tif"}


# ---------------------------------------------------------------------------
# Basic utilities
# ---------------------------------------------------------------------------

def calculate_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string (0..8)."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def chi_square_test(data: bytes):
    """Chi-square test of byte uniformity. Returns (is_random, statistic)."""
    if len(data) < 256:
        return False, 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    expected = len(data) / 256.0
    chi = float(np.sum((counts - expected) ** 2 / expected))
    return chi < 293.248, chi  # low chi -> indistinguishable from random


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_phash(pil_img):
    """Perceptual hash string for duplicate / near-duplicate detection."""
    if imagehash is None or pil_img is None:
        return None
    try:
        return str(imagehash.phash(pil_img.convert("RGB")))
    except Exception as e:
        log.debug("phash failed: %s", e)
        return None


def phash_distance(h1: str, h2: str) -> int:
    """Hamming distance between two hex phash strings."""
    return bin(int(h1, 16) ^ int(h2, 16)).count("1")


# ---------------------------------------------------------------------------
# Image loading (once per file)
# ---------------------------------------------------------------------------

class LoadedImage:
    """Holds the single read of a file plus lazily-decoded representations."""

    def __init__(self, file_path: str, data: bytes):
        self.path = file_path
        self.data = data
        self.ext = os.path.splitext(file_path)[1].lower()
        self._pil = None
        self._pil_failed = False
        self._cv_gray = None
        self._cv_color = None

    @property
    def pil(self):
        if self._pil is None and not self._pil_failed:
            try:
                self._pil = Image.open(io.BytesIO(self.data))
                self._pil.load()
            except Exception as e:
                log.debug("PIL decode failed for %s: %s", self.path, e)
                self._pil_failed = True
        return self._pil

    @property
    def cv_color(self):
        if self._cv_color is None:
            arr = np.frombuffer(self.data, dtype=np.uint8)
            self._cv_color = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if self._cv_color is None and self.pil is not None:
                rgb = np.array(self.pil.convert("RGB"))
                self._cv_color = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
        return self._cv_color

    @property
    def cv_gray(self):
        if self._cv_gray is None and self.cv_color is not None:
            self._cv_gray = cv2.cvtColor(self.cv_color, cv2.COLOR_BGR2GRAY)
        return self._cv_gray


# ---------------------------------------------------------------------------
# File structure / polyglot analysis  (FIXED: offset-0 magic, small files)
# ---------------------------------------------------------------------------

MAGIC_AT_ZERO = [
    ("JPEG", b"\xff\xd8\xff"),
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("GIF", b"GIF87a"),
    ("GIF", b"GIF89a"),
    ("PDF", b"%PDF-"),
    ("ZIP", b"PK\x03\x04"),
    ("RAR", b"Rar!\x1a\x07"),
    ("PE", b"MZ"),
    ("ELF", b"\x7fELF"),
    ("BMP", b"BM"),
    ("WEBP/RIFF", b"RIFF"),
    ("TIFF", b"II*\x00"),
    ("TIFF", b"MM\x00*"),
]

# Signatures worth flagging if EMBEDDED anywhere in trailing data
EMBEDDED_SIGS = [
    ("ZIP archive", b"PK\x03\x04"),
    ("RAR archive", b"Rar!\x1a\x07"),
    ("7-Zip archive", b"7z\xbc\xaf\x27\x1c"),
    ("PDF document", b"%PDF-"),
    ("ELF executable", b"\x7fELF"),
    ("PNG image", b"\x89PNG\r\n\x1a\n"),
    ("JPEG image", b"\xff\xd8\xff\xe0"),
]


def identify_format(data: bytes):
    for name, sig in MAGIC_AT_ZERO:
        if data.startswith(sig):
            return name
    return None


def get_appended_data(data: bytes, ext: str) -> bytes:
    """Return bytes appended after the legitimate end-of-image marker."""
    try:
        if ext in (".jpg", ".jpeg"):
            end = data.rfind(b"\xff\xd9")
            if end != -1 and end + 2 < len(data):
                return data[end + 2:]
        elif ext == ".png":
            end = data.rfind(b"IEND\xae\x42\x60\x82")
            if end != -1 and end + 8 < len(data):
                return data[end + 8:]
        elif ext == ".gif":
            if data.endswith(b"\x3b"):
                return b""
            end = data.rfind(b"\x3b")
            if end != -1 and end + 1 < len(data):
                return data[end + 1:]
    except Exception as e:
        log.debug("appended-data check failed: %s", e)
    return b""


def detect_polyglot_files(data: bytes, ext: str):
    """Detect mismatched magic, embedded archives and appended payloads."""
    findings = []
    if len(data) < 16:
        return findings
    try:
        actual = identify_format(data)
        expected = {
            ".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".gif": "GIF",
            ".bmp": "BMP", ".webp": "WEBP/RIFF", ".tiff": "TIFF", ".tif": "TIFF",
        }.get(ext)
        if actual is None:
            findings.append("Unknown file signature - not a standard image format")
        elif expected and actual != expected:
            findings.append(
                f"Extension/content mismatch: file claims {ext} but is {actual}")

        appended = get_appended_data(data, ext)
        if len(appended) > 16:  # ignore tiny padding
            entropy = calculate_entropy(appended)
            findings.append(
                f"Data appended after image end marker: {len(appended):,} bytes "
                f"(entropy {entropy:.2f})")
            for name, sig in EMBEDDED_SIGS:
                if sig in appended[:4096] or sig in appended[-4096:]:
                    findings.append(f"Embedded {name} found in appended data")
                    break
    except Exception as e:
        log.debug("polyglot detection failed: %s", e)
    return findings


def validate_file_structure(data: bytes, ext: str, pil_img):
    findings = []
    try:
        file_size = len(data)
        if ext in (".jpg", ".jpeg") and pil_img is not None:
            w, h = pil_img.size
            uncompressed = w * h * 3
            if uncompressed and file_size > uncompressed * 2:
                findings.append(
                    f"File size ({file_size:,} B) exceeds uncompressed size of a "
                    f"{w}x{h} image ({uncompressed:,} B) - hidden data likely")
        elif ext == ".png":
            pos = 8
            all_chunks, meta_chunks, critical = [], [], []
            while pos + 8 <= len(data):
                length = struct.unpack(">I", data[pos:pos + 4])[0]
                ctype = data[pos + 4:pos + 8]
                if len(ctype) < 4:
                    break
                name = ctype.decode("ascii", errors="replace")
                all_chunks.append(name)
                # IDAT/fdAT are the image pixel stream - encoders legitimately
                # split them into dozens of blocks, so they must NOT count
                # toward "excessive chunks" (this was a false-positive source).
                if name not in ("IDAT", "fdAT"):
                    meta_chunks.append(name)
                if ctype[0:1].isupper():
                    critical.append(name)
                pos += 12 + length
                if name == "IEND":
                    break
            # Only an unusual number of NON-image-data chunks is suspicious
            # (e.g. many text chunks hiding data). APNG frames (fcTL) are
            # expected in animations, so we exclude them from the metadata tally.
            text_and_other = [c for c in meta_chunks
                              if c not in ("IHDR", "IEND", "PLTE", "fcTL",
                                           "acTL", "tRNS", "gAMA", "sRGB",
                                           "iCCP", "pHYs", "cHRM", "bKGD",
                                           "tIME", "sBIT")]
            # Any chunk not in the PNG spec's standard set is a private/vendor
            # chunk - a software fingerprint. Editors and pipelines embed these
            # (e.g. Fotor leaves a 'deBG' chunk). This is how we can flag
            # "processed by software" even when all text/EXIF tags were stripped.
            STANDARD_PNG_CHUNKS = {
                "IHDR", "PLTE", "IDAT", "IEND",                    # critical
                "bKGD", "cHRM", "dSIG", "eXIf", "gAMA", "hIST",    # ancillary
                "iCCP", "iTXt", "pHYs", "sBIT", "sPLT", "sRGB",
                "tEXt", "tIME", "tRNS", "zTXt", "cICP", "mDCv", "cLLi",
                "acTL", "fcTL", "fdAT",                            # APNG
            }
            nonstandard = sorted({c for c in all_chunks
                                  if c not in STANDARD_PNG_CHUNKS})
            if nonstandard:
                findings.append(
                    f"Non-standard PNG chunk(s) present: {', '.join(nonstandard)} "
                    f"- file was processed by software that embeds private "
                    f"chunks (editor/pipeline fingerprint)")

            if len(text_and_other) > 20:
                findings.append(
                    f"Unusual number of non-image PNG chunks: "
                    f"{len(text_and_other)} (possible data hiding)")
            unexpected = [c for c in critical
                          if c not in ("IHDR", "IDAT", "IEND", "PLTE")]
            if unexpected:
                findings.append(
                    f"Non-standard critical PNG chunks: {', '.join(set(unexpected))}")
    except Exception as e:
        log.debug("structure validation failed: %s", e)
    return findings


# ---------------------------------------------------------------------------
# EXIF / metadata
# ---------------------------------------------------------------------------

def extract_exif_data(pil_img):
    """Public getexif() API. Returns {tag_name: value} with GPS sub-IFD."""
    result = {}
    if pil_img is None:
        return result
    try:
        exif = pil_img.getexif()
        for tag_id, value in exif.items():
            name = TAGS.get(tag_id, str(tag_id))
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            result[name] = value
        # merge the EXIF sub-IFD (DateTimeOriginal etc.)
        try:
            sub = exif.get_ifd(0x8769)
            for tag_id, value in sub.items():
                name = TAGS.get(tag_id, str(tag_id))
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                result.setdefault(name, value)
        except Exception:
            pass
        try:
            gps = exif.get_ifd(0x8825)
            if gps:
                result["GPSInfo"] = {GPSTAGS.get(k, str(k)): v
                                     for k, v in gps.items()}
        except Exception:
            pass
    except Exception as e:
        log.debug("EXIF extraction failed: %s", e)
    return result


def _to_degrees(value):
    d, m, s = value
    return float(d) + float(m) / 60.0 + float(s) / 3600.0


def extract_gps(exif_data):
    """Return {'lat': .., 'lon': ..} or None."""
    gps = exif_data.get("GPSInfo")
    if not gps:
        return None
    try:
        lat = _to_degrees(gps["GPSLatitude"])
        lon = _to_degrees(gps["GPSLongitude"])
        if str(gps.get("GPSLatitudeRef", "N")).upper().startswith("S"):
            lat = -lat
        if str(gps.get("GPSLongitudeRef", "E")).upper().startswith("W"):
            lon = -lon
        if lat == 0 and lon == 0:
            return None
        return {"lat": round(lat, 6), "lon": round(lon, 6)}
    except Exception as e:
        log.debug("GPS parse failed: %s", e)
        return None


def analyze_metadata_anomalies(exif_data):
    findings = []
    try:
        software = str(exif_data.get("Software", ""))
        editors = ("photoshop", "gimp", "lightroom", "affinity", "paint.net",
                   "snapseed", "pixlr", "canva")
        if any(e in software.lower() for e in editors):
            findings.append(f"Image processed with editing software: {software}")

        for key, value in exif_data.items():
            if key == "GPSInfo":
                continue
            text = str(value)
            if len(text) > 500:
                findings.append(
                    f"Unusually large metadata field '{key}' ({len(text)} chars)")
            # base64 blobs hidden in metadata
            for m in re.finditer(r"[A-Za-z0-9+/]{60,}={0,2}", text):
                try:
                    decoded = base64.b64decode(m.group(), validate=True)
                    printable = sum(32 <= b < 127 for b in decoded)
                    if printable / max(len(decoded), 1) > 0.8:
                        findings.append(
                            f"Base64-encoded text hidden in EXIF '{key}'")
                        break
                except Exception:
                    continue
    except Exception as e:
        log.debug("metadata anomaly analysis failed: %s", e)
    return findings


def analyze_timestamp_anomalies(file_path, exif_data):
    findings = []
    try:
        st = os.stat(file_path)
        fs_modified = datetime.fromtimestamp(st.st_mtime)
        now = datetime.now()
        stamps = {}
        for name in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
            raw = exif_data.get(name)
            if raw:
                try:
                    stamps[name] = datetime.strptime(str(raw)[:19],
                                                     "%Y:%m:%d %H:%M:%S")
                except ValueError:
                    findings.append(f"Malformed EXIF timestamp {name}: {raw!r}")
        for name, ts in stamps.items():
            if ts > now:
                findings.append(f"EXIF {name} is in the future: {ts}")
            if (fs_modified - ts).days < -1:
                findings.append(
                    f"File modified before its EXIF {name} - clock rollback "
                    f"or metadata forgery")
        if ("DateTimeOriginal" in stamps and "DateTimeDigitized" in stamps
                and stamps["DateTimeOriginal"] > stamps["DateTimeDigitized"]):
            findings.append("DateTimeOriginal is AFTER DateTimeDigitized "
                            "(impossible for a real capture)")
    except Exception as e:
        log.debug("timestamp analysis failed: %s", e)
    return findings


# ---------------------------------------------------------------------------
# Metadata segment extraction (drives modern-threat scanning)
# ---------------------------------------------------------------------------

def extract_metadata_segments(data: bytes, ext: str) -> bytes:
    """
    Concatenate only the byte ranges where text can legitimately hide:
    JPEG APPn/COM segments, PNG text chunks, plus any appended data.
    Pixel/compressed streams are intentionally EXCLUDED - regexing them
    produced endless false positives in v1.
    """
    chunks = []
    try:
        if ext in (".jpg", ".jpeg"):
            pos = 2
            while pos + 4 <= len(data):
                if data[pos] != 0xFF:
                    break
                marker = data[pos + 1]
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    pos += 2
                    continue
                if marker == 0xDA:  # start of scan -> compressed data follows
                    break
                seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                if 0xE0 <= marker <= 0xEF or marker == 0xFE:  # APPn / COM
                    chunks.append(data[pos + 4:pos + 2 + seg_len])
                pos += 2 + seg_len
        elif ext == ".png":
            pos = 8
            while pos + 8 <= len(data):
                length = struct.unpack(">I", data[pos:pos + 4])[0]
                ctype = data[pos + 4:pos + 8]
                if ctype in (b"tEXt", b"zTXt", b"iTXt"):
                    chunks.append(data[pos + 8:pos + 8 + length])
                pos += 12 + length
                if ctype == b"IEND":
                    break
        else:
            chunks.append(data[:8192])
    except Exception as e:
        log.debug("segment extraction failed: %s", e)

    chunks.append(get_appended_data(data, ext))
    return b"".join(chunks)


# High-severity C2 / exfil / script indicators -> reported as THREATS
MODERN_PATTERNS = {
    "IPFS hash": re.compile(r"\bQm[1-9A-HJ-NP-Za-km-z]{44}\b"),
    "Ethereum address": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "Bitcoin address": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "Onion service URL": re.compile(r"\b[a-z2-7]{16,56}\.onion\b"),
    "Pastebin raw link": re.compile(r"pastebin\.com/raw/\w{8}", re.I),
    "Discord webhook": re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/", re.I),
    "Telegram bot": re.compile(r"t\.me/\w+bot\b", re.I),
    "Mega.nz link": re.compile(r"mega\.nz/(?:file|folder|#)\S+", re.I),
    "Cloud share link": re.compile(
        r"(?:drive\.google\.com/file/d/|1drv\.ms/|dropbox\.com/s/)\S+", re.I),
    "PowerShell command": re.compile(
        r"powershell(?:\.exe)?\s+(?:-\w+\s+)*", re.I),
    "Script tag": re.compile(r"<script[\s>]", re.I),
    "PHP tag": re.compile(r"<\?php", re.I),
}

# A bare URL in metadata is only weakly interesting and is extremely common in
# legitimate files: XMP/ICC use w3.org and adobe.com namespace URLs, AI
# workflows embed model/doc links (comfy.org, github, huggingface, civitai),
# camera software writes maker URLs. URLs to these are NOT threats - flagging
# them cried wolf on normal ComfyUI/Flux exports and any XMP-tagged image.
GENERIC_URL_RE = re.compile(r"https?://[^\s\"'<>\\]{8,200}", re.I)
BENIGN_URL_DOMAINS = (
    "w3.org", "adobe.com", "purl.org", "iptc.org", "npmjs.org", "npmjs.com",
    "schema.org", "color.org", "creativecommons.org", "comfy.org",
    "github.com", "githubusercontent.com", "huggingface.co", "hf.co",
    "civitai.com", "pytorch.org", "python.org", "openai.com", "google.com",
    "apple.com", "microsoft.com", "gimp.org", "krita.org", "inkscape.org",
    "gnu.org", "sourceforge.net", "wikipedia.org", "mozilla.org",
)


def detect_modern_threats(data: bytes, ext: str):
    """
    Scan ONLY metadata/appended segments. Returns (severity, description) tuples
    where severity is 'high' (C2/exfil/script -> threat) or 'low' (a bare
    non-benign URL -> informational warning).
    """
    findings = []
    try:
        segments = extract_metadata_segments(data, ext)
        if not segments:
            return findings
        text = segments.decode("utf-8", errors="ignore")
        for name, pattern in MODERN_PATTERNS.items():
            m = pattern.search(text)
            if m:
                findings.append(("high", f"{name}: {m.group()[:120]}"))
        # generic URLs: skip benign namespaces/model links, demote to low
        for m in list(GENERIC_URL_RE.finditer(text))[:30]:
            url = m.group()
            if any(d in url.lower() for d in BENIGN_URL_DOMAINS):
                continue
            findings.append(("low", f"Non-standard URL in metadata: {url[:120]}"))
            break
        # base64-encoded URLs are a real exfil/obfuscation signal -> high
        for m in list(re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", text))[:10]:
            try:
                decoded = base64.b64decode(m.group()).decode(
                    "utf-8", errors="ignore")
                low = decoded.lower()
                if ("http://" in low or "https://" in low) and \
                        not any(d in low for d in BENIGN_URL_DOMAINS):
                    findings.append(
                        ("high", f"Base64-encoded URL in metadata: {decoded[:100]}"))
            except Exception:
                continue
    except Exception as e:
        log.debug("modern threat scan failed: %s", e)
    return findings[:15]


# ---------------------------------------------------------------------------
# AI provenance + detection  (REWRITTEN: evidence first)
# ---------------------------------------------------------------------------

AI_SOFTWARE_MARKERS = (
    "comfyui", "stable diffusion", "stable-diffusion", "automatic1111",
    "invokeai", "novelai", "midjourney", "dall-e", "dall\u00b7e", "dalle",
    "flux", "sdxl", "fooocus", "draw things", "leonardo.ai", "firefly",
    "imagen", "ideogram", "niji",
)


def _parse_comfy_parameters(raw):
    """Pull models, sampler, steps, seed, cfg and negative prompt from a
    ComfyUI prompt-graph JSON. Returns a dict of whatever was found."""
    params = {}
    try:
        graph = json.loads(raw)
    except Exception:
        return params
    models, pos_prompts, neg_prompts = set(), [], []
    for node in graph.values():
        if not isinstance(node, dict):
            continue
        ins = node.get("inputs", {}) or {}
        ct = str(node.get("class_type", ""))
        for key in ("ckpt_name", "unet_name", "vae_name", "clip_name",
                    "clip_name1", "clip_name2", "lora_name", "model_name"):
            v = ins.get(key)
            if isinstance(v, str) and v:
                models.add(v)
        for key in ("sampler_name", "scheduler", "steps", "cfg",
                    "denoise", "guidance"):
            if key in ins and not isinstance(ins[key], list):
                params.setdefault(key, ins[key])
        for key in ("seed", "noise_seed"):
            if key in ins and not isinstance(ins[key], list):
                params.setdefault("seed", ins[key])
        if "CLIPTextEncode" in ct and isinstance(ins.get("text"), str):
            (neg_prompts if "neg" in ct.lower() else pos_prompts).append(ins["text"])
    if models:
        params["models"] = sorted(models)
    if neg_prompts:
        params["negative_prompt"] = " | ".join(neg_prompts)[:600]
    return params


def _parse_a1111_parameters(text):
    """Parse the A1111/Forge 'parameters' string: prompt + 'Key: value' tail."""
    params = {}
    try:
        text = str(text)
        # the settings line is the last line containing 'Steps:'
        tail = ""
        for line in text.splitlines():
            if re.search(r"\bSteps:\s*\d", line):
                tail = line
        for key in ("Steps", "Sampler", "CFG scale", "Seed", "Model",
                    "Model hash", "Size", "Denoising strength", "Schedule type"):
            m = re.search(rf"{re.escape(key)}:\s*([^,]+)", tail)
            if m:
                params[key.lower().replace(" ", "_")] = m.group(1).strip()
        m = re.search(r"Negative prompt:\s*(.+)", text)
        if m:
            params["negative_prompt"] = m.group(1).strip()[:600]
    except Exception:
        pass
    return params


def extract_ai_provenance(li: LoadedImage, exif_data):
    """
    Hard-evidence extraction. Generators literally sign their work:
      - A1111 / Forge:  PNG tEXt key 'parameters' (or EXIF UserComment in JPEG)
      - ComfyUI:        PNG tEXt keys 'prompt' and 'workflow' (JSON)
      - InvokeAI:       'invokeai_metadata' / 'sd-metadata'
      - NovelAI:        'Software' == 'NovelAI' + 'Comment' JSON
      - C2PA/Content Credentials: JUMBF box ('jumb'/'c2pa') in the file
    Returns dict {detected, generator, source, prompt, parameters}.
    'parameters' holds models / sampler / steps / seed / cfg when available.
    """
    prov = {"detected": False, "generator": None, "source": None,
            "prompt": None, "parameters": {}}
    try:
        info = dict(getattr(li.pil, "info", {}) or {})

        def set_prov(gen, source, prompt=None, parameters=None):
            prov.update(detected=True, generator=gen, source=source)
            if prompt:
                prov["prompt"] = str(prompt)[:1500]
            if parameters:
                prov["parameters"] = parameters

        if "parameters" in info:
            set_prov("Stable Diffusion (A1111/Forge)",
                     "PNG 'parameters' text chunk", info["parameters"],
                     _parse_a1111_parameters(info["parameters"]))
        elif "prompt" in info or "workflow" in info:
            raw = info.get("prompt") or info.get("workflow")
            prompt_text = raw
            try:  # pull the positive prompt out of ComfyUI's JSON graph
                graph = json.loads(raw)
                texts = [v["inputs"]["text"] for v in graph.values()
                         if isinstance(v, dict)
                         and "CLIPTextEncode" in str(v.get("class_type", ""))
                         and isinstance(v.get("inputs", {}).get("text"), str)]
                if texts:
                    prompt_text = " | ".join(texts)[:1500]
            except Exception:
                pass
            set_prov("ComfyUI", "PNG 'prompt'/'workflow' chunk", prompt_text,
                     _parse_comfy_parameters(info.get("prompt")
                                             or info.get("workflow")))
        elif "invokeai_metadata" in info or "sd-metadata" in info:
            set_prov("InvokeAI",
                     "PNG 'invokeai_metadata' chunk",
                     info.get("invokeai_metadata") or info.get("sd-metadata"))
        elif str(info.get("Software", "")).lower().startswith("novelai"):
            set_prov("NovelAI", "PNG 'Software' chunk", info.get("Comment"))

        if not prov["detected"]:
            for field in ("Software", "Make", "Model", "ImageDescription"):
                val = str(exif_data.get(field, "")).lower()
                hit = next((m for m in AI_SOFTWARE_MARKERS if m in val), None)
                if hit:
                    set_prov(exif_data.get(field), f"EXIF {field} tag")
                    break

        if not prov["detected"]:
            uc = str(exif_data.get("UserComment", ""))
            if "steps:" in uc.lower() and ("sampler" in uc.lower()
                                           or "cfg scale" in uc.lower()):
                set_prov("Stable Diffusion (A1111, JPEG export)",
                         "EXIF UserComment", uc, _parse_a1111_parameters(uc))

        # C2PA / Content Credentials (DALL-E, Adobe Firefly, cameras)
        head = li.data[:262144]
        if (b"c2pa" in head or b"jumb" in head or b"jumd" in head
                or b"contentauth" in head.lower()
                or b"contentcredentials" in head.lower()):
            prov["c2pa"] = True
            if not prov["detected"]:
                set_prov("Unknown (C2PA manifest present)",
                         "C2PA / Content Credentials manifest")
    except Exception as e:
        log.debug("provenance extraction failed: %s", e)
    return prov


AI_RESOLUTIONS = {
    (512, 512), (768, 768), (1024, 1024), (512, 768), (768, 512),
    (896, 1152), (1152, 896), (832, 1216), (1216, 832), (1344, 768),
    (768, 1344), (1024, 1536), (1536, 1024),
}


def detect_ai_generated_content(li: LoadedImage, exif_data, provenance):
    """
    Returns (indicators:list[dict], probability:float, confidence:str).
    Hard provenance evidence -> 0.98. Heuristics alone are capped at 0.45
    so they can never claim HIGH confidence (v1 flagged every screenshot).
    """
    indicators = []

    if provenance.get("detected"):
        indicators.append({
            "name": f"Generator metadata found: {provenance['generator']}",
            "score": 0.98, "hard_evidence": True})
        return indicators, 0.98, "CONFIRMED"

    scores = {}
    try:
        filename = os.path.basename(li.path).lower()
        if any(p in filename for p in ("comfyui", "stable_diffusion", "sd_",
                                       "flux_", "dalle", "midjourney")):
            scores["AI tool name in filename"] = 0.20
        if re.search(r"_\d{5}_?", filename):
            scores["Sequential batch-style filename"] = 0.08

        camera_tags = ("Make", "Model", "DateTimeOriginal")
        if not any(t in exif_data for t in camera_tags):
            scores["No camera metadata"] = 0.10  # weak: true of all screenshots

        if li.pil is not None:
            w, h = li.pil.size
            if (w, h) in AI_RESOLUTIONS:
                scores["Common diffusion-model resolution"] = 0.12
            elif w % 64 == 0 and h % 64 == 0 and w >= 512 and h >= 512:
                scores["Dimensions are multiples of 64"] = 0.06

        total = min(sum(scores.values()), 0.45)  # heuristic cap
    except Exception as e:
        log.debug("AI heuristics failed: %s", e)
        total = 0.0

    for name, score in sorted(scores.items(), key=lambda x: -x[1]):
        indicators.append({"name": name, "score": round(score, 2),
                           "hard_evidence": False})

    if total >= 0.30:
        confidence = "MEDIUM (heuristic only)"
    elif total >= 0.15:
        confidence = "LOW (heuristic only)"
    else:
        confidence = "NONE"
    return indicators, round(total, 2), confidence


# ---------------------------------------------------------------------------
# Tamper detection: ELA + EXIF thumbnail mismatch   (NEW)
# ---------------------------------------------------------------------------

def error_level_analysis(li: LoadedImage, quality=90):
    """
    Classic ELA: resave the JPEG at a known quality and measure how much each
    region resists recompression. Uniform error = consistent history;
    localized high error = pasted/edited regions. Indicative, not proof.
    """
    if li.ext not in (".jpg", ".jpeg") or li.pil is None:
        return None
    try:
        original = li.pil.convert("RGB")
        buf = io.BytesIO()
        original.save(buf, "JPEG", quality=quality)
        buf.seek(0)
        resaved = Image.open(buf)
        diff = np.asarray(ImageChops.difference(original, resaved),
                          dtype=np.float32).max(axis=2)

        mean_err = float(diff.mean())
        # split into a 8x8 grid; compare hottest block against the median
        gh, gw = max(diff.shape[0] // 8, 1), max(diff.shape[1] // 8, 1)
        block_means = [
            diff[r:r + gh, c:c + gw].mean()
            for r in range(0, diff.shape[0] - gh + 1, gh)
            for c in range(0, diff.shape[1] - gw + 1, gw)
        ]
        block_means = np.array(block_means)
        median = float(np.median(block_means))
        hottest = float(block_means.max())
        # guard the ratio against a near-zero median (flat/low-error images)
        ratio = hottest / max(median, 0.5)

        # A splice shows up as one block recompressing very differently from the
        # rest. For high-quality JPEGs absolute errors are small, so a very high
        # ratio is the reliable signal; for noisier images we also require a
        # meaningful absolute hotspot. The median>=0.3 guard stops a perfectly
        # flat block (median≈0) from manufacturing a huge ratio out of noise.
        suspicious = bool(
            median >= 0.3 and (
                (ratio > 12.0 and hottest > 2.5)
                or (ratio > 5.0 and hottest > 15.0)))
        return {
            "mean_error": round(mean_err, 2),
            "hotspot_ratio": round(ratio, 2),
            "suspicious": suspicious,
            "note": ("Localized recompression anomaly - possible spliced/edited "
                     "region" if suspicious else
                     "Error levels uniform - no splice indication"),
        }
    except Exception as e:
        log.debug("ELA failed: %s", e)
        return None


def check_thumbnail_mismatch(li: LoadedImage):
    """
    Editors often update the main image but keep the ORIGINAL embedded EXIF
    thumbnail. A large perceptual distance between the two exposes editing.
    """
    if piexif is None or imagehash is None or li.pil is None:
        return None
    if li.ext not in (".jpg", ".jpeg", ".tiff", ".tif"):
        return None
    try:
        exif_dict = piexif.load(li.data)
        thumb_bytes = exif_dict.get("thumbnail")
        if not thumb_bytes:
            return None
        thumb = Image.open(io.BytesIO(thumb_bytes)).convert("RGB")
        main = li.pil.convert("RGB")
        # phash captures structure; average_hash captures global tone/brightness.
        # Editing that phash tolerates (inversion, recolor) still moves ahash,
        # so we take the max distance of the two.
        p_dist = int(imagehash.phash(main) - imagehash.phash(thumb))
        a_dist = int(imagehash.average_hash(main) - imagehash.average_hash(thumb))
        distance = max(p_dist, a_dist)
        mismatch = p_dist > 14 or a_dist > 18
        return {
            "has_thumbnail": True,
            "phash_distance": p_dist,
            "ahash_distance": a_dist,
            "mismatch": mismatch,
            "note": ("Embedded thumbnail differs substantially from the main "
                     "image - the file was likely edited after capture"
                     if mismatch else
                     "Embedded thumbnail matches the main image"),
        }
    except Exception as e:
        log.debug("thumbnail check failed: %s", e)
        return None


# ---------------------------------------------------------------------------
# Statistical / steganography analysis (deep & ultra levels)
# ---------------------------------------------------------------------------

def detect_data_anomalies(li: LoadedImage):
    """File-level statistical checks (deep level)."""
    findings = []
    try:
        appended = get_appended_data(li.data, li.ext)
        if len(appended) > 256:
            ent = calculate_entropy(appended)
            if ent > 7.5:
                findings.append(
                    f"Appended data is high-entropy ({ent:.2f}) - encrypted or "
                    f"compressed payload likely")
        if li.ext in LOSSLESS_EXTS and li.cv_gray is not None:
            # unusually uniform histogram can indicate embedded noise
            hist = np.bincount(li.cv_gray.ravel(), minlength=256)
            nonzero = hist[hist > 0]
            if len(nonzero) > 200:
                cv = float(nonzero.std() / (nonzero.mean() + 1e-9))
                if cv < 0.20:
                    findings.append(
                        f"Suspiciously flat pixel histogram (cv={cv:.2f})")
    except Exception as e:
        log.debug("data anomaly detection failed: %s", e)
    return findings


def detect_lsb_steganography(li: LoadedImage):
    """
    Chi-square Pair-of-Values attack on the LSB plane (lossless formats only -
    JPEG LSBs are always noise-like, which is why v1 false-positived).
    """
    findings = []
    if li.ext not in LOSSLESS_EXTS or li.cv_color is None:
        return findings
    try:
        img = li.cv_color
        suspicious_channels = 0
        for c in range(img.shape[2] if img.ndim == 3 else 1):
            channel = img[:, :, c] if img.ndim == 3 else img
            hist = np.bincount(channel.ravel(), minlength=256).astype(np.float64)
            # PoV: after LSB embedding, counts of value pairs (2k, 2k+1) equalize
            evens, odds = hist[0::2], hist[1::2]
            pair_sums = evens + odds
            mask = pair_sums > 30
            if mask.sum() < 20:
                continue
            expected = pair_sums[mask] / 2.0
            chi = float(np.sum((evens[mask] - expected) ** 2 / expected))
            dof = int(mask.sum() - 1)
            # chi far below dof => pairs equalized => embedding signature
            if chi < dof * 0.35:
                suspicious_channels += 1
        if suspicious_channels >= 2:
            findings.append(
                f"LSB pair-of-values signature in {suspicious_channels} color "
                f"channels - LSB steganography likely")
    except Exception as e:
        log.debug("LSB analysis failed: %s", e)
    return findings


def spa_steganalysis(li: LoadedImage):
    """
    Sample Pair Analysis estimate of LSB embedding rate (ultra level).
    Reports only when the estimated rate is well above natural noise.
    """
    findings = []
    if li.ext not in LOSSLESS_EXTS or li.cv_gray is None:
        return findings
    try:
        x = li.cv_gray.astype(np.int32)
        u, v = x[:, :-1].ravel(), x[:, 1:].ravel()
        even_u = (u % 2 == 0)
        w = np.sum((v == u) & even_u) + np.sum((v == u + 1) & even_u) \
            + np.sum((v == u) & ~even_u) + np.sum((v == u - 1) & ~even_u)
        z = np.sum(np.abs(u - v) <= 1)
        if z == 0:
            return findings
        beta = max(0.0, 1.0 - 2.0 * w / z)
        if beta > 0.10:
            findings.append(
                f"Sample Pair Analysis estimates ~{beta * 100:.0f}% LSB "
                f"embedding rate")
    except Exception as e:
        log.debug("SPA failed: %s", e)
    return findings


def detect_palette_steganography(li: LoadedImage):
    findings = []
    try:
        if li.pil is not None and li.pil.mode == "P":
            palette = li.pil.getpalette() or []
            colors = [tuple(palette[i:i + 3]) for i in range(0, len(palette), 3)]
            colors = [c for c in colors if len(c) == 3]
            dupes = len(colors) - len(set(colors))
            if dupes > 8:
                findings.append(
                    f"Palette contains {dupes} duplicate colors - classic "
                    f"palette-based steganography indicator")
    except Exception as e:
        log.debug("palette check failed: %s", e)
    return findings


# ---------------------------------------------------------------------------
# YARA + VirusTotal
# ---------------------------------------------------------------------------

# Precautionary: yara-python does not guarantee that a single compiled Rules
# object is safe to call match() on from multiple threads at once, so we compile
# once (fast, memory-light) and serialize just the match() call behind this lock.
# Matching one image is sub-millisecond, so the parallelism lost is negligible
# while the heavy work (decode, entropy, steganalysis) stays fully parallel.
_YARA_LOCK = threading.Lock()


def yara_scannable_region(data: bytes, ext: str) -> bytes:
    """
    YARA should scan only structurally meaningful regions - the file header,
    text/metadata segments, and any appended data - NOT the bulk compressed
    pixel stream. A multi-megabyte image's IDAT/scan data is effectively random
    and will contain short rule tokens ('TVo', '<~', 'PE') by pure chance,
    producing endless false positives. Real threats (embedded executables,
    scripts, C2 strings, polyglot payloads) live in the header, metadata, or
    appended trailer, all of which are covered here.
    """
    parts = [data[:65536]]                                  # header + structure
    seg = extract_metadata_segments(data, ext)              # text chunks + appended
    if seg:
        parts.append(seg)
    if len(data) > 4096:
        parts.append(data[-4096:])                          # trailer
    return b"\x00".join(parts)


def scan_with_yara(data: bytes, compiled_rules):
    """Match precompiled YARA rules against in-memory bytes (thread-safe)."""
    if compiled_rules is None:
        return []
    try:
        with _YARA_LOCK:
            return [str(m) for m in compiled_rules.match(data=data)]
    except Exception as e:
        log.warning("YARA match error: %s", e)
        return []


def check_virustotal_hash(sha256_hash, api_key, timeout=15):
    """Hash lookup against VirusTotal v3 (now with a timeout - v1 could hang)."""
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
            headers={"x-apikey": api_key}, timeout=timeout)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return {"malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0)}
        if resp.status_code == 404:
            return {"note": "Hash not present in VirusTotal"}
        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit reached"}
        return {"error": f"VirusTotal API error {resp.status_code}"}
    except requests.RequestException as e:
        return {"error": f"VirusTotal request failed: {e}"}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan_file(file_path, data, analysis_level="quick", compiled_rules=None,
              vt_api_key=None):
    """
    Analyze one image. `data` is the file's bytes (read once by the caller).
    Returns a structured, JSON-serializable result dict.
    """
    li = LoadedImage(file_path, data)
    threats, warnings = [], []

    exif_data = extract_exif_data(li.pil)
    provenance = extract_ai_provenance(li, exif_data)
    ai_indicators, ai_probability, ai_confidence = \
        detect_ai_generated_content(li, exif_data, provenance)

    for f in detect_polyglot_files(data, li.ext):
        threats.append({"type": "File Structure", "description": f,
                        "level": "high"})
    for f in validate_file_structure(data, li.ext, li.pil):
        warnings.append({"type": "File Structure", "description": f,
                         "level": "medium"})
    for severity, f in detect_modern_threats(data, li.ext):
        if severity == "high":
            threats.append({"type": "Modern Threat", "description": f,
                            "level": "high"})
        else:
            warnings.append({"type": "Metadata Note", "description": f,
                             "level": "low"})
    for f in analyze_metadata_anomalies(exif_data):
        warnings.append({"type": "Metadata Anomaly", "description": f,
                         "level": "low"})
    for f in analyze_timestamp_anomalies(file_path, exif_data):
        warnings.append({"type": "Timestamp Anomaly", "description": f,
                         "level": "low"})
    for hit in scan_with_yara(yara_scannable_region(data, li.ext), compiled_rules):
        threats.append({"type": "YARA Detection", "description": hit,
                        "level": "high"})

    thumb_check = check_thumbnail_mismatch(li)
    if thumb_check and thumb_check["mismatch"]:
        warnings.append({"type": "Tamper Indicator",
                         "description": thumb_check["note"], "level": "medium"})

    ela = None
    if analysis_level in ("deep", "ultra"):
        ela = error_level_analysis(li)
        if ela and ela["suspicious"]:
            warnings.append({"type": "Tamper Indicator (ELA)",
                             "description": ela["note"], "level": "medium"})
        for f in detect_data_anomalies(li):
            warnings.append({"type": "Statistical Anomaly", "description": f,
                             "level": "medium"})
        for f in detect_lsb_steganography(li):
            threats.append({"type": "LSB Steganography", "description": f,
                            "level": "high"})

    if analysis_level == "ultra":
        for f in spa_steganalysis(li):
            threats.append({"type": "Steganalysis (SPA)", "description": f,
                            "level": "high"})
        for f in detect_palette_steganography(li):
            warnings.append({"type": "Palette Anomaly", "description": f,
                             "level": "medium"})

    sha256 = compute_sha256(data)
    vt_result = None
    if vt_api_key and threats:  # only spend VT quota on flagged files
        vt_result = check_virustotal_hash(sha256, vt_api_key)
        if vt_result and vt_result.get("malicious", 0) > 0:
            threats.append({
                "type": "VirusTotal",
                "description": f"{vt_result['malicious']} AV engines flag this "
                               f"file as malicious", "level": "high"})

    status = "threats" if threats else ("warnings" if warnings else "clean")

    dimensions = None
    if li.pil is not None:
        try:
            dimensions = {"width": li.pil.size[0], "height": li.pil.size[1]}
        except Exception:
            pass

    result = {
        "filename": os.path.basename(file_path),
        "file_path": file_path,
        "file_size": len(data),
        "dimensions": dimensions,
        "format": li.ext.lstrip("."),
        "sha256": sha256,
        "phash": compute_phash(li.pil),
        "status": status,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "ai_probability": ai_probability,
        "ai_confidence": ai_confidence,
        "ai_indicators": ai_indicators,
        "ai_provenance": provenance,
        "threats": threats,
        "warnings": warnings,
        "gps": extract_gps(exif_data),
        "ela": ela,
        "thumbnail_check": thumb_check,
        "virustotal": vt_result,
        "camera": {k: str(exif_data[k]) for k in ("Make", "Model", "Software")
                   if k in exif_data},
    }
    return result
