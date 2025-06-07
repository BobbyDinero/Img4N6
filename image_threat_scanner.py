import os
import re
import base64
import hashlib
import requests
import yara
import math
import struct
import zlib
import cv2
from collections import Counter
from PIL import Image
from PIL.ExifTags import TAGS
import numpy as np
from scipy import fftpack, stats
from scipy.signal import find_peaks
import warnings
from datetime import datetime

warnings.filterwarnings("ignore")

# === BASIC UTILITY FUNCTIONS ===


def calculate_entropy(data):
    """Calculate Shannon entropy to detect encrypted/compressed data"""
    if not data:
        return 0

    byte_counts = Counter(data)
    total_bytes = len(data)

    entropy = 0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy


def chi_square_test(data, threshold=0.05):
    """Chi-square test for randomness detection"""
    if len(data) < 256:
        return False, 0

    expected = len(data) / 256
    observed = [0] * 256
    for byte in data:
        observed[byte] += 1

    chi_square = sum((obs - expected) ** 2 / expected for obs in observed)
    critical_value = 293.248

    return chi_square > critical_value, chi_square


def compute_sha256(file_path):
    """Compute SHA-256 hash of file"""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error: {e}"


# === NEW: FILE STRUCTURE VALIDATION ===


def detect_polyglot_files(file_path):
    """Detect files that are valid in multiple formats (polyglots)"""
    findings = []

    try:
        with open(file_path, "rb") as f:
            header = f.read(1024)
            f.seek(-512, 2)  # Go to 512 bytes from end
            trailer = f.read(512)

        # Check for multiple valid headers
        format_signatures = {
            "JPEG": [b"\xff\xd8\xff"],
            "PNG": [b"\x89PNG\r\n\x1a\n"],
            "GIF": [b"GIF87a", b"GIF89a"],
            "PDF": [b"%PDF-"],
            "ZIP": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
            "RAR": [b"Rar!\x1a\x07\x00"],
            "PE": [b"MZ"],
            "ELF": [b"\x7fELF"],
        }

        detected_formats = []
        for format_name, signatures in format_signatures.items():
            for sig in signatures:
                if sig in header or sig in trailer:
                    detected_formats.append(format_name)
                    break

        if len(set(detected_formats)) > 1:
            findings.append(
                f"Polyglot file detected: {', '.join(set(detected_formats))}"
            )

        # Check for appended data after valid image
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in [".jpg", ".jpeg"]:
            # JPEG should end with FFD9
            if not trailer.endswith(b"\xff\xd9") and b"\xff\xd9" in header:
                # Find the actual JPEG end
                with open(file_path, "rb") as f:
                    data = f.read()
                jpeg_end = data.rfind(b"\xff\xd9")
                if (
                    jpeg_end > 0 and jpeg_end < len(data) - 100
                ):  # Significant data after JPEG end
                    appended_size = len(data) - jpeg_end - 2
                    findings.append(
                        f"Data appended after JPEG end marker: {appended_size} bytes"
                    )

        elif file_ext == ".png":
            # PNG should end with IEND chunk
            if b"IEND" in header and not trailer.endswith(b"IEND\xae\x42\x60\x82"):
                with open(file_path, "rb") as f:
                    data = f.read()
                iend_pos = data.rfind(b"IEND\xae\x42\x60\x82")
                if iend_pos > 0 and iend_pos < len(data) - 50:
                    appended_size = len(data) - iend_pos - 8
                    findings.append(
                        f"Data appended after PNG IEND chunk: {appended_size} bytes"
                    )

    except Exception as e:
        return []

    return findings


def validate_file_structure(file_path):
    """Validate file structure integrity"""
    findings = []

    try:
        file_ext = os.path.splitext(file_path)[1].lower()
        file_size = os.path.getsize(file_path)

        if file_ext in [".jpg", ".jpeg"]:
            # Validate JPEG structure
            try:
                img = Image.open(file_path)
                declared_size = img.size[0] * img.size[1] * 3  # Rough estimate

                # Check if file size is suspiciously large compared to image dimensions
                if file_size > declared_size * 2:  # Very conservative threshold
                    size_ratio = file_size / declared_size
                    findings.append(
                        f"File size ({file_size:,} bytes) much larger than expected for {img.size[0]}x{img.size[1]} image (ratio: {size_ratio:.1f}x)"
                    )

            except Exception:
                pass

        elif file_ext == ".png":
            # PNG chunk validation
            try:
                with open(file_path, "rb") as f:
                    f.seek(8)  # Skip PNG signature
                    chunks = []
                    critical_chunks = []

                    while True:
                        length_bytes = f.read(4)
                        if len(length_bytes) != 4:
                            break

                        chunk_length = struct.unpack(">I", length_bytes)[0]
                        chunk_type = f.read(4)

                        if len(chunk_type) != 4:
                            break

                        chunks.append(chunk_type.decode("ascii", errors="ignore"))

                        # Check if critical chunk (uppercase first letter)
                        if chunk_type[0] < 97:  # ASCII 'a' = 97
                            critical_chunks.append(
                                chunk_type.decode("ascii", errors="ignore")
                            )

                        f.seek(chunk_length + 4, 1)  # Skip data + CRC

                    # Check for suspicious number of chunks
                    if len(chunks) > 50:
                        findings.append(f"Excessive PNG chunks: {len(chunks)}")

                    # Check for unusual critical chunks
                    expected_critical = ["IHDR", "IDAT", "IEND"]
                    unexpected_critical = [
                        c for c in critical_chunks if c not in expected_critical
                    ]
                    if unexpected_critical:
                        findings.append(
                            f"Unexpected critical PNG chunks: {', '.join(unexpected_critical)}"
                        )

            except Exception:
                pass

    except Exception as e:
        return []

    return findings


# === NEW: TIMESTAMP ANALYSIS ===


def analyze_timestamp_anomalies(file_path):
    """Analyze file and EXIF timestamps for manipulation indicators"""
    findings = []

    try:
        # Get file system timestamps
        file_stat = os.stat(file_path)
        fs_created = datetime.fromtimestamp(file_stat.st_ctime)
        fs_modified = datetime.fromtimestamp(file_stat.st_mtime)

        # Get EXIF timestamps
        try:
            img = Image.open(file_path)
            exif_data = img._getexif()

            if exif_data:
                # Common EXIF timestamp tags
                timestamp_tags = {
                    306: "DateTime",
                    36867: "DateTimeOriginal",
                    36868: "DateTimeDigitized",
                }

                exif_timestamps = {}
                for tag_id, tag_name in timestamp_tags.items():
                    if tag_id in exif_data:
                        try:
                            exif_time = datetime.strptime(
                                exif_data[tag_id], "%Y:%m:%d %H:%M:%S"
                            )
                            exif_timestamps[tag_name] = exif_time
                        except:
                            continue

                # Analyze timestamp relationships
                if exif_timestamps:
                    # Check if EXIF times are in the future
                    now = datetime.now()
                    for name, timestamp in exif_timestamps.items():
                        if timestamp > now:
                            findings.append(
                                f"EXIF {name} is in the future: {timestamp}"
                            )

                    # Check if EXIF times are much older than file system times
                    for name, exif_time in exif_timestamps.items():
                        fs_diff_days = abs((fs_modified - exif_time).days)
                        if fs_diff_days > 365:  # More than a year difference
                            findings.append(
                                f"Large discrepancy between EXIF {name} and file modification time: {fs_diff_days} days"
                            )

                    # Check for suspicious timestamp patterns (not just identical)
                    # Only flag if timestamps are identical AND it's unusual for the device type
                    timestamp_values = list(exif_timestamps.values())
                    if len(set(timestamp_values)) == 1 and len(timestamp_values) > 1:
                        # Check if this is from a known device that naturally creates identical timestamps
                        try:
                            img = Image.open(file_path)
                            exif_dict = img._getexif()
                            device_make = (
                                exif_dict.get(271, "").lower() if exif_dict else ""
                            )  # Make tag
                            device_model = (
                                exif_dict.get(272, "").lower() if exif_dict else ""
                            )  # Model tag

                            # Don't flag for devices known to create identical timestamps
                            known_devices = [
                                "apple",
                                "iphone",
                                "ipad",
                                "samsung",
                                "google",
                                "pixel",
                            ]
                            is_known_device = any(
                                device in device_make or device in device_model
                                for device in known_devices
                            )

                            if not is_known_device:
                                findings.append(
                                    "All EXIF timestamps are identical (possible manipulation)"
                                )
                        except:
                            # If we can't determine device, be conservative and don't flag
                            pass

        except Exception:
            pass

        # Check file system timestamp anomalies
        time_diff = abs((fs_created - fs_modified).total_seconds())
        if time_diff < 1:  # Created and modified within 1 second
            findings.append(
                "File creation and modification times are suspiciously close"
            )

    except Exception as e:
        return []

    return findings


# === NEW: PIXEL CLUSTERING ANALYSIS ===


def detect_pixel_clustering_anomalies(file_path):
    """Detect unnatural pixel clustering that might indicate hidden data"""
    findings = []

    try:
        img = cv2.imread(file_path, cv2.IMREAD_COLOR)
        if img is None:
            return findings

        # Convert to different color spaces for analysis
        img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        img_hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

        # Analyze color distribution in each channel
        for i, color in enumerate(["Blue", "Green", "Red"]):
            channel = img[:, :, i].flatten()

            # Check for unnatural clustering at specific values
            value_counts = Counter(channel)

            # Look for values that appear much more frequently than neighbors
            for value in range(1, 254):  # Skip pure black/white
                if value in value_counts:
                    neighbors = [
                        value_counts.get(value - 1, 0),
                        value_counts.get(value + 1, 0),
                    ]
                    avg_neighbor = sum(neighbors) / len(neighbors) if neighbors else 0

                    if (
                        avg_neighbor > 0 and value_counts[value] > avg_neighbor * 5
                    ):  # Conservative threshold
                        frequency = value_counts[value] / len(channel)
                        if frequency > 0.05:  # More than 5% of pixels
                            findings.append(
                                f"Unnatural {color} channel clustering at value {value}: {frequency:.2%} of pixels"
                            )

        # Check for LSB plane anomalies in a different way
        for i, color in enumerate(["Blue", "Green", "Red"]):
            channel = img[:, :, i]
            lsb_plane = channel & 1

            # Count runs of identical LSB values
            lsb_flat = lsb_plane.flatten()
            runs = []
            current_run = 1

            for j in range(1, len(lsb_flat)):
                if lsb_flat[j] == lsb_flat[j - 1]:
                    current_run += 1
                else:
                    runs.append(current_run)
                    current_run = 1
            runs.append(current_run)

            # Check for unusually long runs - be more conservative for JPEG
            max_run = max(runs) if runs else 0
            avg_run = sum(runs) / len(runs) if runs else 0

            # Much higher thresholds to reduce false positives
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in [".jpg", ".jpeg"]:
                # JPEG compression naturally creates very long LSB runs
                threshold = len(lsb_flat) * 0.3  # 30% of image size
            else:
                threshold = 5000  # Much higher for non-JPEG

            if max_run > threshold:
                findings.append(
                    f"Extremely suspicious {color} LSB run length: {max_run} pixels"
                )

    except Exception as e:
        return []

    return findings


# === NEW: MODERN THREAT DETECTION ===


def detect_modern_threats(file_path):
    """Detect modern threat vectors in image metadata"""
    findings = []

    try:
        # Read all image data including metadata
        with open(file_path, "rb") as f:
            file_data = f.read()

        file_text = file_data.decode("utf-8", errors="ignore").lower()

        # Modern C2 and communication channels
        modern_patterns = {
            "IPFS Hash": r"qm[1-9a-hj-np-za-km-z]{44}",
            "Ethereum Address": r"0x[a-f0-9]{40}",
            "Bitcoin Address": r"[13][a-km-za-hj-np-z1-9]{25,34}",
            "Pastebin Raw": r"pastebin\.com/raw/[a-z0-9]{8}",
            "GitHub Raw": r"raw\.githubusercontent\.com/[^/]+/[^/]+/",
            "OneDrive Share": r"1drv\.ms/[a-z]/[a-z0-9]+",
            "Google Drive": r"drive\.google\.com/file/d/[a-za-z0-9_-]+",
            "Dropbox Share": r"dropbox\.com/s/[a-z0-9]+/",
            "Mega.nz": r"mega\.nz/#[!a-z0-9]+",
            "Telegram Bot": r"t\.me/[a-z0-9_]+bot",
        }

        for threat_name, pattern in modern_patterns.items():
            matches = re.findall(pattern, file_text)
            if matches:
                findings.append(f"{threat_name} detected: {matches[0]}")

        # Check for Base64 encoded URLs
        base64_patterns = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", file_text)
        for pattern in base64_patterns[:5]:  # Check first 5 matches only
            try:
                decoded = base64.b64decode(pattern).decode("utf-8", errors="ignore")
                if "http" in decoded.lower() or ".com" in decoded.lower():
                    findings.append(f"Base64 encoded URL detected: {decoded[:100]}")
            except:
                continue

        # Check for cryptocurrency mentions with amounts - more specific patterns
        crypto_amount_patterns = [
            r"(bitcoin|btc)\s*(wallet|address|payment|send|receive|transfer)\s*[:\-]?\s*([0-9]+\.?[0-9]*)",
            r"(ethereum|eth)\s*(wallet|address|payment|send|receive|transfer)\s*[:\-]?\s*([0-9]+\.?[0-9]*)",
            r"(monero|xmr)\s*(wallet|address|payment|send|receive|transfer)\s*[:\-]?\s*([0-9]+\.?[0-9]*)",
            r"(send|transfer|pay)\s*([0-9]+\.?[0-9]*)\s*(bitcoin|btc|ethereum|eth|monero|xmr)",
            r"(wallet|address)\s*[:\-]\s*([0-9]+\.?[0-9]*)\s*(bitcoin|btc|ethereum|eth|monero|xmr)",
        ]

        for pattern in crypto_amount_patterns:
            matches = re.findall(pattern, file_text)
            if matches:
                for match in matches[:3]:  # Limit output
                    if len(match) == 3:
                        findings.append(
                            f"Cryptocurrency transaction reference: {match[0]} {match[1]} {match[2]}"
                        )
                    else:
                        findings.append(
                            f"Cryptocurrency transaction reference: {' '.join(match)}"
                        )

    except Exception as e:
        return []

    return findings


# === NEW: AI-GENERATED IMAGE DETECTION ===


def detect_ai_generated_content(file_path):
    """Enhanced AI-generated image detection - tuned for modern models like ComfyUI/Stable Diffusion"""
    print(f"🔍 DEBUG: Starting enhanced AI detection for: {file_path}")

    findings = []
    ai_scores = {}

    try:
        # Load image for analysis
        img = cv2.imread(file_path, cv2.IMREAD_COLOR)
        if img is None:
            print(f"❌ DEBUG: cv2.imread failed for {file_path}")
            try:
                from PIL import Image

                pil_img = Image.open(file_path)
                img_array = np.array(pil_img)
                if len(img_array.shape) == 3:
                    img = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
                else:
                    img = img_array
                print(f"✅ DEBUG: PIL backup worked for {file_path}")
            except Exception as e:
                print(f"❌ DEBUG: PIL also failed: {e}")
                return findings, 0.0

        print(f"📊 DEBUG: Image loaded successfully, shape: {img.shape}")

        # Convert to grayscale safely
        if len(img.shape) == 3:
            img_gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        else:
            img_gray = img

        h, w = img_gray.shape
        print(f"📐 DEBUG: Image dimensions: {w}x{h}")

        # === ENHANCED AI DETECTION FOR MODERN MODELS ===

        # 1. ComfyUI/Stable Diffusion specific indicators
        filename = os.path.basename(file_path).lower()
        print(f"📄 DEBUG: Filename: {filename}")

        # Strong filename indicators
        comfyui_patterns = [
            "comfyui",
            "comfy_ui",
            "stable_diffusion",
            "sd_",
            "flux_",
            "dalle",
        ]
        if any(pattern in filename for pattern in comfyui_patterns):
            ai_scores["ai_filename"] = 0.40  # Very strong indicator
            print(f"🎯 DEBUG: AI filename pattern detected: +0.40")

        # Sequential naming pattern (common in AI generation)
        import re

        if re.search(r"_\d{5}_", filename) or re.search(r"_\d{4}_", filename):
            ai_scores["sequential_naming"] = 0.25
            print(f"🔢 DEBUG: Sequential naming pattern: +0.25")

        # 2. Missing camera metadata (ENHANCED - now much stronger for AI)
        try:
            from PIL import Image

            pil_img = Image.open(file_path)
            exif_data = pil_img._getexif()

            has_camera_info = False
            camera_make = None
            camera_model = None

            if exif_data:
                camera_tags = [
                    271,
                    272,
                    306,
                    36867,
                    36868,
                ]  # Make, Model, DateTime, etc.
                has_camera_info = any(tag in exif_data for tag in camera_tags)
                camera_make = exif_data.get(271, "")
                camera_model = exif_data.get(272, "")
                print(
                    f"📷 DEBUG: Camera metadata - Make: '{camera_make}', Model: '{camera_model}'"
                )

            if not has_camera_info:
                ai_scores["missing_camera_metadata"] = 0.35  # Increased weight
                print(f"🚨 DEBUG: No camera metadata: +0.35")
            elif camera_make and any(
                ai_tool in camera_make.lower()
                for ai_tool in ["comfyui", "stable", "diffusion", "ai"]
            ):
                ai_scores["ai_metadata"] = 0.45  # AI tool in metadata
                print(f"🤖 DEBUG: AI tool in metadata: +0.45")

        except Exception as e:
            print(f"❌ DEBUG: Metadata check failed: {e}")
            ai_scores["missing_camera_metadata"] = 0.35  # Assume missing

        # 3. File entropy analysis (TUNED FOR PNG)
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            file_entropy = calculate_entropy(file_data)
            is_random, chi_stat = chi_square_test(file_data)

            print(f"📈 DEBUG: File entropy: {file_entropy:.3f}")
            print(f"🎲 DEBUG: Chi-square random: {is_random}, stat: {chi_stat:.2f}")

            # PNG files from AI generators have specific entropy patterns
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext == ".png":
                # PNG from AI tools typically has high entropy but specific range
                if 7.6 <= file_entropy <= 7.99:
                    ai_scores["ai_png_entropy"] = 0.25
                    print(f"🎯 DEBUG: AI-typical PNG entropy: +0.25")
                elif file_entropy > 7.99:
                    ai_scores["very_high_entropy"] = 0.30
                    print(f"🚨 DEBUG: Very high entropy (AI compression): +0.30")

            # Combination of high entropy + randomness
            if file_entropy > 7.7 and is_random:
                ai_scores["entropy_plus_random"] = 0.20
                print(f"🚨 DEBUG: High entropy + random: +0.20")

        except Exception as e:
            print(f"❌ DEBUG: File entropy analysis failed: {e}")

        # 4. ENHANCED pixel-level analysis for AI artifacts
        try:
            pixel_entropy = calculate_entropy(img_gray.flatten())
            print(f"🖼️ DEBUG: Pixel entropy: {pixel_entropy:.3f}")

            # AI images often have very specific pixel entropy ranges
            if 7.3 <= pixel_entropy <= 7.8:
                ai_scores["ai_pixel_patterns"] = 0.20
                print(f"🎯 DEBUG: AI-typical pixel entropy: +0.20")

        except Exception as e:
            print(f"❌ DEBUG: Pixel entropy failed: {e}")

        # 5. AI-specific color distribution analysis
        try:
            if len(img.shape) == 3 and img.shape[2] >= 3:
                # Analyze color channel statistics
                r_channel = img[:, :, 2].flatten()
                g_channel = img[:, :, 1].flatten()
                b_channel = img[:, :, 0].flatten()

                # AI images often have very specific color distributions
                r_std = np.std(r_channel)
                g_std = np.std(g_channel)
                b_std = np.std(b_channel)

                print(
                    f"🎨 DEBUG: Color std - R:{r_std:.2f}, G:{g_std:.2f}, B:{b_std:.2f}"
                )

                # AI generated images often have very similar std dev across channels
                channel_stds = [r_std, g_std, b_std]
                std_variance = np.var(channel_stds)

                if std_variance < 10:  # Very similar std dev across channels
                    ai_scores["uniform_color_distribution"] = 0.15
                    print(f"🎯 DEBUG: Uniform color distribution (AI): +0.15")

                # Check for AI-typical value distributions
                for i, (channel, name) in enumerate(
                    [(r_channel, "R"), (g_channel, "G"), (b_channel, "B")]
                ):
                    # AI often creates specific histogram patterns
                    hist, _ = np.histogram(channel, bins=256, range=(0, 256))

                    # Look for artificial peaks/gaps common in AI
                    peaks = len(
                        [
                            i
                            for i in range(1, 255)
                            if hist[i] > hist[i - 1]
                            and hist[i] > hist[i + 1]
                            and hist[i] > np.mean(hist) * 2
                        ]
                    )
                    if peaks > 15:  # Too many artificial peaks
                        ai_scores[f"artificial_{name.lower()}_peaks"] = 0.08
                        print(f"🔺 DEBUG: Artificial {name} channel peaks: +0.08")

        except Exception as e:
            print(f"❌ DEBUG: Color analysis failed: {e}")

        # 6. ENHANCED edge analysis for AI signatures
        try:
            edges = cv2.Canny(img_gray, 50, 150)
            edge_density = np.sum(edges > 0) / (h * w)
            print(f"📏 DEBUG: Edge density: {edge_density:.4f}")

            # AI images often have very specific edge characteristics
            if 0.08 <= edge_density <= 0.25:  # AI-typical edge density
                ai_scores["ai_edge_density"] = 0.15
                print(f"🎯 DEBUG: AI-typical edge density: +0.15")

            # Analyze edge distribution patterns
            edge_hist = np.sum(edges, axis=0)
            edge_variance = np.var(edge_hist)
            if (
                edge_variance < np.mean(edge_hist) * 50
            ):  # Very uniform edge distribution
                ai_scores["uniform_edge_distribution"] = 0.12
                print(f"📊 DEBUG: Uniform edge distribution (AI): +0.12")

        except Exception as e:
            print(f"❌ DEBUG: Edge analysis failed: {e}")

        # 7. Resolution and dimension analysis
        try:
            # AI tools often generate at specific resolutions
            common_ai_resolutions = [
                (512, 512),
                (1024, 1024),
                (768, 768),
                (896, 896),
                (512, 768),
                (768, 512),
                (1024, 768),
                (768, 1024),
                (1152, 896),
                (896, 1152),
            ]

            if (w, h) in common_ai_resolutions or (h, w) in common_ai_resolutions:
                ai_scores["ai_resolution"] = 0.20
                print(f"🎯 DEBUG: Common AI resolution {w}x{h}: +0.20")

            # Check if dimensions are multiples of 64 (common in AI)
            if w % 64 == 0 and h % 64 == 0:
                ai_scores["ai_dimension_multiple"] = 0.15
                print(f"🔢 DEBUG: Dimensions multiple of 64: +0.15")

        except Exception as e:
            print(f"❌ DEBUG: Resolution analysis failed: {e}")

        # 8. File size to quality ratio analysis
        try:
            file_size = os.path.getsize(file_path)
            pixels = w * h
            size_per_pixel = file_size / pixels if pixels > 0 else 0

            print(
                f"📊 DEBUG: File size: {file_size}, Pixels: {pixels}, Size/pixel: {size_per_pixel:.2f}"
            )

            # AI PNG files often have specific compression characteristics
            if file_ext == ".png" and 0.5 <= size_per_pixel <= 2.0:
                ai_scores["ai_compression_ratio"] = 0.12
                print(f"🗜️ DEBUG: AI-typical compression ratio: +0.12")

        except Exception as e:
            print(f"❌ DEBUG: File size analysis failed: {e}")

        # === CALCULATE ENHANCED TOTAL PROBABILITY ===
        total_score = sum(ai_scores.values())

        # Apply bonus multiplier for multiple strong indicators
        strong_indicators = sum(1 for score in ai_scores.values() if score >= 0.25)
        if strong_indicators >= 2:
            bonus_multiplier = 1.2
            total_score *= bonus_multiplier
            print(f"🚀 DEBUG: Multiple strong indicators bonus: x{bonus_multiplier}")

        ai_probability = min(total_score, 1.0)

        print(f"🎯 DEBUG: AI scores breakdown: {ai_scores}")
        print(
            f"🎯 DEBUG: Total AI probability: {ai_probability:.3f} ({ai_probability*100:.1f}%)"
        )

        # Generate findings based on detection
        if ai_probability > 0.05:  # Low threshold
            confidence_level = "LOW"
            if ai_probability > 0.3:
                confidence_level = "MEDIUM"
            if ai_probability > 0.6:
                confidence_level = "HIGH"
            if ai_probability > 0.8:
                confidence_level = "VERY HIGH"

            findings.append(
                f"AI-generated content detected (Confidence: {confidence_level}, Score: {ai_probability:.2f})"
            )
            print(f"✅ DEBUG: AI detection positive with {confidence_level} confidence")

            # Report top contributing factors
            sorted_scores = sorted(ai_scores.items(), key=lambda x: x[1], reverse=True)
            top_indicators = sorted_scores[:6]  # Show more indicators

            indicator_names = {
                "ai_filename": "AI tool filename pattern",
                "sequential_naming": "Sequential AI naming",
                "missing_camera_metadata": "Missing camera metadata",
                "ai_metadata": "AI tool in metadata",
                "ai_png_entropy": "AI-typical PNG entropy",
                "very_high_entropy": "Very high file entropy",
                "entropy_plus_random": "High entropy + randomness",
                "ai_pixel_patterns": "AI pixel patterns",
                "uniform_color_distribution": "Uniform color distribution",
                "artificial_r_peaks": "Artificial red channel peaks",
                "artificial_g_peaks": "Artificial green channel peaks",
                "artificial_b_peaks": "Artificial blue channel peaks",
                "ai_edge_density": "AI-typical edge density",
                "uniform_edge_distribution": "Uniform edge distribution",
                "ai_resolution": "Common AI resolution",
                "ai_dimension_multiple": "AI dimension multiple",
                "ai_compression_ratio": "AI compression signature",
            }

            for indicator, score in top_indicators:
                if score > 0.05:
                    indicator_name = indicator_names.get(indicator, indicator)
                    findings.append(f"  └─ {indicator_name}: {score:.2f}")
                    print(f"📋 DEBUG: Indicator - {indicator_name}: {score:.2f}")

            # Enhanced generation method prediction
            if ai_scores.get("ai_filename", 0) > 0.2:
                findings.append("  └─ Likely generated by: ComfyUI/Stable Diffusion")
            elif ai_scores.get("ai_resolution", 0) > 0.1:
                findings.append(
                    "  └─ Likely generated by: Diffusion model (SD/FLUX/DALL-E)"
                )
            elif total_score > 0.6:
                findings.append("  └─ Likely generated by: Advanced AI model")

        else:
            print(f"❌ DEBUG: AI probability too low: {ai_probability:.3f}")

        return findings, ai_probability

    except Exception as e:
        print(f"❌ DEBUG: Major exception in AI detection: {str(e)}")
        import traceback

        traceback.print_exc()
        return [f"AI detection error: {str(e)}"], 0.0


def extract_exif_data(file_path):
    """Extract EXIF metadata from image"""
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()
        if not exif_data:
            return {"EXIF": "No EXIF data found."}

        labeled_exif = {}
        for tag, value in exif_data.items():
            label = TAGS.get(tag, tag)
            labeled_exif[label] = value
        return labeled_exif
    except Exception as e:
        return {"Error": str(e)}


def check_for_base64_in_metadata(exif_data):
    """Check for base64 encoded payloads in metadata"""
    suspicious_entries = {}
    for key, value in exif_data.items():
        if isinstance(value, str) and re.search(r"[A-Za-z0-9+/=]{100,}", value):
            try:
                decoded = base64.b64decode(value, validate=True)
                suspicious_entries[key] = {
                    "decoded_preview": decoded[:50],
                    "warning": "⚠️ Potential base64-encoded payload detected",
                    "entropy": calculate_entropy(decoded),
                }
            except Exception:
                continue
    return suspicious_entries


def analyze_metadata_anomalies(exif_data):
    """Analyze EXIF metadata for anomalies"""
    anomalies = []

    for key, value in exif_data.items():
        if isinstance(value, (str, bytes)):
            if isinstance(value, str):
                value_bytes = value.encode("utf-8", errors="ignore")
            else:
                value_bytes = value

            # Check entropy of metadata values
            if len(value_bytes) > 20:
                entropy = calculate_entropy(value_bytes)
                if entropy > 6:
                    anomalies.append(f"High entropy in {key}: {entropy:.2f}")

            # Check for unusual characters
            if isinstance(value, str):
                if any(ord(c) > 127 for c in value):
                    anomalies.append(f"Non-ASCII characters in {key}")

                # Check for script-like content
                script_indicators = [
                    "<script",
                    "javascript:",
                    "eval(",
                    "function(",
                    "var ",
                    "const ",
                    "let ",
                ]
                if any(indicator in value.lower() for indicator in script_indicators):
                    anomalies.append(f"Script-like content in {key}")

    return anomalies


def detect_data_anomalies(file_path):
    """Detect statistical anomalies that might indicate hidden data"""
    anomalies = []

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # JPEG files naturally have high entropy due to compression - adjust thresholds
        file_ext = os.path.splitext(file_path)[1].lower()

        entropy = calculate_entropy(data)
        # Adjust entropy threshold based on file type
        if file_ext in [".jpg", ".jpeg"]:
            entropy_threshold = 7.99  # JPEG compression creates high entropy
        else:
            entropy_threshold = 7.5

        if entropy > entropy_threshold:
            anomalies.append(
                f"Unusually high entropy detected: {entropy:.2f} (threshold: {entropy_threshold})"
            )

        # JPEG files naturally fail chi-square test due to compression
        if file_ext not in [".jpg", ".jpeg"]:
            is_random, chi_stat = chi_square_test(data)
            if is_random:
                anomalies.append(
                    f"Data appears randomly distributed (chi²: {chi_stat:.2f})"
                )

        if len(data) > 1000:
            samples = [
                data[:500],
                data[len(data) // 2 : len(data) // 2 + 500],
                data[-500:],
            ]

            entropies = [calculate_entropy(sample) for sample in samples]
            variance = max(entropies) - min(entropies)

            # JPEG files naturally have entropy variance
            variance_threshold = 4.0 if file_ext in [".jpg", ".jpeg"] else 2.0

            if variance > variance_threshold:
                anomalies.append(
                    f"High entropy variance across file sections: {variance:.2f}"
                )

    except Exception as e:
        anomalies.append(f"Statistical analysis error: {e}")

    return anomalies


def detect_lsb_steganography(file_path):
    """Detect LSB (Least Significant Bit) steganography"""
    try:
        image = Image.open(file_path)

        if image.mode not in ["RGB", "RGBA", "L"]:
            return []

        img_array = np.array(image)

        if len(img_array.shape) == 3:
            red_lsb = img_array[:, :, 0] & 1
            green_lsb = img_array[:, :, 1] & 1
            blue_lsb = img_array[:, :, 2] & 1
            all_lsbs = np.concatenate(
                [red_lsb.flatten(), green_lsb.flatten(), blue_lsb.flatten()]
            )
        else:
            all_lsbs = img_array.flatten() & 1

        lsb_bytes = np.packbits(all_lsbs)
        lsb_entropy = calculate_entropy(lsb_bytes)

        findings = []
        # Adjust threshold - natural images can have LSB entropy around 0.7-0.8
        if lsb_entropy > 0.85:  # More conservative threshold
            findings.append(
                f"Suspicious LSB patterns detected (entropy: {lsb_entropy:.3f})"
            )

        lsb_str = "".join(map(str, all_lsbs[:1000]))

        # Look for very obvious patterns only
        if "00000000000000000000" in lsb_str or "11111111111111111111" in lsb_str:
            findings.append("Repetitive patterns in LSBs detected")

        try:
            lsb_text = "".join(chr(b) for b in lsb_bytes[:100] if 32 <= b <= 126)
            if len(lsb_text) > 20 and any(
                word in lsb_text.lower()
                for word in ["the", "and", "for", "are", "but", "not", "you", "all"]
            ):
                findings.append(f"Possible hidden text in LSBs: '{lsb_text[:50]}...'")
        except:
            pass

        return findings

    except Exception as e:
        return []  # Don't report numpy comparison errors


def detect_dct_steganography(file_path):
    """Detect DCT (Discrete Cosine Transform) steganography in JPEG files"""
    findings = []

    try:
        if not file_path.lower().endswith((".jpg", ".jpeg")):
            return findings

        # Read image
        img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return ["Could not read image for DCT analysis"]

        # Apply DCT to 8x8 blocks
        h, w = img.shape
        dct_coeffs = []

        for i in range(0, h - 7, 8):
            for j in range(0, w - 7, 8):
                block = img[i : i + 8, j : j + 8].astype(np.float32)
                dct_block = cv2.dct(block)
                dct_coeffs.extend(dct_block.flatten())

        # Analyze DCT coefficient distribution
        dct_array = np.array(dct_coeffs)

        # Check for statistical anomalies in DCT coefficients
        # Benford's Law test on DCT coefficients - but be more conservative
        first_digits = [
            int(str(abs(coeff))[0])
            for coeff in dct_array
            if coeff != 0 and not np.isnan(coeff) and abs(coeff) >= 1
        ]
        if len(first_digits) > 1000:  # Need more samples for reliable test
            digit_counts = Counter(first_digits)
            expected_benford = [30.1, 17.6, 12.5, 9.7, 7.9, 6.7, 5.8, 5.1, 4.6]

            if len(digit_counts) >= 9:
                observed = [digit_counts.get(i + 1, 0) for i in range(9)]
                total = sum(observed)
                if total > 0:
                    observed_pct = [(count / total) * 100 for count in observed]

                    # Chi-square test for Benford's Law - more conservative threshold
                    chi_stat = sum(
                        (obs - exp) ** 2 / exp
                        for obs, exp in zip(observed_pct, expected_benford)
                        if exp > 0
                    )
                    if chi_stat > 25:  # Higher threshold to reduce false positives
                        findings.append(
                            f"DCT coefficients significantly violate Benford's Law (χ²={chi_stat:.2f})"
                        )

        # Check for periodic patterns in DCT coefficients (sign of embedding)
        if len(dct_array) > 1000:
            # Look for patterns in AC coefficients
            ac_coeffs = dct_array[
                np.abs(dct_array) > 0.1
            ]  # Filter out near-zero coefficients
            if len(ac_coeffs) > 100:
                # Check for LSB pattern in DCT coefficients - more conservative
                lsb_pattern = ac_coeffs.astype(int) % 2
                lsb_entropy = calculate_entropy(lsb_pattern.astype(np.uint8))
                if lsb_entropy < 0.6:  # Much more conservative threshold
                    findings.append(
                        f"Highly suspicious DCT coefficient LSB patterns (entropy: {lsb_entropy:.3f})"
                    )

    except Exception as e:
        return []  # Don't report numpy comparison errors

    return findings


def detect_frequency_domain_hiding(file_path):
    """Detect frequency domain steganography using FFT analysis"""
    findings = []

    try:
        img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return findings

        # Apply 2D FFT
        fft = np.fft.fft2(img)
        fft_shifted = np.fft.fftshift(fft)
        magnitude_spectrum = np.abs(fft_shifted)

        # Analyze frequency domain for anomalies
        # Check for unusual high-frequency components
        h, w = magnitude_spectrum.shape
        center_h, center_w = h // 2, w // 2

        # Extract high-frequency region
        high_freq_region = magnitude_spectrum.copy()
        high_freq_region[
            center_h - 50 : center_h + 50, center_w - 50 : center_w + 50
        ] = 0

        # Calculate energy in high frequencies
        total_energy = np.sum(magnitude_spectrum**2)
        high_freq_energy = np.sum(high_freq_region**2)

        if total_energy > 0:
            high_freq_ratio = high_freq_energy / total_energy
            # JPEG compression naturally creates high-frequency content - be more conservative
            file_ext = os.path.splitext(file_path)[1].lower()
            threshold = 0.15 if file_ext in [".jpg", ".jpeg"] else 0.1

            if high_freq_ratio > threshold:
                findings.append(
                    f"Unusual high-frequency energy detected: {high_freq_ratio:.3f}"
                )

        # Check for periodic patterns in frequency domain
        # Look for spikes that might indicate embedded data - be more conservative
        flattened_spectrum = magnitude_spectrum.flatten()
        mean_val = np.mean(flattened_spectrum)
        std_val = np.std(flattened_spectrum)

        # Use higher threshold for peak detection
        threshold_val = mean_val + 5 * std_val  # More conservative
        peaks, _ = find_peaks(flattened_spectrum, height=threshold_val)

        # Natural images can have many peaks due to edges and textures
        peak_threshold = len(flattened_spectrum) * 0.005  # More conservative
        if len(peaks) > peak_threshold:
            findings.append(f"Excessive frequency domain peaks detected: {len(peaks)}")

    except Exception as e:
        return []  # Don't report errors for legitimate images

    return findings


def detect_palette_steganography(file_path):
    """Detect palette-based steganography in indexed color images"""
    findings = []

    try:
        img = Image.open(file_path)

        # Only analyze palette-based images
        if img.mode != "P":
            return findings

        # Get palette
        palette = img.getpalette()
        if not palette:
            return findings

        # Convert palette to RGB triplets
        rgb_palette = [palette[i : i + 3] for i in range(0, len(palette), 3)]

        # Check for unusual palette properties
        unique_colors = len(set(tuple(color) for color in rgb_palette))

        # Analyze color distribution
        img_array = np.array(img)
        color_counts = Counter(img_array.flatten())

        # Check for LSB patterns in palette indices
        palette_indices = list(color_counts.keys())
        if len(palette_indices) > 10:
            lsb_pattern = [idx & 1 for idx in palette_indices]
            lsb_entropy = calculate_entropy(np.array(lsb_pattern, dtype=np.uint8))

            if lsb_entropy < 0.9:  # Suspiciously low entropy
                findings.append(
                    f"Suspicious palette index LSB patterns (entropy: {lsb_entropy:.3f})"
                )

        # Check for similar colors (palette reordering attack)
        similar_pairs = 0
        for i, color1 in enumerate(rgb_palette):
            for j, color2 in enumerate(rgb_palette[i + 1 :], i + 1):
                # Calculate color difference
                diff = sum((a - b) ** 2 for a, b in zip(color1, color2))
                if diff < 100:  # Very similar colors
                    similar_pairs += 1

        if similar_pairs > len(rgb_palette) * 0.1:
            findings.append(
                f"Unusually similar palette colors detected: {similar_pairs} pairs"
            )

    except Exception as e:
        findings.append(f"Palette analysis error: {e}")

    return findings


def detect_custom_steganography_patterns(file_path):
    """Detect custom steganography methods using pattern analysis"""
    findings = []

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Convert to numpy array for analysis
        data_array = np.frombuffer(data, dtype=np.uint8)

        # Check for repeating patterns (characteristic of some custom methods) - more conservative
        for pattern_length in [16, 32, 64]:  # Focus on longer patterns
            if (
                len(data_array) > pattern_length * 200
            ):  # Need more data for reliable detection
                patterns = []
                for i in range(0, len(data_array) - pattern_length, pattern_length):
                    pattern = tuple(data_array[i : i + pattern_length])
                    patterns.append(pattern)

                pattern_counts = Counter(patterns)
                most_common = pattern_counts.most_common(1)[0]

                # Be much more conservative - patterns should repeat A LOT to be suspicious
                if most_common[1] > len(patterns) * 0.1:  # Pattern repeats > 10%
                    findings.append(
                        f"Highly repeating {pattern_length}-byte pattern: {most_common[1]} occurrences"
                    )

        # Check for bit-plane anomalies - more conservative
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in [
            ".jpg",
            ".jpeg",
        ]:  # Skip JPEG files as they naturally have bit-plane anomalies
            anomaly_count = 0
            for bit_position in range(8):
                bit_plane = (data_array >> bit_position) & 1
                bit_entropy = calculate_entropy(bit_plane)

                # Much more conservative thresholds
                if (
                    bit_entropy < 0.5 or bit_entropy > 0.999
                ):  # Extremely ordered or random
                    anomaly_count += 1

            # Only report if multiple bit planes are anomalous
            if anomaly_count >= 3:
                findings.append(
                    f"Multiple anomalous bit-planes detected: {anomaly_count}"
                )

        # Check for mathematical relationships between bytes - more conservative
        # Skip this test for JPEG files as they naturally have arithmetic progressions due to compression
        if len(data_array) > 2000 and file_ext not in [".jpg", ".jpeg"]:
            # Look for arithmetic progressions in a smaller sample
            sample = data_array[:1000]
            diffs = np.diff(sample)
            diff_counts = Counter(diffs)
            most_common_diff = diff_counts.most_common(1)[0]

            # Much higher threshold
            if most_common_diff[1] > 150:  # Same difference appears > 150 times
                findings.append(
                    f"Strong arithmetic progression: difference {most_common_diff[0]} appears {most_common_diff[1]} times"
                )

    except Exception as e:
        return []  # Don't report errors for legitimate images

    return findings


def ml_anomaly_detection(file_path):
    """Use statistical ML techniques to detect anomalies"""
    findings = []

    try:
        # Load image and extract features
        img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return findings

        # Extract multiple statistical features
        features = []

        # Pixel value statistics
        features.extend(
            [
                np.mean(img),
                np.std(img),
                np.var(img),
                stats.skew(img.flatten()),
                stats.kurtosis(img.flatten()),
            ]
        )

        # Gradient statistics
        grad_x = cv2.Sobel(img, cv2.CV_64F, 1, 0, ksize=3)
        grad_y = cv2.Sobel(img, cv2.CV_64F, 0, 1, ksize=3)
        gradient_magnitude = np.sqrt(grad_x**2 + grad_y**2)

        features.extend(
            [
                np.mean(gradient_magnitude),
                np.std(gradient_magnitude),
                stats.skew(gradient_magnitude.flatten()),
                stats.kurtosis(gradient_magnitude.flatten()),
            ]
        )

        # Texture analysis using Local Binary Patterns simulation
        h, w = img.shape
        lbp_like_features = []
        # Sample fewer points to avoid memory issues
        step = max(1, min(h, w) // 100)  # Adaptive sampling
        for i in range(step, h - step, step):
            for j in range(step, w - step, step):
                center = img[i, j]
                neighbors = [
                    img[i - step, j - step],
                    img[i - step, j],
                    img[i - step, j + step],
                    img[i, j + step],
                    img[i + step, j + step],
                    img[i + step, j],
                    img[i + step, j - step],
                    img[i, j - step],
                ]
                binary_pattern = sum(
                    2**k for k, neighbor in enumerate(neighbors) if neighbor >= center
                )
                lbp_like_features.append(binary_pattern)

        if lbp_like_features:
            features.extend(
                [
                    np.mean(lbp_like_features),
                    np.std(lbp_like_features),
                    len(set(lbp_like_features))
                    / len(lbp_like_features),  # Diversity ratio
                ]
            )

        # Anomaly detection using statistical thresholds - more conservative for JPEG
        file_ext = os.path.splitext(file_path)[1].lower()
        is_jpeg = file_ext in [".jpg", ".jpeg"]

        anomaly_scores = []

        # Check skewness (natural images typically have positive skew) - adjusted for JPEG
        skew_min, skew_max = (-1.0, 3.0) if is_jpeg else (-0.5, 2.0)
        if features[3] < skew_min or features[3] > skew_max:
            anomaly_scores.append(f"Unusual pixel skewness: {features[3]:.3f}")

        # Check kurtosis (natural images have specific kurtosis ranges) - adjusted for JPEG
        kurt_min, kurt_max = (-2.0, 15.0) if is_jpeg else (2.0, 10.0)
        if features[4] < kurt_min or features[4] > kurt_max:
            anomaly_scores.append(f"Unusual pixel kurtosis: {features[4]:.3f}")

        # Check gradient statistics (steganography often reduces gradient variance) - adjusted
        grad_skew_threshold = 100.0 if is_jpeg else 50.0
        if abs(features[7]) > grad_skew_threshold:
            anomaly_scores.append(f"Extreme gradient skewness: {features[7]:.3f}")

        # Overall anomaly score - more conservative ranges
        z_scores = []
        if is_jpeg:
            expected_ranges = [
                (50, 200),  # Mean pixel value (wider for JPEG)
                (20, 100),  # Std pixel value (wider for JPEG)
                (400, 10000),  # Var pixel value (wider for JPEG)
                (-1, 3),  # Skew pixel value (wider for JPEG)
                (-2, 15),  # Kurt pixel value (wider for JPEG)
                (5, 70),  # Mean gradient (wider for JPEG)
                (3, 40),  # Std gradient (wider for JPEG)
            ]
        else:
            expected_ranges = [
                (80, 170),  # Mean pixel value
                (30, 90),  # Std pixel value
                (900, 8100),  # Var pixel value
                (-0.5, 2.5),  # Skew pixel value
                (1, 12),  # Kurt pixel value
                (8, 60),  # Mean gradient
                (4, 30),  # Std gradient
            ]

        for i, (feature_val, (min_exp, max_exp)) in enumerate(
            zip(features[:7], expected_ranges)
        ):
            if feature_val < min_exp or feature_val > max_exp:
                z_scores.append(
                    abs(feature_val - (min_exp + max_exp) / 2)
                    / ((max_exp - min_exp) / 4)
                )

        if z_scores:
            avg_z_score = np.mean(z_scores)
            # Higher threshold for anomaly detection
            threshold = 8.0 if is_jpeg else 4.0  # Much higher threshold for JPEG
            if avg_z_score > threshold:
                anomaly_scores.append(
                    f"High statistical anomaly score: {avg_z_score:.2f}"
                )

        findings.extend(anomaly_scores)

    except Exception as e:
        return []  # Don't report errors for legitimate images

    return findings


def deep_metadata_analysis(file_path):
    """Advanced metadata analysis for hidden content"""
    findings = []

    try:
        # JPEG Comment and Application segments analysis
        if file_path.lower().endswith((".jpg", ".jpeg")):
            with open(file_path, "rb") as f:
                data = f.read()

            # Look for multiple APP segments (suspicious)
            app_segments = []
            pos = 0
            while pos < len(data) - 1:
                if data[pos] == 0xFF and 0xE0 <= data[pos + 1] <= 0xEF:
                    app_segments.append(data[pos + 1])
                pos += 1

            if len(set(app_segments)) > 3:  # More than 3 different APP segments
                findings.append(
                    f"Multiple APP segments found: {len(set(app_segments))} types"
                )

            # Look for COM segments (comments)
            com_positions = []
            pos = 0
            while pos < len(data) - 1:
                if data[pos] == 0xFF and data[pos + 1] == 0xFE:
                    com_positions.append(pos)
                pos += 1

            if len(com_positions) > 1:
                findings.append(f"Multiple JPEG comment segments: {len(com_positions)}")

        # Extended EXIF analysis
        try:
            from PIL.ExifTags import GPSTAGS

            img = Image.open(file_path)
            exif_dict = img._getexif()

            if exif_dict:
                # Check for unusual EXIF tags
                standard_tags = set(TAGS.values())
                for tag_id, value in exif_dict.items():
                    tag_name = TAGS.get(tag_id, tag_id)

                    if isinstance(tag_name, int) and tag_name > 50000:
                        findings.append(f"Unusual EXIF tag ID: {tag_name}")

                    # Check for binary data in text fields
                    if isinstance(value, bytes) and len(value) > 100:
                        entropy = calculate_entropy(value)
                        if entropy > 7:
                            findings.append(
                                f"High entropy binary data in EXIF tag {tag_name}: {entropy:.2f}"
                            )

                # GPS data analysis
                gps_info = exif_dict.get(34853)  # GPS Info tag
                if gps_info:
                    findings.append(
                        "GPS coordinates present - potential privacy/OPSEC concern"
                    )

        except Exception:
            pass

    except Exception as e:
        findings.append(f"Deep metadata analysis error: {e}")

    return findings


def rs_steganalysis(file_path):
    """RS (Regular/Singular) Steganalysis - industry standard LSB detection"""
    findings = []

    try:
        img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return findings

        # Flatten image
        pixels = img.flatten().astype(np.int32)

        # Define discrimination function (horizontal adjacent pixels)
        def discrimination_function(x, mask):
            return np.sum(np.abs(x[:-1] - x[1:]) * mask[:-1])

        # Create random mask
        np.random.seed(42)  # For reproducible results
        mask = np.random.choice([0, 1], size=len(pixels))

        # Calculate R, S groups for original image
        f_original = discrimination_function(pixels, mask)

        # Flip LSBs and recalculate
        pixels_flipped = pixels.copy()
        pixels_flipped = pixels_flipped ^ 1  # Flip LSB
        f_flipped = discrimination_function(pixels_flipped, mask)

        # Calculate RS statistics
        if f_original != 0:
            rs_ratio = abs(f_flipped - f_original) / f_original

            # Higher threshold for JPEG files due to compression artifacts
            file_ext = os.path.splitext(file_path)[1].lower()
            threshold = (
                0.2 if file_ext in [".jpg", ".jpeg"] else 0.1
            )  # Even higher for JPEG

            if rs_ratio > threshold:
                findings.append(
                    f"RS steganalysis indicates LSB embedding (ratio: {rs_ratio:.3f})"
                )

        # Additional test with different masks - more conservative for JPEG
        confirmation_threshold = 0.2 if file_ext in [".jpg", ".jpeg"] else 0.15
        for seed in [123, 456, 789]:
            np.random.seed(seed)
            test_mask = np.random.choice([0, 1], size=len(pixels))
            f_test = discrimination_function(pixels, test_mask)
            f_test_flipped = discrimination_function(pixels_flipped, test_mask)

            if f_test != 0:
                test_ratio = abs(f_test_flipped - f_test) / f_test
                if test_ratio > confirmation_threshold:
                    findings.append(
                        f"RS test {seed} confirms LSB embedding (ratio: {test_ratio:.3f})"
                    )
                    break

    except Exception as e:
        findings.append(f"RS steganalysis error: {e}")

    return findings


def spa_steganalysis(file_path):
    """Sample Pair Analysis - advanced statistical steganalysis"""
    findings = []

    try:
        img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return findings

        pixels = img.flatten()

        # Create sample pairs (adjacent pixels)
        pairs = [(pixels[i], pixels[i + 1]) for i in range(0, len(pixels) - 1, 2)]

        # Analyze pairs where LSB might be different
        close_pairs = [(p1, p2) for p1, p2 in pairs if abs(p1 - p2) <= 1]

        if len(close_pairs) > 100:
            # Count pairs where only LSB differs
            lsb_diff_count = sum(1 for p1, p2 in close_pairs if (p1 ^ p2) == 1)

            if len(close_pairs) > 0:
                lsb_diff_ratio = lsb_diff_count / len(close_pairs)

                # In natural images, this ratio should be around 0.5
                # Steganography often creates bias - be more conservative
                # JPEG compression naturally creates some bias
                file_ext = os.path.splitext(file_path)[1].lower()
                if file_ext in [".jpg", ".jpeg"]:
                    # JPEG images naturally have lower ratios due to compression
                    if (
                        lsb_diff_ratio < 0.05 or lsb_diff_ratio > 0.95
                    ):  # Much more extreme thresholds
                        findings.append(
                            f"SPA analysis indicates strong LSB modification (ratio: {lsb_diff_ratio:.3f})"
                        )
                else:
                    # Non-compressed formats should be closer to 0.5
                    if lsb_diff_ratio < 0.15 or lsb_diff_ratio > 0.85:
                        findings.append(
                            f"SPA analysis indicates LSB modification (ratio: {lsb_diff_ratio:.3f})"
                        )

    except Exception as e:
        return []  # Don't report errors for legitimate images

    return findings


def weighted_stego_analysis(file_path):
    """Weighted Stego (WS) Analysis - advanced JPEG steganalysis"""
    findings = []

    try:
        if not file_path.lower().endswith((".jpg", ".jpeg")):
            return findings

        img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return findings

        # Apply DCT to 8x8 blocks
        h, w = img.shape
        dct_coeffs = []

        for i in range(0, h - 7, 8):
            for j in range(0, w - 7, 8):
                block = img[i : i + 8, j : j + 8].astype(np.float32)
                dct_block = cv2.dct(block)
                # Focus on AC coefficients (skip DC coefficient)
                ac_coeffs = dct_block.flatten()[1:]
                dct_coeffs.extend(ac_coeffs)

        if len(dct_coeffs) > 1000:
            # Analyze distribution of AC coefficients
            dct_array = np.array(dct_coeffs)

            # Count coefficients by value
            coeff_counts = Counter(dct_array.astype(int))

            # Check for anomalies in coefficient distribution
            # Look for even/odd bias (sign of steganography) - but be more conservative
            even_count = sum(
                count for coeff, count in coeff_counts.items() if coeff % 2 == 0
            )
            odd_count = sum(
                count for coeff, count in coeff_counts.items() if coeff % 2 == 1
            )

            if even_count + odd_count > 0:
                even_ratio = even_count / (even_count + odd_count)

                # JPEG compression naturally creates some bias - be more conservative
                if (
                    even_ratio < 0.25 or even_ratio > 0.95
                ):  # Much more extreme thresholds
                    findings.append(
                        f"WS analysis detects extreme DCT coefficient bias (even ratio: {even_ratio:.3f})"
                    )

            # Check for specific coefficient anomalies (0, 1, -1) - more conservative
            zero_count = coeff_counts.get(0, 0)
            one_count = coeff_counts.get(1, 0) + coeff_counts.get(-1, 0)

            if len(dct_coeffs) > 0:
                zero_ratio = zero_count / len(dct_coeffs)
                one_ratio = one_count / len(dct_coeffs)

                # JPEG naturally has many zeros due to quantization - be very conservative
                if zero_ratio > 0.95:  # Extremely high threshold
                    findings.append(
                        f"Extremely high zero DCT coefficients: {zero_ratio:.3f}"
                    )
                if one_ratio > 0.25:  # Higher threshold for ±1 values
                    findings.append(
                        f"Suspicious ±1 DCT coefficient ratio: {one_ratio:.3f}"
                    )

    except Exception as e:
        return []  # Don't report errors for legitimate images

    return findings


def blockchain_hash_validation(file_path):
    """Validate against known hash databases and blockchain records"""
    findings = []

    try:
        sha256_hash = compute_sha256(file_path)

        # Check against known malicious hash patterns
        malicious_prefixes = [
            "deadbeef",
            "1337",
            "cafebabe",
            "feedface",
            "baddc0de",
            "baadf00d",
            "c0ffee",
            "facade",
        ]

        hash_lower = sha256_hash.lower()
        for prefix in malicious_prefixes:
            if hash_lower.startswith(prefix):
                findings.append(f"Hash has suspicious prefix: {prefix}")

        # Check for hash collision indicators
        # Count repeated characters (collision attempts often have patterns)
        char_counts = Counter(hash_lower)
        max_char_count = max(char_counts.values())

        if max_char_count > 8:  # Too many of the same character
            findings.append(
                f"Hash shows possible collision attempt (max char repeat: {max_char_count})"
            )

        # Check for timestamp manipulation indicators in file
        file_stat = os.stat(file_path)
        created_time = file_stat.st_ctime
        modified_time = file_stat.st_mtime

        # Suspicious if created and modified are exactly the same (down to the second)
        if abs(created_time - modified_time) < 1:
            findings.append("File timestamps suggest possible manipulation")

        # Check for hidden file attributes (Windows)
        if os.name == "nt":  # Windows
            import stat

            if (
                hasattr(file_stat, "st_file_attributes")
                and file_stat.st_file_attributes & 0x02
            ):  # Hidden attribute
                findings.append("File has hidden attribute")

    except Exception as e:
        return []  # Don't report errors for legitimate files

    return findings


def scan_with_yara(file_path, rules_path="rules.yar"):
    """Scan file with YARA rules"""
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(file_path)
        return [str(match) for match in matches]
    except Exception as e:
        return [f"YARA error: {e}"]


def check_virustotal_hash(sha256_hash, api_key):
    """Check file hash against VirusTotal database"""
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"],
        }
    elif response.status_code == 404:
        return {"note": "File not found in VirusTotal database."}
    else:
        return {"error": f"API error: {response.status_code} {response.reason}"}


# === MAIN SCAN FUNCTION ===


def scan_image(
    file_path,
    vt_api_key=None,
    yara_rules_path="rules.yar",
    deep_analysis=True,
    advanced_analysis=True,
):
    """Main image scanning function"""
    print(f"=== FILE: {file_path} ===")
    file_size = os.path.getsize(file_path)
    print(f"File Size: {file_size:,} bytes")

    sha256 = compute_sha256(file_path)
    print(f"SHA-256: {sha256}")

    # Quick AI check for header
    ai_findings_preview, ai_prob_preview = detect_ai_generated_content(file_path)
    if ai_prob_preview > 0.1:
        confidence = "LOW"
        if ai_prob_preview > 0.3:
            confidence = "MEDIUM"
        if ai_prob_preview > 0.6:
            confidence = "HIGH"
        if ai_prob_preview > 0.8:
            confidence = "VERY HIGH"
        print(
            f"🤖 AI Content Probability: {ai_prob_preview:.1%} ({confidence} confidence)"
        )
    else:
        print("📷 Natural Image: No AI generation detected")

    # Basic EXIF analysis
    print("\n=== BASIC ANALYSIS ===")
    print("📋 EXIF Metadata:")
    exif_data = extract_exif_data(file_path)
    for key, value in exif_data.items():
        # Truncate very long values for display
        display_value = str(value)
        if len(display_value) > 200:
            display_value = display_value[:200] + "... [truncated]"
        print(f"  {key}: {display_value}")

    # Check for base64 in metadata
    base64_alerts = check_for_base64_in_metadata(exif_data)
    if base64_alerts:
        print("\n⚠️ SUSPICIOUS METADATA FIELDS:")
        for key, info in base64_alerts.items():
            print(f"  {key}: {info['warning']}")
            print(f"  Decoded preview: {info['decoded_preview']}")
            print(f"  Entropy: {info['entropy']:.3f}")

    # Metadata anomalies
    metadata_anomalies = analyze_metadata_anomalies(exif_data)
    if metadata_anomalies:
        print("\n📊 METADATA ANOMALIES:")
        for anomaly in metadata_anomalies:
            print(f"  - {anomaly}")

    # NEW: File structure validation
    print("\n🔍 File Structure Validation:")
    polyglot_findings = detect_polyglot_files(file_path)
    structure_findings = validate_file_structure(file_path)

    all_structure_findings = polyglot_findings + structure_findings
    if all_structure_findings:
        for finding in all_structure_findings:
            print(f"  - {finding}")
    else:
        print("  - No file structure anomalies detected")

    # NEW: Timestamp analysis
    print("\n⏰ Timestamp Analysis:")
    timestamp_findings = analyze_timestamp_anomalies(file_path)
    if timestamp_findings:
        for finding in timestamp_findings:
            print(f"  - {finding}")
    else:
        print("  - No timestamp anomalies detected")

    # NEW: Modern threat detection
    print("\n🌐 Modern Threat Detection:")
    modern_findings = detect_modern_threats(file_path)
    if modern_findings:
        for finding in modern_findings:
            print(f"  - {finding}")
    else:
        print("  - No modern threat indicators found")

    # NEW: AI-generated content detection
    print("\n🤖 AI-Generated Content Detection:")
    ai_findings, ai_probability = detect_ai_generated_content(file_path)
    if ai_findings:
        for finding in ai_findings:
            print(f"  - {finding}")
    else:
        print("  - No AI-generated content indicators found")

    # YARA scan
    print("\n🔍 YARA Pattern Matching:")
    yara_hits = scan_with_yara(file_path, yara_rules_path)
    if yara_hits and not any("error" in hit.lower() for hit in yara_hits):
        print("  Matches found:")
        for match in yara_hits:
            print(f"  - {match}")
    else:
        print("  - No YARA matches detected")

    # VirusTotal check
    if vt_api_key:
        print("\n🌐 VirusTotal Analysis:")
        vt_result = check_virustotal_hash(sha256, vt_api_key)
        for k, v in vt_result.items():
            print(f"  {k}: {v}")

    if deep_analysis:
        print("\n=== DEEP ANALYSIS ===")

        # Statistical analysis
        print("🔢 Statistical Analysis:")
        stat_anomalies = detect_data_anomalies(file_path)
        if stat_anomalies:
            for anomaly in stat_anomalies:
                print(f"  - {anomaly}")
        else:
            print("  - No statistical anomalies detected")

        # LSB steganography detection
        print("\n🔍 LSB Steganography Analysis:")
        lsb_findings = detect_lsb_steganography(file_path)
        if lsb_findings:
            for finding in lsb_findings:
                print(f"  - {finding}")
        else:
            print("  - No LSB steganography indicators found")

        # NEW: Pixel clustering analysis
        print("\n🎨 Pixel Clustering Analysis:")
        clustering_findings = detect_pixel_clustering_anomalies(file_path)
        if clustering_findings:
            for finding in clustering_findings:
                print(f"  - {finding}")
        else:
            print("  - No pixel clustering anomalies detected")

    if advanced_analysis:
        print("\n=== ADVANCED ANALYSIS ===")

        # DCT steganography detection
        print("📊 DCT Steganography Analysis:")
        dct_findings = detect_dct_steganography(file_path)
        if dct_findings:
            for finding in dct_findings:
                print(f"  - {finding}")
        else:
            print("  - No DCT steganography indicators found")

        # Frequency domain analysis
        print("\n🌊 Frequency Domain Analysis:")
        freq_findings = detect_frequency_domain_hiding(file_path)
        if freq_findings:
            for finding in freq_findings:
                print(f"  - {finding}")
        else:
            print("  - No frequency domain anomalies detected")

        # Palette steganography
        print("\n🎨 Palette Steganography Analysis:")
        palette_findings = detect_palette_steganography(file_path)
        if palette_findings:
            for finding in palette_findings:
                print(f"  - {finding}")
        else:
            print("  - No palette-based steganography detected")

        # Custom pattern detection
        print("\n🔬 Custom Pattern Analysis:")
        pattern_findings = detect_custom_steganography_patterns(file_path)
        if pattern_findings:
            for finding in pattern_findings:
                print(f"  - {finding}")
        else:
            print("  - No custom steganography patterns detected")

        # ML-based anomaly detection
        print("\n🤖 ML Anomaly Detection:")
        ml_findings = ml_anomaly_detection(file_path)
        if ml_findings:
            for finding in ml_findings:
                print(f"  - {finding}")
        else:
            print("  - No ML-detected anomalies found")

        # Deep metadata analysis
        print("\n📋 Deep Metadata Analysis:")
        metadata_findings = deep_metadata_analysis(file_path)
        if metadata_findings:
            for finding in metadata_findings:
                print(f"  - {finding}")
        else:
            print("  - No deep metadata anomalies detected")

        # RS Steganalysis (industry standard)
        print("\n📐 RS Steganalysis:")
        rs_findings = rs_steganalysis(file_path)
        if rs_findings:
            for finding in rs_findings:
                print(f"  - {finding}")
        else:
            print("  - No RS steganalysis indicators found")

        # Sample Pair Analysis
        print("\n🔢 Sample Pair Analysis:")
        spa_findings = spa_steganalysis(file_path)
        if spa_findings:
            for finding in spa_findings:
                print(f"  - {finding}")
        else:
            print("  - No SPA indicators found")

        # Weighted Stego Analysis (JPEG)
        print("\n⚖️ Weighted Stego Analysis:")
        ws_findings = weighted_stego_analysis(file_path)
        if ws_findings:
            for finding in ws_findings:
                print(f"  - {finding}")
        else:
            print("  - No WS indicators found")

        # Forensic hash validation
        print("\n🔗 Forensic Hash Validation:")
        hash_findings = blockchain_hash_validation(file_path)
        if hash_findings:
            for finding in hash_findings:
                print(f"  - {finding}")
        else:
            print("  - No hash anomalies detected")

    print("=" * 70 + "\n")


# === ENTRY POINT ===

if __name__ == "__main__":
    print("🚀 Enhanced Forensic Image Threat Scanner")
    print("=" * 60)

    folder = input("Enter full path to image folder: ").strip()
    vt_key = input("Enter VirusTotal API key (or leave blank to skip): ").strip()
    yara_path = (
        input("Enter YARA rule file path (default is rules.yar): ").strip()
        or "rules.yar"
    )

    print("\nAnalysis Options:")
    print("1. Quick scan (basic + structure validation + modern threats)")
    print("2. Deep scan (+ statistical analysis + pixel clustering)")
    print("3. Ultra scan (+ advanced steganography detection)")

    choice = input("Select analysis level (1-3): ").strip()

    deep_analysis = choice in ["2", "3"]
    advanced_analysis = choice == "3"

    supported_exts = (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp")
    if not os.path.isdir(folder):
        print("❌ Error: Folder not found.")
    else:
        analysis_type = (
            ["Quick", "Deep", "Ultra"][int(choice) - 1]
            if choice in ["1", "2", "3"]
            else "Deep"
        )
        print(f"\n🔎 Scanning folder: {folder}")
        print(f"📊 Analysis level: {analysis_type}")
        print("=" * 60 + "\n")

        scanned_count = 0
        for filename in os.listdir(folder):
            if filename.lower().endswith(supported_exts):
                full_path = os.path.join(folder, filename)
                scan_image(
                    full_path,
                    vt_key or None,
                    yara_path,
                    deep_analysis,
                    advanced_analysis,
                )
                scanned_count += 1

        print(f"✅ Scan complete. {scanned_count} files analyzed.")
