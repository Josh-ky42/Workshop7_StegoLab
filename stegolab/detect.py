"""TASK 3 - Detect: forensic checks an analyst runs on a suspicious image.

Hiding data is only half the story. A forensic analyst receives an image and must decide whether
something is hidden in it, where, and how confident they are. We look in three places:

    1. AFTER THE FILE ENDS  - data appended after the image's official end marker.
    2. METADATA             - text chunks / EXIF fields that viewers never show.
    3. THE PIXELS           - LSB statistics and a visual "bit plane" that reveals patterns.

HOW YOU KNOW YOU ARE DONE
    python -m unittest tests.test_task3_detect -v
"""
from __future__ import annotations

from typing import Dict, List

from PIL import Image
from PIL.ExifTags import TAGS

from stegolab.embed import read_lsbs
from stegolab.encoder import HEADER_BYTES, parse_header

PNG_END = b"IEND\xaeB`\x82"     # the IEND chunk type + its fixed CRC: a PNG must end here
JPEG_END = b"\xff\xd9"

def find_appended_data(path: str) -> bytes:
    """Return any bytes stored AFTER the image's end marker (empty bytes if there are none)."""

    with open(path, "rb") as fh:
        data = fh.read()

    if data.startswith(b"\x89PNG"):
        end = data.find(PNG_END)
        if end == -1:
            return b""
        return data[end + len(PNG_END):]

    elif data.startswith(b"\xff\xd8"):
        end = data.rfind(JPEG_END)
        if end == -1:
            return b""
        return data[end + len(JPEG_END):]

    return b""

def read_metadata(path: str) -> Dict[str, str]:
    """Return text metadata: PNG text chunks and EXIF fields, as {name: value}."""

    img = Image.open(path)
    found: Dict[str, str] = {}

    # PNG text chunks
    for key, value in img.info.items():
        if isinstance(value, str):
            found[key] = value

    # EXIF metadata
    exif = img.getexif()
    for tag_id, value in exif.items():
        tag_name = TAGS.get(tag_id, str(tag_id))
        found[tag_name] = str(value)

    return found


def lsb_ratios(path: str, window: int = 2000) -> Dict[str, float]:
    """Share of LSBs that are 1 in the first ``window`` colour values and across the whole image.

    Hidden data looks like random noise, so its LSBs sit close to 0.5. But many ordinary
    photos are noisy too, and smooth areas (a clear sky) can be all 0s or all 1s. These numbers
    are CONTEXT for the analyst, not a verdict - which is why analyse() does not raise a finding
    from them on its own.
    """
    # TODO 3.3  channels = Image.open(path).convert("RGB").tobytes()
    #           Build a list of every LSB. Return {"start": share of 1s in the first `window`,
    #           "whole": share of 1s in the whole image}.
    raise NotImplementedError("TODO (Task 3.3 - stretch)")


def make_lsb_plane(path: str, output_path: str) -> None:
    """Save a black-and-white picture of the red channel's LSBs (1 -> white, 0 -> black).

    In smooth images, hidden data shows up as a band of 'TV static' where the payload was written.
    """
    img = Image.open(path).convert("RGB")
    # TODO 3.4  red = img.tobytes()[0::3]   (every third value = the red channel)
    #           Turn each value into 255 if its LSB is 1, else 0.
    #           Image.frombytes("L", img.size, bytes(...)).save(output_path)
    raise NotImplementedError("TODO (Task 3.4 - stretch)")


def has_stegolab_header(path: str) -> bool:
    """True if the LSBs start with the StegoLab MAGIC header."""
    return parse_header(read_lsbs(Image.open(path), HEADER_BYTES * 8)) is not None


def analyse(path: str) -> Dict:
    """Run every check and return one results dictionary for report.py."""
    appended = find_appended_data(path)
    metadata = read_metadata(path)
    ratios = lsb_ratios(path)
    findings: List[str] = []
    if appended:
        findings.append(f"{len(appended)} bytes found after the end of the image")
    if metadata:
        findings.append(f"{len(metadata)} metadata field(s) present")
    if has_stegolab_header(path):
        findings.append("LSBs start with a StegoLab header: hidden message confirmed")
    return {"file": path, "appended": appended, "metadata": metadata,
            "lsb": ratios, "findings": findings}
