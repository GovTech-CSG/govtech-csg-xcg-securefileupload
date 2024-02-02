# ------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# This file incorporates work covered by the following copyright:
#
# Copyright (c) 2024 Agency for Science, Technology and Research (A*STAR).
#   All rights reserved.
# Copyright (c) 2024 Government Technology Agency (GovTech).
#   All rights reserved.
# ------------------------------------------------------------------------
import hashlib
import mimetypes
from dataclasses import dataclass, field
from io import BytesIO

import magic

from govtech_csg_xcg.securefileupload import logger


@dataclass
class BasicFileInformation:
    name: str
    size: int
    content_type: str
    content_type_extra: str
    charset: str
    sha256: str


@dataclass
class DetectionResults:
    filename_splits: list = field(default_factory=list)
    extensions: list = field(default_factory=list)
    signature_mime: str = ""
    guessed_mime: str = ""
    yara_matches: list = field(default_factory=list)


@dataclass
class ValidationResults:
    file_size_ok: bool = True
    matching_extension_signature_request_ok: bool = True
    filename_length_ok: bool = True
    extensions_whitelist_ok: bool = True
    request_whitelist_ok: bool = True
    signature_whitelist_ok: bool = True
    yara_rules_ok: bool = True
    quicksand_result_ok: bool = True
    quicksand_result_detail: str = ""
    clamav_result_ok: bool = True
    clamav_result_detail: str = ""

    file_integrity_ok: bool = True
    file_integrity_check_done: bool = True

    malicious: bool = True

    total_points_overall: int = 0
    guessing_scores: dict = field(default_factory=dict)


@dataclass
class PossibleAttacks:
    mime_manipulation: bool = False
    null_byte_injection: bool = False


@dataclass
class SanitizationResults:
    created_random_filename_with_guessed_extension: bool = False
    disarmed_pdf: bool = False


@dataclass
class FileTypes:
    magic_full: str = ""
    magic_mime: str = ""
    mimetypes_type: str = ""
    content_type: str = ""


class File:
    """
    Common class for all files.
    """

    def __init__(self, file):
        logger.debug("[File class] - Initializing file object")
        self._uploaded_file = file
        self._content = b"".join([chunk for chunk in file.chunks()])
        self._block = False
        self._block_reasons = []
        self._name = file.name

        _, _, hash_sha256, _ = self._get_file_hashes()

        guessing_scores = {
            mime_type: 0 for mime_type in list(mimetypes.types_map.values())
        }

        self.basic_information = BasicFileInformation(
            file.name,
            file.size,
            file.content_type,
            file.content_type_extra,
            file.charset,
            hash_sha256,
        )

        self.file_types = FileTypes(
            magic_full=magic.from_buffer(self.content),
            magic_mime=magic.from_buffer(self.content, mime=True),
            mimetypes_type=mimetypes.guess_type(file.name)[0],
            content_type=file.content_type,
        )

        self.validation_results = ValidationResults(guessing_scores=guessing_scores)
        self.attack_results = PossibleAttacks()
        self.detection_results = DetectionResults()
        self.sanitization_results = SanitizationResults()

    def _get_file_hashes(self):
        logger.debug("[File class] - Retrieving file hashes")
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        sha512_hash = hashlib.sha512()

        for chunk in self._uploaded_file.chunks():
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
            sha512_hash.update(chunk)

        hexdigest_md5 = md5_hash.hexdigest()
        hexdigest_sha1 = sha1_hash.hexdigest()
        hexdigest_sha256 = sha256_hash.hexdigest()
        hexdigest_sha512 = sha512_hash.hexdigest()

        logger.debug(f"[File class] - MD5: {hexdigest_md5}")
        logger.debug(f"[File class] - SHA1: {hexdigest_sha1}")
        logger.debug(f"[File class] - SHA256: {hexdigest_sha256}")
        logger.debug(f"[File class] - SHA512: {hexdigest_sha512}")

        return hexdigest_md5, hexdigest_sha1, hexdigest_sha256, hexdigest_sha512

    @property
    def uploaded_file(self):
        return self._uploaded_file

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, new_content: bytes):
        logger.debug("[File class] - Setting new file content")
        self._content = new_content
        self._uploaded_file.file = BytesIO(new_content)

    @property
    def block(self):
        return self._block

    @block.setter
    def block(self, new_block_status: bool):
        logger.debug("[File class] - Setting new block status")
        self._block = new_block_status

    @property
    def block_reasons(self):
        return self._block_reasons

    def append_block_reason(self, block_reason):
        logger.debug("[File class] - Appending new block reason")
        self._block_reasons.append(block_reason)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, new_name: str):
        self._name = new_name
        self.basic_information.name = new_name
        self._uploaded_file.name = new_name
