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
import logging

from govtech_csg_xcg.securefileupload import logger

from ...vendor.pdfid import pdfid


def sanitize_file(file):
    """sanitize pdf file using pdfid"""
    logger.debug("[Sanitizer module] - Starting application sanitization")

    try:
        options = pdfid.get_fake_options()
        options.disarm = True
        options.return_disarmed_buffer = True
        logging.getLogger("PDFiD").setLevel(logging.WARNING)

        disarmed_pdf_dict = pdfid.PDFiDMain(["pdffile"], options, [file.content])

        # check whether the file content was modified
        md5_hash = hashlib.sha256()
        md5_hash.update(disarmed_pdf_dict["buffers"][0])
        if md5_hash.hexdigest() != file.basic_information.sha256:
            file.sanitization_results.disarmed_pdf = True

        file.content = disarmed_pdf_dict["buffers"][0]

    except Exception as e:
        logger.error(
            f"[Sanitizer module - PDF] - Error sanitizing PDF to generate a disarmed PDF file: {e}"
        )
