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
from govtech_csg_xcg.securefileupload import logger


def evaluate(file, request):
    logger.debug("[Evaluator module] - Starting maliciousness evaluation")

    block_upload = request.block_upload
    upload_errmsg = request.upload_errmsg

    #############################
    # Handle validation results #
    #############################

    # Always block if strict validation fails
    # Block if YARA rule matches

    # 1. strict validation - validation
    strict_val_res = [
        file.validation_results.file_size_ok,
        file.validation_results.matching_extension_signature_request_ok,
        file.validation_results.filename_length_ok,
        file.validation_results.extensions_whitelist_ok,
        file.validation_results.request_whitelist_ok,
        file.validation_results.signature_whitelist_ok,
    ]

    # 2. strict validation - attack
    possible_attack_val_res = [
        not file.attack_results.mime_manipulation,
        not file.attack_results.null_byte_injection,
    ]

    strict_val_success = all(strict_val_res)
    possible_attack_val_success = all(possible_attack_val_res)

    if not (strict_val_success and possible_attack_val_success):
        block_upload = True
        file.block = True
        file.validation_results.malicious = True
        file.append_block_reason("strict_eval_failed")

        upload_errmsg = (
            upload_errmsg + " File: [" + file.basic_information.name + "] " + "ERROR: "
        )

        if not file.validation_results.file_size_ok:
            upload_errmsg = upload_errmsg + "File size not match;"

        if not file.validation_results.matching_extension_signature_request_ok:
            upload_errmsg = upload_errmsg + "File extension and signature not match;"

        if not file.validation_results.filename_length_ok:
            upload_errmsg = upload_errmsg + "Filename length not match;"

        if not file.validation_results.extensions_whitelist_ok:
            upload_errmsg = upload_errmsg + "File extensions whitelist not match;"

        if not file.validation_results.request_whitelist_ok:
            upload_errmsg = upload_errmsg + "Request whitelist not match;"

        if not file.validation_results.signature_whitelist_ok:
            upload_errmsg = upload_errmsg + "Signature whitelist not match;"

        if file.attack_results.mime_manipulation:
            upload_errmsg = upload_errmsg + "File with mime_manipulation;"

        if file.attack_results.null_byte_injection:
            upload_errmsg = upload_errmsg + "File with null_byte_injection;"

        logger.warning("[Evaluator module] - Blocking: Strict evaluation FAILED")
    else:
        logger.debug("[Evaluator module] - Strict evaluation PASSED")

    # 2. relaxed YARA validation
    yara_val_success = file.validation_results.yara_rules_ok

    if not yara_val_success:
        block_upload = True
        file.block = True
        file.validation_results.malicious = True
        file.append_block_reason("yara_eval_failed")
        upload_errmsg = f"{upload_errmsg} File: [{file.basic_information.name}]: \
            YARA evaluation FAILED;"
        logger.warning("[Evaluator module] - Blocking: YARA evaluation FAILED")
    else:
        logger.debug("[Evaluator module] - YARA evaluation PASSED")

    # 3. relaxed quicksand validation
    clamav_val_success = file.validation_results.quicksand_result_ok

    if not clamav_val_success:
        block_upload = True
        file.block = True
        file.validation_results.malicious = True
        file.append_block_reason("QS_detection")
        upload_errmsg = f"{upload_errmsg} File: [{file.basic_information.name}]: \
            Quicksand evaluation FAILED: {file.validation_results.quicksand_result_detail};"
        logger.warning("[Evaluator module] - Blocking: Quicksand evaluation FAILED")
    else:
        logger.debug("[Evaluator module] - Quicksand evaluation PASSED")

    # 4. relaxed clamav validation
    clamav_val_success = file.validation_results.clamav_result_ok

    if not clamav_val_success:
        block_upload = True
        file.block = True
        file.validation_results.malicious = True
        file.append_block_reason("clamav")
        upload_errmsg = f"{upload_errmsg} File: [{file.basic_information.name}]: \
            clamAV evaluation FAILED: {file.validation_results.clamav_result_detail};"
        logger.warning("[Evaluator module] - Blocking: clamAV evaluation FAILED")
    else:
        logger.debug("[Evaluator module] - clamAV evaluation PASSED")

    return file, block_upload, upload_errmsg
