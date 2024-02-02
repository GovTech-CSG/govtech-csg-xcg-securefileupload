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
import mimetypes
import operator
import os
import pprint

import magic

from govtech_csg_xcg.securefileupload import logger

from ...conf import settings
from ..helper import add_point_to_guessed_file_type

try:
    import yara
except ImportError:
    yara = None


def perform_yara_matching(file):
    """
    Perform YARA matching.
    """
    if yara is not None:
        logger.debug("[Validation module] - Performing YARA matching")

        yara_dir_path = settings.GLOBAL_UPLOAD_CONFIG["yara_file_location"]
        rules = yara.compile(
            filepaths={
                file_name.split(".")[0]: os.path.join(yara_dir_path, file_name)
                for file_name in os.listdir(yara_dir_path)
                if file_name.lower().endswith(".yar")
                or file_name.lower().endswith(".yara")
            }
        )

        matches = rules.match(data=file.content)

        file.detection_results.yara_matches = matches

    else:
        logger.info(
            "[Validation module] - Skipping YARA validation as YARA library is not installed"
        )


def match_file_signature(file):
    """get the mimetype of the file using magic lib"""
    logger.debug("[Validation module] - Matching file signature")

    return magic.from_buffer(file.content, mime=True)


def get_filename_splits(file_object):
    """split the file by dot and return a list"""
    file_name_splits = list(
        map(lambda x: x.lower(), file_object.basic_information.name.split("."))
    )

    return file_name_splits


def check_file_size_allowed(file, upload_config):
    """
    Check if the file size is within the allowed limits.

    Parameters:
        file (object): An object representing the file to be checked.
        upload_config (dict): A dictionary containing the upload configuration, including the "file_size_limit" key.

    Returns:
        None. The validation result is stored in the "file_size_ok" attribute of the "validation_results" attribute of the "file" object, and the "block" attribute of the "file" object is updated if the file size is not allowed.
    """
    logger.debug("[Validation module] - Validating file size")

    if upload_config["file_size_limit"] is not None:
        file_size_ok = (
            file.basic_information.size / 1000 <= upload_config["file_size_limit"]
        )
    else:
        file_size_ok = True
    file.validation_results.file_size_ok = file_size_ok

    if not file_size_ok:
        file.block = True
        logger.warning("[Validation module] - File size is too big.")


def check_mime_against_whitelist(mime_to_check, upload_config):
    """
    Check if the MIME type of a file is in the allowed whitelist.

    Parameters:
        mime_to_check (str): The MIME type of the file to be checked, in the format "type/subtype".
        upload_config (dict): A dictionary containing the upload configuration, including the "whitelist" key.

    Returns:
        bool: True if the MIME type is in the whitelist, False otherwise.
    """
    return mime_to_check in upload_config["whitelist"]


def check_request_header_mime(file, upload_config):
    """
    Check if the MIME type specified in the request header is in the allowed whitelist.

    Parameters:
        file (object): An object representing the file to be checked.
        upload_config (dict): A dictionary containing the upload configuration, including the "whitelist" key.

    Returns:
        None. The validation result is stored in the "request_whitelist_ok" attribute of the "validation_results" attribute of the "file" object, and the "block" attribute of the "file" object is updated if the MIME type is not in the whitelist.
    """
    logger.debug(
        "[Validation module] - Validating request header MIME type against whitelist"
    )

    mime_whitelist_result = check_mime_against_whitelist(
        file.basic_information.content_type, upload_config
    )

    file.validation_results.request_whitelist_ok = mime_whitelist_result

    if not mime_whitelist_result:
        file.block = True
        logger.warning("[Validation module] - Content-Type not whitelisted")


def check_signature_and_request_mime_match_file_extensions(file):
    """
    Check if the MIME type specified in the request header and the MIME type
    inferred from the file signature match the file extensions.

    Parameters:
        file (object): An object representing the file to be checked. The "extensions"
        attribute of the "detection_results" attribute should contain a list of file
        extensions, and the "content_type" and "signature_mime" attributes of the
        "basic_information" attribute should contain the MIME types specified in the
        request header and inferred from the file signature, respectively.

    Returns:
        None. The validation result is stored in the "matching_extension_signature_request_ok"
        attribute of the "validation_results" attribute of the "file" object, and the
        "mime_manipulation" attribute of the "attack_results" attribute of the "file" object
        is updated if the MIME types do not match the file extensions. The "block" attribute
        of the "file" object is updated if the MIME types do not match.
    """

    extension_matchings = []

    mime_similar_collections = [
        [
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-word",
            "application/rtf",
            "text/rtf",
        ],
        [
            "application/msexcel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-excel",
        ],
        [
            "application/mspowerpoint",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/vnd.ms-powerpoint",
        ],
        [
            "application/pdf",
            "application/x-pdf",
            "application/acrobat",
            "applications/vnd.pdf",
            "text/pdf",
            "text/x-pdf",
        ],
        [
            "image/jpeg",
            "image/pjpeg",
            "image/jpg",
            "image/png",
            "image/gif",
            "image/bmp",
            "image/x-windows-bmp",
            "image/x-bitmap",
            "image/x-xbitmap",
            "image/x-win-bitmap",
            "image/x-ms-bmp",
            "image/x-bmp",
        ],
        [
            "video/mp4",
            "video/mpeg",
            "video/quicktime",
            "video/x-msvideo",
            "video/x-ms-wmv",
            "video/x-ms-wm",
            "video/avi",
            "video/msvideo",
            "video/x-ms-asf",
            "video/x-ms-asf-plugin",
        ],
        [
            "audio/mpeg",
            "audio/mp3",
            "audio/x-mpeg",
            "audio/x-mp3",
            "audio/x-mpeg3",
            "audio/mpeg3",
            "audio/mpg",
            "audio/x-mpg",
            "audio/x-mpegaudio",
            "audio/x-mp3-playlist",
        ],
    ]

    for single_file_extension in file.detection_results.extensions:
        file_extension_mime = mimetypes.guess_type("name." + single_file_extension)[0]

        possible_mime_types = [file_extension_mime]
        for mime_similar_collection in mime_similar_collections:
            if file_extension_mime in mime_similar_collection:
                possible_mime_types.extend(mime_similar_collection)
                break

        mime_type_matching = (
            file.basic_information.content_type in possible_mime_types
            and file.detection_results.signature_mime in possible_mime_types
        )

        extension_matchings.append(mime_type_matching)

    all_extensions_match = all(extension_matchings)

    file.validation_results.matching_extension_signature_request_ok = (
        all_extensions_match
    )
    file.attack_results.mime_manipulation = not all_extensions_match

    if not all_extensions_match:
        file.block = True
        logger.warning("[Validation module] - Extension MIME does not match")


def check_file_signature(file, upload_config):
    """
    Check if the MIME type inferred from the file signature is in the allowed whitelist.

    Parameters:
        file (object): An object representing the file to be checked. The "signature_mime"
        attribute of the "detection_results" attribute should contain the MIME type inferred
        from the file signature.
        upload_config (dict): A dictionary containing the upload configuration, including the
        "whitelist" key.

    Returns:
        None. The validation result is stored in the "signature_whitelist_ok" attribute of
        the "validation_results" attribute of the "file" object, and the "block" attribute of
        the "file" object is updated if the MIME type is not in the whitelist.
    """
    logger.debug("[Validation module] - Validating file signature")

    mime_whitelist_result = check_mime_against_whitelist(
        file.detection_results.signature_mime, upload_config
    )
    file.validation_results.signature_whitelist_ok = mime_whitelist_result

    if not mime_whitelist_result:
        file.block = True
        logger.warning("[Validation module] - Signature not whitelisted")


def check_filename_length(file, upload_config):
    """
    Check if the length of the filename is within the allowed limits.

    Parameters:
        file (object): An object representing the file to be checked. The "name"
        attribute of the "basic_information" attribute should contain the filename.
        upload_config (dict): A dictionary containing the upload configuration,
        including the "filename_length_limit" key.

    Returns:
        None. The validation result is stored in the "filename_length_ok" attribute
        of the "validation_results" attribute of the "file" object, and the "block"
        attribute of the "file" object is updated if the filename length is not allowed.
    """
    logger.debug("[Validation module] - Validating filename length")

    if upload_config["filename_length_limit"] is not None:
        length_ok = (
            len(file.basic_information.name) <= upload_config["filename_length_limit"]
        )
    else:
        length_ok = True
    file.validation_results.filename_length_ok = length_ok

    if not length_ok:
        file.block = True
        logger.warning("[Validation module] - Filename length too long")


def check_filename_extensions(file, upload_config):
    """
    Check if all the file extensions in the filename are in the allowed whitelist.

    Parameters:
        file (object): An object representing the file to be checked. The "extensions"
        attribute of the "detection_results" attribute should contain a list of file extensions.
        upload_config (dict): A dictionary containing the upload configuration, including the
        "whitelist" key.

    Returns:
        None. The validation result is stored in the "extensions_whitelist_ok" attribute of
        the "validation_results" attribute of the "file" object, and the "block" attribute of the
        "file" object is updated if any of the file extensions is not in the whitelist.
    """
    logger.debug("[Validation module] - Validating all filename extensions")

    mime_whitelist_results = []
    for single_extension in file.detection_results.extensions:
        curr_file_extension_mime = mimetypes.guess_type("name." + single_extension)[0]
        mime_whitelist_results.append(
            check_mime_against_whitelist(curr_file_extension_mime, upload_config)
        )

    all_extensions_whitelisted = all(mime_whitelist_results)

    file.validation_results.extensions_whitelist_ok = all_extensions_whitelisted
    if not all_extensions_whitelisted:
        file.block = True
        logger.warning("[Validation module] - Extension not whitelisted")

    # TODO: Add detection of alternate media file extensions such as .php5


def check_yara_rules(file):
    """
    Check if the file matches any of the configured YARA rules.

    Parameters:
        file (object): An object representing the file to be checked. The "yara_matches" attribute
        of the "detection_results" attribute should contain a list of YARA match objects.

    Returns:
        None. The validation result is stored in the "yara_rules_ok" attribute of the
        "validation_results" attribute of the "file" object, and the "block" attribute of the
        "file" object is updated if any YARA rule matches. The "block_reason" attribute of the
        "file" object is appended with a message indicating the YARA rule that matched.
    """
    logger.debug("[Validation module] - Validating YARA rules")

    file.validation_results.yara_rules_ok = (
        len(file.detection_results.yara_matches) == 0
    )

    if not file.validation_results.yara_rules_ok:
        file.block = True

        for match in file.detection_results.yara_matches:
            file.append_block_reason("YARA match: " + match.rule)


def check_filename_for_null_byte_injections(file):
    """
    Check if the filename contains any null byte injection attacks.

    Parameters:
        file (object): An object representing the file to be checked. The "filename_splits"
        attribute of the "detection_results" attribute should contain a list of substrings
        of the filename split by dots.

    Returns:
        None. The "null_byte_injection" attribute of the "attack_results" attribute of the
        "file" object is updated if a null byte injection attack is found in the filename.
        The "block" attribute of the "file" object is updated if a null byte inject attack is found.
    """

    logger.debug("[Validation module] - Validating for null byte injections")

    null_byte_found = False

    for file_name_split in file.detection_results.filename_splits:
        null_byte_found_in_split = (
            "0x00" in file_name_split
            or "%00" in file_name_split
            or "\0" in file_name_split
        )

        if null_byte_found_in_split:
            null_byte_found = True
            break

    file.attack_results.null_byte_injection = null_byte_found
    if null_byte_found:
        file.block = True
        logger.warning("[Validation module] - Null byte injection found")


def guess_mime_type(file):
    """
    Guess the MIME type of the file by considering its file signature, file extension, and
    Content-Type header.

    Parameters:
        file (object): An object representing the file to be checked. The "signature_mime"
        attribute of the "detection_results" attribute, the "extensions" attribute of the
        "detection_results" attribute, and the "content_type" attribute of the "basic_information"
        attribute should contain relevant information for guessing the MIME type.

    Returns:
        None. The "guessed_mime" attribute of the "detection_results" attribute of the "file"
        object is updated with the guessed MIME type.
    """
    logger.debug("[Validation module] - Guessing MIME type")

    guessing_scores = {mime_type: 0 for mime_type in list(mimetypes.types_map.values())}
    total_points_given = 0
    total_points_overall = 0

    # Adding file signature information
    file_signature_mime = file.detection_results.signature_mime
    if file_signature_mime in guessing_scores.keys():
        guessing_scores[file_signature_mime] += 1
        total_points_given += 1
    total_points_overall += 1

    # Adding file extension information
    main_file_extension = file.detection_results.extensions[0]
    main_mime_type = mimetypes.guess_type("name." + main_file_extension)[0]
    if main_mime_type in guessing_scores.keys():
        guessing_scores[main_mime_type] += 1
        total_points_given += 1
    total_points_overall += 1

    # Adding Content-Type header information
    content_type_mime = file.basic_information.content_type
    if content_type_mime in guessing_scores.keys():
        guessing_scores[content_type_mime] += 1
        total_points_given += 1
    total_points_overall += 1

    # Evaluating maliciousness
    sorted_guessing_scores = {
        k: v
        for k, v in sorted(guessing_scores.items(), key=lambda item: item[1])
        if v > 0
    }
    logger.debug(f"[Validation module] - {pprint.pformat(sorted_guessing_scores)}")
    logger.debug(
        f"[Validation module] - {total_points_overall=} - {total_points_given=}"
    )

    guessed_mime_type = max(guessing_scores.items(), key=operator.itemgetter(1))[0]
    file.detection_results.guessed_mime = guessed_mime_type


def validate_file(file, upload_config):
    """
    Validate the file to ensure it meets the requirements specified in the
    upload config.

    Args:
        file: A File object containing the file to be validated.
        upload_config: A dictionary containing the configuration for file uploads.

    Returns:
        None. Modifies the file object in place.
    """
    logger.debug(
        f"{file.basic_information.name} - [Validation module] - Starting basic detection"
    )

    # Retrieve basic file information
    filename_splits = get_filename_splits(file)
    file.detection_results.filename_splits = filename_splits
    file.detection_results.extensions = [filename_splits[-1]]
    main_file_extension = file.detection_results.extensions[0]
    main_extension_mime_type = mimetypes.guess_type("name." + main_file_extension)[0]
    add_point_to_guessed_file_type(file, main_extension_mime_type)

    # Detecting file signature
    signature_mime = match_file_signature(file)
    file.detection_results.signature_mime = signature_mime
    add_point_to_guessed_file_type(file, signature_mime)

    # Validate file information
    check_file_size_allowed(file, upload_config)

    check_request_header_mime(file, upload_config)

    check_signature_and_request_mime_match_file_extensions(file)

    check_file_signature(file, upload_config)

    check_filename_length(file, upload_config)

    check_filename_extensions(file, upload_config)

    check_filename_for_null_byte_injections(file)

    if not file.block:
        # Match YARA rules
        perform_yara_matching(file)
        check_yara_rules(file)

    if not file.block:
        guess_mime_type(file)
