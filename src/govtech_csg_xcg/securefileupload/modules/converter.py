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
from io import BytesIO

from django.core.files.uploadedfile import InMemoryUploadedFile
from django.utils.datastructures import MultiValueDict

from govtech_csg_xcg.securefileupload import File, logger


def request_to_base_file_objects(request_files):
    """extract file information from request files"""
    logger.debug("[Converter module - Basic] - Starting request to File objects")
    file_objects = {}
    for file_key in request_files:
        request_file = request_files[file_key]
        file_objects[file_key] = File.File(request_file)
    return file_objects


def invalid_file(original_request):
    """remove the file from the request object"""
    sanitized_request = original_request
    setattr(sanitized_request, "_files", None)
    return sanitized_request


def build_files(sanitized_file_objects):
    """build request.FILES dict from the customized file object"""
    logger.debug("[Converter module] - Building FILES")
    all_files_MultiValueDict = MultiValueDict()

    for key in sanitized_file_objects:
        sanitized_file_object = sanitized_file_objects[key]
        sanitized_imuf = build_InMemoryUploadedFile(sanitized_file_object)
        all_files_MultiValueDict.appendlist(key, sanitized_imuf)

    return all_files_MultiValueDict


def build_InMemoryUploadedFile(sanitized_file_object):
    """build the individual InMemoryUploadedFile for request.FILES"""
    logger.debug("[Converter module] - Building InMemoryUploadedFile")

    if sanitized_file_object.block:
        # This file has the block flag, then overwrites it with a 1-byte dummy file to keep the upload going.
        file_imuf = InMemoryUploadedFile(
            BytesIO(b" "),
            "file",
            sanitized_file_object.basic_information.name,
            sanitized_file_object.basic_information.content_type,
            1,
            sanitized_file_object.basic_information.charset,
            sanitized_file_object.basic_information.content_type_extra,
        )
        logger.debug(
            f"[Converter module] - File [{sanitized_file_object.name}]'s content is being overwritten with a dummy 1-byte file"
        )

    else:
        file_imuf = InMemoryUploadedFile(
            BytesIO(sanitized_file_object.content),
            "file",
            sanitized_file_object.basic_information.name,
            sanitized_file_object.basic_information.content_type,
            sanitized_file_object.basic_information.size,
            sanitized_file_object.basic_information.charset,
            sanitized_file_object.basic_information.content_type_extra,
        )

    return file_imuf
