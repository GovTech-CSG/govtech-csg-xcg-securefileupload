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
import logging
import mimetypes
import time

from django.http import Http404
from django.urls import resolve

from govtech_csg_xcg.securefileupload import logger

from .conf import settings
from .modules import converter, evaluator
from .modules.helper import set_current_request
from .modules.sanitization import sanitizer
from .modules.validation import validator


class FileUploadValidationMiddleware:
    def __init__(self, get_response):
        # One-time configuration and initialization.
        mimetypes.add_type("image/jpeg", ".jfif")
        logging.getLogger("PIL").setLevel(logging.WARNING)
        self.get_response = get_response

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        set_current_request(request)

        if request.method == "POST" and len(request.FILES) > 0:
            self._monitor_request(request)

            if request.block_upload:
                logger.warning("[Middleware] - Blocking request.")
                # request = self._invalid(request) # TODO whether remove file?

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

        set_current_request(None)

        return response

    def _monitor_request(self, request):
        request.block_upload = False
        request.upload_errmsg = ""
        request.middleware_timers = [time.time()]
        request.upload_config = self._extract_single_upload_config(request)

        files = self._extract_files(request)

        for _, file in files.items():
            logger.info(f"[Middleware] - - Analyzing file [{file.name}]")
            self._analyze_file(file, request)
            _, request.block_upload, request.upload_errmsg = self._evaluate_file(
                file, request
            )
            if not file.block and request.upload_config["sanitization"]:
                self._sanitize_file(file, request)

        sanitized_files = converter.build_files(files)
        setattr(request, "_files", sanitized_files)

        self._print_elapsed_time("COMPLETE", request)

    def _sanitize_file(self, file, request):
        sanitizer.sanitize(file, request)
        self._print_elapsed_time("Sanitizer", request)

    def _extract_files(self, request):
        files = converter.request_to_base_file_objects(request.FILES)

        self._print_elapsed_time("Converter", request)
        return files

    def _invalid(self, request):
        conversion = converter.invalid_file(request)

        return conversion

    def _analyze_file(self, file, request):
        validator.validate(file, request.upload_config)
        self._print_elapsed_time("Validator", request)

    def _evaluate_file(self, file, request):
        file, block_upload, upload_errmsg = evaluator.evaluate(file, request)
        self._print_elapsed_time("Evaluator", request)

        return file, block_upload, upload_errmsg

    def _print_elapsed_time(self, processing_step, request):
        curr_time = time.time()
        execution_last_step = (curr_time - request.middleware_timers[-1]) * 1000
        execution_until_now = (curr_time - request.middleware_timers[0]) * 1000

        if processing_step == "COMPLETE":
            logger.debug(
                "[Middleware] - TOTAL execution time: %s sec"
                % (round(execution_until_now / 1000, 3))
            )
        else:
            logger.debug(
                f"[Middleware] - {processing_step} took {round(execution_last_step, 3)} ms - Total: {round(execution_until_now / 1000, 3)} sec"
            )
        request.middleware_timers.append(curr_time)

    def _extract_single_upload_config(self, request):
        path = request.path

        try:
            resolver = resolve(path)
        except Http404:
            return settings.GLOBAL_UPLOAD_CONFIG

        view_func = resolver.func

        if hasattr(view_func, "url_upload_config"):
            upload_config = view_func.url_upload_config
        else:
            upload_config = settings.GLOBAL_UPLOAD_CONFIG

        return upload_config
