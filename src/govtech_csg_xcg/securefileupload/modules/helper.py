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
import re

from govtech_csg_xcg.securefileupload import _thread_locals


def find_hex_pattern(needle, haystack):
    return [m.start() for m in re.finditer(needle, haystack)]


def fill_hex_with_zero(content, start_idx, end_idx):
    for i in range(start_idx, end_idx):
        content.pop(i)
        content.insert(i, 0)
    return content


def add_point_to_guessed_file_type(file, mime):
    if mime in file.validation_results.guessing_scores:
        file.validation_results.guessing_scores[mime] += 1
    else:
        file.validation_results.guessing_scores[mime] = 1

    file.validation_results.total_points_overall += 1


def get_current_request():
    """
    Return the request associated with the current thread.
    """
    return getattr(_thread_locals, "request", None)


def set_current_request(request=None):
    """
    Update the request associated with the current thread.
    """
    _thread_locals.request = request
