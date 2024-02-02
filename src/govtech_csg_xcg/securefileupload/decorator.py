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
import copy
from functools import wraps

from .conf import settings
from .utils import fill_missing_configs


def upload_config(
    quicksand=None,
    file_size_limit=None,
    filename_length_limit=None,
    whitelist_name=None,
    whitelist=None,
):
    """
    Decorator for views that upload options.
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapper_view(request, *args, **kwargs):
            return view_func(request, *args, **kwargs)

        url_upload_config = copy.deepcopy(settings.GLOBAL_UPLOAD_CONFIG)

        if quicksand is not None:
            url_upload_config["quicksand"] = quicksand

        if file_size_limit is not None:
            url_upload_config["file_size_limit"] = file_size_limit

        if filename_length_limit is not None:
            url_upload_config["filename_length_limit"] = filename_length_limit

        if whitelist_name is not None:
            url_upload_config["whitelist_name"] = whitelist_name

        if whitelist is not None:
            url_upload_config["whitelist"] = whitelist

        url_upload_config = fill_missing_configs(
            url_upload_config, settings.GLOBAL_UPLOAD_CONFIG
        )

        _wrapper_view.url_upload_config = url_upload_config
        return _wrapper_view

    return decorator
