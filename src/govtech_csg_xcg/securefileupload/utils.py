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
from .data import whitelists


def fill_missing_configs(partial_config, full_config):
    # This creates a third dict that combines the two,
    # and allows values from partial_config to overwrite
    # full_config for the same keys.
    filled_config = {**full_config, **partial_config}

    if filled_config["whitelist_name"] != "CUSTOM":
        filled_config["whitelist"] = _get_valid_whitelist(
            filled_config["whitelist_name"]
        )

    return filled_config


def _get_valid_whitelist(whitelist_name):
    if whitelist_name == "AUDIO_ALL":
        whitelist = whitelists.WHITELIST_MIME_TYPES__AUDIO_ALL
    elif whitelist_name == "APPLICATION_ALL":
        whitelist = whitelists.WHITELIST_MIME_TYPES__APPLICATION_ALL
    elif whitelist_name == "IMAGE_ALL":
        whitelist = whitelists.WHITELIST_MIME_TYPES__IMAGE_ALL
    elif whitelist_name == "TEXT_ALL":
        whitelist = whitelists.WHITELIST_MIME_TYPES__TEXT_ALL
    elif whitelist_name == "VIDEO_ALL":
        whitelist = whitelists.WHITELIST_MIME_TYPES__VIDEO_ALL
    elif whitelist_name == "AUDIO_RESTRICTIVE":
        whitelist = whitelists.WHITELIST_MIME_TYPES__AUDIO_RESTRICTIVE
    elif whitelist_name == "APPLICATION_RESTRICTIVE":
        whitelist = whitelists.WHITELIST_MIME_TYPES__APPLICATION_RESTRICTIVE
    elif whitelist_name == "IMAGE_RESTRICTIVE":
        whitelist = whitelists.WHITELIST_MIME_TYPES__IMAGE_RESTRICTIVE
    elif whitelist_name == "TEXT_RESTRICTIVE":
        whitelist = whitelists.WHITELIST_MIME_TYPES__TEXT_RESTRICTIVE
    elif whitelist_name == "VIDEO_RESTRICTIVE":
        whitelist = whitelists.WHITELIST_MIME_TYPES__VIDEO_RESTRICTIVE
    elif whitelist_name == "ALL":
        whitelist = whitelists.WHITELIST_MIME_TYPES__ALL
    else:  # RESTRICTIVE or other
        whitelist = whitelists.WHITELIST_MIME_TYPES__RESTRICTIVE

    return whitelist
