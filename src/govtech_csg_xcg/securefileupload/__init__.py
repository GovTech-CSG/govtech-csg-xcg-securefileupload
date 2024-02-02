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
import threading

_thread_locals = threading.local()

# Create the Logger
logger = logging.getLogger(__package__.rsplit(".", 1)[-1])

# Allow the user to override the logger's handler
if not logger.handlers:
    # Create the Handler for logging data to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # Create a Formatter for formatting the log messages
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s][XCG][%(name)s]: %(message)s"
    )
    console_handler.setFormatter(formatter)

    # Set the Handler to the Logger
    logger.addHandler(console_handler)

# Allow the user to override the logger's level
if logger.level == logging.NOTSET:
    logger.setLevel(logging.INFO)

logger.propagate = False
