from .base import *  # noqa: F401, F403

XCG_SECUREFILEUPLOAD_CONFIG = {
    "quicksand": False,
    "file_size_limit": None,
    "filename_length_limit": None,
    "whitelist_name": "ALL",
    "sanitization": True,
    "keep_original_filename": False,
    "clamav": False,
}
