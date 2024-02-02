from .default import *  # noqa: F403, F405

XCG_SECUREFILEUPLOAD_CONFIG["yara_file_location"] = (  # noqa: F405
    BASE_DIR / "testapp/yara_rules/"  # noqa: F405
)
