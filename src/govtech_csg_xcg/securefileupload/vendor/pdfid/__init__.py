import logging

# Create the Logger
logger = logging.getLogger("PDFiD")

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
    logger.setLevel(logging.INFO)
    logger.propagate = False
