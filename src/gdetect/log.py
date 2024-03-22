"""
This is the logger definition for the package.
"""

import logging
import sys

FORMATTER = logging.Formatter("%(asctime)s-[%(name)s]-%(levelname)s: %(message)s")


def get_console_handler():
    """define the logger handler"""
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(FORMATTER)
    return console_handler


def get_logger(name="GLIMPS-DETECT", level=logging.WARNING):
    """return the logger (is already a singleton)"""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(get_console_handler())
    #    logger.addHandler(get_file_handler())
    # with this pattern, it's rarely necessary to propagate the error up to parent
    logger.propagate = False
    return logger
