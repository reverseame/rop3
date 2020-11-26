import sys
import logging

import rop3.utils as utils

logger = logging.getLogger(utils.TOOL_NAME)

''' Log format '''
logging.basicConfig(level=logging.DEBUG, format='%(name)s: %(levelname)s: %(message)s')

def debug(msg):
    log(logging.DEBUG, msg)

def info(msg):
    log(logging.INFO, msg)

def warning(msg):
    log(logging.WARNING, msg)

def error(msg):
    log(logging.ERROR, msg)
    sys.exit(-1)

def critical(msg):
    log(logging.CRITICAL, msg)
    sys.exit(-1)

def log(loglevel, msg):
    ''' Show debug message '''
    logger.log(loglevel, msg)
