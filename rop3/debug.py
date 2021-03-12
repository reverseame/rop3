'''
This file is part of rop3 (https://github.com/reverseame/rop3).

rop3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

rop3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with rop3. If not, see <https://www.gnu.org/licenses/>.
'''

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
