"""
# Copyright 2021 21CN Corporation Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""

# -*- coding: utf-8 -*-

import datetime
import logging.handlers
import os

import config

LOG_FORMATTER = '%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s'

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(LOG_FORMATTER)

log_path = config.log_dir
try:
    os.makedirs(log_path)
except OSError:
    pass

debug_file = log_path + '/debug.log'
fh = logging.handlers.TimedRotatingFileHandler(debug_file,
                                               when='midnight',
                                               interval=1,
                                               backupCount=7,
                                               atTime=datetime.time.min)
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)

error_file = log_path + '/error.log'
eh = logging.FileHandler(error_file, mode='w')
eh.setLevel(logging.ERROR)
eh.setFormatter(formatter)
logger.addHandler(eh)

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)
