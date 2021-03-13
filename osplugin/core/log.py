import datetime
import logging.handlers

import config

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')

log_path = config.log_dir

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
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)
