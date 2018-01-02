import logging
import logging.handlers

#EDGE_ACCESS_LOG="edge_access.log"
EDGE_ACCESS_LOG_NAME="edge_access"
log_levels = (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL)



def find_loglevel(debug_level):
    if (debug_level == 0):
        return logging.DEBUG
    elif (debug_level == 1):
        return logging.INFO
    elif (debug_level == 2):
        return logging.WARNING
    elif (debug_level == 3):
        return logging.ERROR
    elif (debug_level == 4):
        return logging.CRITICAL
    else:
        return logging.NOTSET

class edge_logger:
    def __init__(self, debug_level, logFile):
        file_format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s'
        log_level =  find_loglevel(debug_level)
        logging.basicConfig(level=log_level,
                             format=file_format,
                             datefmt='%m-%d %H:%M',
                             filename=logFile,
                             filemode='a')
        self.console = logging.StreamHandler()
        self.console.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.console.setFormatter(formatter)
        self.logger = logging.getLogger(EDGE_ACCESS_LOG_NAME)
        rotateHandler = logging.handlers.RotatingFileHandler(logFile, maxBytes=1048576, backupCount=3)
        self.logger.addHandler(self.console)
        self.logger.addHandler(rotateHandler)
    def enable(self, loglevel):
        logging.enable(loglevel)
    def disable(self, loglevel):
        logging.disable(loglevel)
    def log_info(self, logData):
        logging.info(logData)
    def log_debug(self, logData):
        logging.debug(logData)
    def log_error(self, logData):
        logging.error(logData)
    def log_critical(self, logData):
        logging.critical(logData)
    def log_warning(self, logData):
        logging.warning(logData)


