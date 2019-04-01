import logging

logger = logging.getLogger('act_srv')
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler('/log/act_srv.log')
fh.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
fh.setFormatter(formatter)

logger.addHandler(ch)
logger.addHandler(fh)

def debug(msg):
    logger.debug(msg)
