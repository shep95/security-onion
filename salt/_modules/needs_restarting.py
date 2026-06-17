import logging
import shutil
import subprocess

log = logging.getLogger(__name__)


def __virtual__():
    if shutil.which('needs-restarting') is None:
        return False, 'needs-restarting binary not found'
    return True


def check():

    retval = False

    try:
        subprocess.check_call(['needs-restarting', '-r'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            retval = True
        else:
            log.error('needs-restarting returned unexpected exit code %d', e.returncode)
            return False

    return retval
