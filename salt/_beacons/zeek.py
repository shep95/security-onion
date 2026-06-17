import logging


def beacon(config):

  retval = []

  is_enabled = __salt__['healthcheck.is_enabled']()
  logging.info('zeek_beacon: healthcheck_is_enabled: %s' % is_enabled)

  if is_enabled:
    zeekstatus_raw = __salt__['zeekctl.status']()
    if not zeekstatus_raw:
      return []
    zeekstatus = zeekstatus_raw.lower().split(' ')
    logging.info('zeek_beacon: zeekctl.status: %s' % str(zeekstatus))
    if 'stopped' in zeekstatus or 'crashed' in zeekstatus or 'error' in zeekstatus or 'error:' in zeekstatus:
     zeek_restart = True
    else:
     zeek_restart = False

    __salt__['telegraf.send']('healthcheck zeek_restart=%i' % int(zeek_restart))
    retval.append({'zeek_restart': zeek_restart})
    logging.info('zeek_beacon: retval: %s' % str(retval))

  return retval

