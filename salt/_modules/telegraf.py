#!py

import logging
import socket


def send(data):

  mainint = __salt__['pillar.get']('sensor:mainint', __salt__['pillar.get']('manager:mainint'))
  ip_interfaces = __salt__['grains.get']('ip_interfaces') or {}
  ip_list = ip_interfaces.get(mainint) or []
  mainip = ip_list[0] if ip_list else None
  if not mainip:
      log.error('telegraf.send: could not determine IP for interface %s', mainint)
      return 0
  dstport = 8094

  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
      sent = sock.sendto(data.encode('utf-8'), (mainip, dstport))

  return sent
