# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Deprecated. SOC/onionconfig owns the settings database now; this state only
# removes the old so_pillar notify engine and reactor config if previously
# deployed.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

pg_notify_pillar_engine_module_absent:
  file.absent:
    - name: /etc/salt/engines/pg_notify_pillar.py
    - watch_in:
      - service: salt_master_service

pg_notify_pillar_engine_config_absent:
  file.absent:
    - name: /etc/salt/master.d/pg_notify_pillar_engine.conf
    - watch_in:
      - service: salt_master_service

pg_notify_pillar_reactor_config_absent:
  file.absent:
    - name: /etc/salt/master.d/so_pillar_reactor.conf
    - watch_in:
      - service: salt_master_service

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
