#!/usr/bin/env bash

# This script adds pillar and schedule files securely
local_salt_dir=/opt/so/saltstack/local
MINION=$1

if [[ ! "$MINION" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]]; then
  echo "Invalid minion ID: must match ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$"
  exit 1
fi

tmp_dir="/tmp/$MINION"
if [[ ! -d "$tmp_dir/pillar" ]]; then
  echo "Missing pillar directory for minion: $MINION"
  exit 1
fi

echo "Adding $MINION"
cp "$tmp_dir/pillar/$MINION.sls" "$local_salt_dir/pillar/minions/"
if [ -d "$tmp_dir/schedules" ] && [ "$(ls -A "$tmp_dir/schedules/")" ]; then
  cp "$tmp_dir/schedules/"* "$local_salt_dir/salt/patch/os/schedules/"
fi
rm -rf "$tmp_dir"