#!/usr/bin/env python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
so-config.py writes SOC/onionconfig settings to Postgres.

so-yaml.py remains a YAML file editor. Call this tool when a pillar-backed
setting also needs to be reflected in the onionconfig database.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import yaml


PILLAR_ROOT = Path(os.environ.get("SO_CONFIG_PILLAR_ROOT", "/opt/so/saltstack/local/pillar"))
DOCKER_CONTAINER = os.environ.get("SO_CONFIG_PG_CONTAINER", "so-postgres")
PG_DATABASE = os.environ.get("SO_CONFIG_PG_DATABASE", "securityonion")
PG_USER = os.environ.get("SO_CONFIG_PG_USER", "postgres")
DEFAULT_USER_ID = os.environ.get("SO_CONFIG_USER_ID", "so-config")

EXCLUDE_BASENAMES = {
    "secrets.sls",
    "auth.sls",
    "top.sls",
}
EXCLUDE_PATH_FRAGMENTS = (
    "/elasticsearch/nodes.sls",
    "/redis/nodes.sls",
    "/kafka/nodes.sls",
    "/hypervisor/nodes.sls",
    "/logstash/nodes.sls",
    "/node_data/ips.sls",
    "/postgres/auth.sls",
    "/elasticsearch/auth.sls",
    "/kibana/secrets.sls",
)


class SkipPath(Exception):
    pass


def pg_str(value):
    if value is None:
        return "NULL"
    return "'" + str(value).replace("'", "''") + "'"


def pg_jsonb(value):
    return pg_str(json.dumps(value)) + "::jsonb"


def docker_psql(sql):
    proc = subprocess.run(
        ["docker", "exec", "-i", DOCKER_CONTAINER,
         "psql", "-U", PG_USER, "-d", PG_DATABASE,
         "-tA", "-q", "-v", "ON_ERROR_STOP=1"],
        input=sql.encode(),
        capture_output=True,
        check=False,
        timeout=60,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode(errors="replace"))
        raise RuntimeError(f"docker exec psql failed with rc={proc.returncode}")
    return proc.stdout.decode(errors="replace")


def schema_ready():
    sql = """
SELECT to_regclass('public.settings') IS NOT NULL
   AND to_regclass('public.audit_settings') IS NOT NULL;
"""
    return docker_psql(sql).strip() == "t"


def cmd_wait_schema(args):
    import time

    deadline = time.time() + args.timeout
    while time.time() <= deadline:
        if schema_ready():
            return 0
        time.sleep(args.interval)
    print("so-config: onionconfig schema is not ready", file=sys.stderr)
    return 1


def upsert_setting(setting_id, value, *, node_id="", duplicated_from_id=None,
                   user_id=DEFAULT_USER_ID, note=None):
    note = note or "so-config upsert"
    sql = f"""
BEGIN;
WITH old_row AS (
    SELECT value
      FROM settings
     WHERE setting_id = {pg_str(setting_id)}
       AND node_id = {pg_str(node_id)}
     FOR UPDATE
),
upserted AS (
    INSERT INTO settings (setting_id, value, duplicated_from_id, node_id)
    VALUES ({pg_str(setting_id)}, {pg_jsonb(value)}, {pg_str(duplicated_from_id)}, {pg_str(node_id)})
    ON CONFLICT (setting_id, node_id) DO UPDATE
       SET value = EXCLUDED.value,
           duplicated_from_id = EXCLUDED.duplicated_from_id
    RETURNING value
)
INSERT INTO audit_settings (setting_id, node_id, user_id, old_value, new_value, note)
SELECT {pg_str(setting_id)},
       {pg_str(node_id)},
       {pg_str(user_id)},
       (SELECT value FROM old_row),
       (SELECT value FROM upserted),
       {pg_str(note)}
 WHERE NOT EXISTS (SELECT 1 FROM old_row)
    OR (SELECT value FROM old_row) IS DISTINCT FROM (SELECT value FROM upserted);
COMMIT;
"""
    docker_psql(sql)


def delete_setting(setting_id, *, node_id="", user_id=DEFAULT_USER_ID, note=None):
    note = note or "so-config delete"
    sql = f"""
BEGIN;
WITH deleted AS (
    DELETE FROM settings
     WHERE setting_id = {pg_str(setting_id)}
       AND node_id = {pg_str(node_id)}
     RETURNING value
)
INSERT INTO audit_settings (setting_id, node_id, user_id, old_value, new_value, note)
SELECT {pg_str(setting_id)}, {pg_str(node_id)}, {pg_str(user_id)}, value, NULL::jsonb, {pg_str(note)}
  FROM deleted;
COMMIT;
"""
    docker_psql(sql)


def delete_setting_prefix(setting_id, *, node_id="", user_id=DEFAULT_USER_ID, note=None):
    if not setting_id:
        raise ValueError("setting_id prefix cannot be empty")
    note = note or "so-config delete-prefix"
    sql = f"""
BEGIN;
WITH deleted AS (
    DELETE FROM settings
     WHERE node_id = {pg_str(node_id)}
       AND (
             setting_id = {pg_str(setting_id)}
          OR substring(setting_id from 1 for char_length({pg_str(setting_id)}) + 1) = {pg_str(setting_id + ".")}
       )
     RETURNING setting_id, value
)
INSERT INTO audit_settings (setting_id, node_id, user_id, old_value, new_value, note)
SELECT setting_id, {pg_str(node_id)}, {pg_str(user_id)}, value, NULL::jsonb, {pg_str(note)}
  FROM deleted;
COMMIT;
"""
    docker_psql(sql)


def purge_node(node_id, *, user_id=DEFAULT_USER_ID, note=None):
    note = note or "so-config purge-node"
    sql = f"""
BEGIN;
WITH deleted AS (
    DELETE FROM settings
     WHERE node_id = {pg_str(node_id)}
     RETURNING setting_id, value
)
INSERT INTO audit_settings (setting_id, node_id, user_id, old_value, new_value, note)
SELECT setting_id, {pg_str(node_id)}, {pg_str(user_id)}, value, NULL::jsonb, {pg_str(note)}
  FROM deleted;
COMMIT;
"""
    docker_psql(sql)


def parse_value(value, value_file=None):
    if value_file:
        with open(value_file, "r") as fh:
            value = fh.read()
    parsed = yaml.safe_load(value)
    if parsed is None and value == "":
        return ""
    return parsed


def parse_yaml_file(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if b"{%" in raw or b"{{" in raw:
        raise SkipPath(f"{path}: Jinja-templated files stay disk-only")
    if not raw.strip():
        return {}
    parsed = yaml.safe_load(raw)
    return parsed if parsed is not None else {}


def flatten(prefix, value):
    if isinstance(value, dict):
        for key, child in value.items():
            child_id = f"{prefix}.{key}" if prefix else str(key)
            yield from flatten(child_id, child)
    else:
        yield prefix, value


def classify_pillar_path(path):
    norm = Path(path).resolve()
    norm_str = str(norm)

    if norm.name in EXCLUDE_BASENAMES:
        raise SkipPath(f"{path}: excluded basename")
    for fragment in EXCLUDE_PATH_FRAGMENTS:
        if fragment in norm_str:
            raise SkipPath(f"{path}: excluded path fragment {fragment}")
    if norm.suffix != ".sls":
        raise SkipPath(f"{path}: not an .sls file")

    parent = norm.parent.name
    stem = norm.stem

    if parent == "minions":
        if stem.startswith("adv_"):
            return {"kind": "advanced", "setting_id": "advanced", "node_id": stem[4:]}
        return {"kind": "normal", "node_id": stem}

    section = parent
    if stem == f"soc_{section}":
        return {"kind": "normal", "node_id": ""}
    if stem == f"adv_{section}":
        return {"kind": "advanced", "setting_id": f"{section}.advanced", "node_id": ""}

    raise SkipPath(f"{path}: not a SOC-managed pillar file")


def import_pillar_file(path, *, user_id=DEFAULT_USER_ID, note=None):
    meta = classify_pillar_path(path)
    note = note or f"so-config import-file {path}"

    if meta["kind"] == "advanced":
        with open(path, "r") as fh:
            upsert_setting(meta["setting_id"], fh.read(), node_id=meta["node_id"],
                           user_id=user_id, note=note)
        return 1

    data = parse_yaml_file(path)
    if not isinstance(data, dict):
        raise SkipPath(f"{path}: top-level YAML is not a map")

    count = 0
    for setting_id, value in flatten("", data):
        upsert_setting(setting_id, value, node_id=meta["node_id"],
                       user_id=user_id, note=note)
        count += 1
    return count


def iter_pillar_files(root):
    root = Path(root)
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*.sls")):
        if path.is_file():
            yield path


def cmd_set(args):
    upsert_setting(args.setting_id, parse_value(args.value, args.value_file),
                   node_id=args.node_id,
                   duplicated_from_id=args.duplicated_from_id,
                   user_id=args.user_id,
                   note=args.note)
    return 0


def cmd_delete(args):
    delete_setting(args.setting_id, node_id=args.node_id,
                   user_id=args.user_id, note=args.note)
    return 0


def cmd_delete_prefix(args):
    delete_setting_prefix(args.setting_id, node_id=args.node_id,
                          user_id=args.user_id, note=args.note)
    return 0


def cmd_purge_node(args):
    purge_node(args.node_id, user_id=args.user_id, note=args.note)
    return 0


def cmd_import_file(args):
    count = import_pillar_file(args.path, user_id=args.user_id, note=args.note)
    print(f"imported {count} settings from {args.path}")
    return 0


def cmd_import_minion(args):
    count = 0
    for name in (f"{args.node_id}.sls", f"adv_{args.node_id}.sls"):
        path = PILLAR_ROOT / "minions" / name
        if path.exists():
            count += import_pillar_file(path, user_id=args.user_id, note=args.note)
    print(f"imported {count} settings for node {args.node_id}")
    return 0


def cmd_import_all(args):
    count = 0
    skipped = 0
    for path in iter_pillar_files(args.root):
        try:
            count += import_pillar_file(path, user_id=args.user_id, note=args.note)
        except SkipPath as exc:
            skipped += 1
            if args.verbose:
                print(f"skip: {exc}", file=sys.stderr)
    print(f"imported {count} settings, skipped {skipped} files")
    if args.state_file:
        with open(args.state_file, "w") as fh:
            fh.write("ok\n")
    return 0


def cmd_sync_yaml_mutation(args):
    meta = classify_pillar_path(args.path)
    note = args.note or f"so-config sync-yaml-mutation {args.operation} {args.path}"

    if meta["kind"] == "advanced":
        import_pillar_file(args.path, user_id=args.user_id, note=note)
        return 0

    if args.operation in ("add", "replace"):
        upsert_setting(args.key, parse_value(args.value, args.value_file),
                       node_id=meta["node_id"],
                       user_id=args.user_id,
                       note=note)
    elif args.operation == "remove":
        delete_setting_prefix(args.key, node_id=meta["node_id"],
                              user_id=args.user_id, note=note)
    else:
        raise ValueError(f"unsupported operation: {args.operation}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("wait-schema", help="wait for SOC-created onionconfig tables")
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--interval", type=int, default=2)
    p.set_defaults(func=cmd_wait_schema)

    p = sub.add_parser("set", help="upsert one setting")
    p.add_argument("setting_id")
    p.add_argument("value", nargs="?", default="")
    p.add_argument("--value-file")
    p.add_argument("--node-id", default="")
    p.add_argument("--duplicated-from-id")
    p.add_argument("--user-id", default=DEFAULT_USER_ID)
    p.add_argument("--note")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("delete", help="delete one setting")
    p.add_argument("setting_id")
    p.add_argument("--node-id", default="")
    p.add_argument("--user-id", default=DEFAULT_USER_ID)
    p.add_argument("--note")
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("delete-prefix", help="delete one setting and all child settings")
    p.add_argument("setting_id")
    p.add_argument("--node-id", default="")
    p.add_argument("--user-id", default=DEFAULT_USER_ID)
    p.add_argument("--note")
    p.set_defaults(func=cmd_delete_prefix)

    p = sub.add_parser("purge-node", help="delete all settings for one node")
    p.add_argument("node_id")
    p.add_argument("--user-id", default=DEFAULT_USER_ID)
    p.add_argument("--note")
    p.set_defaults(func=cmd_purge_node)

    p = sub.add_parser("import-file", help="import one SOC-managed pillar file")
    p.add_argument("path")
    p.add_argument("--user-id", default=DEFAULT_USER_ID)
    p.add_argument("--note")
    p.set_defaults(func=cmd_import_file)

    p = sub.add_parser("import-minion", help="import one minion's pillar files")
    p.add_argument("node_id")
    p.add_argument("--user-id", default=DEFAULT_USER_ID)
    p.add_argument("--note")
    p.set_defaults(func=cmd_import_minion)

    p = sub.add_parser("import-all", help="import all SOC-managed local pillar files")
    p.add_argument("--root", default=str(PILLAR_ROOT))
    p.add_argument("--state-file")
    p.add_argument("--user-id", default=DEFAULT_USER_ID)
    p.add_argument("--note", default="so-config initial import")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_import_all)

    p = sub.add_parser("sync-yaml-mutation",
                       help="mirror one so-yaml add/replace/remove mutation to onionconfig")
    p.add_argument("path")
    p.add_argument("operation", choices=("add", "replace", "remove"))
    p.add_argument("key")
    p.add_argument("value", nargs="?", default="")
    p.add_argument("--value-file")
    p.add_argument("--user-id", default=DEFAULT_USER_ID)
    p.add_argument("--note")
    p.set_defaults(func=cmd_sync_yaml_mutation)

    return parser


def main(argv):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SkipPath as exc:
        print(f"skip: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"so-config: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
