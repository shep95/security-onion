import importlib
import os
import tempfile
import unittest
from unittest.mock import patch


soconfig = importlib.import_module("so-config")


class TestSoConfigPathMapping(unittest.TestCase):

    def test_classify_global_soc(self):
        meta = soconfig.classify_pillar_path(
            "/opt/so/saltstack/local/pillar/soc/soc_soc.sls")
        self.assertEqual(meta["kind"], "normal")
        self.assertEqual(meta["node_id"], "")

    def test_classify_global_advanced(self):
        meta = soconfig.classify_pillar_path(
            "/opt/so/saltstack/local/pillar/soc/adv_soc.sls")
        self.assertEqual(meta["kind"], "advanced")
        self.assertEqual(meta["setting_id"], "soc.advanced")
        self.assertEqual(meta["node_id"], "")

    def test_classify_minion(self):
        meta = soconfig.classify_pillar_path(
            "/opt/so/saltstack/local/pillar/minions/h1_sensor.sls")
        self.assertEqual(meta["kind"], "normal")
        self.assertEqual(meta["node_id"], "h1_sensor")

    def test_classify_minion_advanced(self):
        meta = soconfig.classify_pillar_path(
            "/opt/so/saltstack/local/pillar/minions/adv_h1_sensor.sls")
        self.assertEqual(meta["kind"], "advanced")
        self.assertEqual(meta["setting_id"], "advanced")
        self.assertEqual(meta["node_id"], "h1_sensor")

    def test_classify_skips_bootstrap(self):
        with self.assertRaises(soconfig.SkipPath):
            soconfig.classify_pillar_path(
                "/opt/so/saltstack/local/pillar/secrets.sls")


class TestSoConfigImport(unittest.TestCase):

    def test_flatten_keeps_lists_as_values(self):
        flattened = dict(soconfig.flatten("", {
            "host": {"mainip": "10.0.0.1"},
            "suricata": {"pcap": {"enabled": True}},
            "items": ["a", "b"],
        }))
        self.assertEqual(flattened["host.mainip"], "10.0.0.1")
        self.assertEqual(flattened["suricata.pcap.enabled"], True)
        self.assertEqual(flattened["items"], ["a", "b"])

    def test_import_file_upserts_flattened_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "h1_sensor.sls")
            minions = os.path.join(tmp, "minions")
            os.mkdir(minions)
            path = os.path.join(minions, "h1_sensor.sls")
            with open(path, "w") as fh:
                fh.write("host:\n  mainip: 10.0.0.1\nsuricata:\n  enabled: true\n")

            calls = []
            with patch.object(soconfig, "upsert_setting",
                              side_effect=lambda *args, **kwargs: calls.append((args, kwargs))):
                count = soconfig.import_pillar_file(path)

        self.assertEqual(count, 2)
        self.assertIn((("host.mainip", "10.0.0.1"), {"node_id": "h1_sensor", "user_id": "so-config", "note": f"so-config import-file {path}"}), calls)
        self.assertIn((("suricata.enabled", True), {"node_id": "h1_sensor", "user_id": "so-config", "note": f"so-config import-file {path}"}), calls)

    def test_import_advanced_file_upserts_raw_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            minions = os.path.join(tmp, "minions")
            os.mkdir(minions)
            path = os.path.join(minions, "adv_h1_sensor.sls")
            with open(path, "w") as fh:
                fh.write("custom:\n  raw: true\n")

            calls = []
            with patch.object(soconfig, "upsert_setting",
                              side_effect=lambda *args, **kwargs: calls.append((args, kwargs))):
                count = soconfig.import_pillar_file(path)

        self.assertEqual(count, 1)
        self.assertEqual(calls[0][0], ("advanced", "custom:\n  raw: true\n"))
        self.assertEqual(calls[0][1]["node_id"], "h1_sensor")


class TestSoConfigSql(unittest.TestCase):

    def test_schema_ready_checks_soc_tables(self):
        captured = {}
        with patch.object(soconfig, "docker_psql",
                          side_effect=lambda sql: captured.update({"sql": sql}) or "t\n"):
            ready = soconfig.schema_ready()

        self.assertTrue(ready)
        self.assertIn("to_regclass('public.settings')", captured["sql"])
        self.assertIn("to_regclass('public.audit_settings')", captured["sql"])

    def test_set_writes_settings_and_audit(self):
        captured = {}
        with patch.object(soconfig, "docker_psql",
                          side_effect=lambda sql: captured.setdefault("sql", sql)):
            soconfig.upsert_setting("host.mainip", "10.0.0.1",
                                    node_id="h1_sensor", user_id="tester", note="unit")

        self.assertIn("INSERT INTO settings", captured["sql"])
        self.assertIn("INSERT INTO audit_settings", captured["sql"])
        self.assertIn("'host.mainip'", captured["sql"])
        self.assertIn("'h1_sensor'", captured["sql"])
        self.assertIn("'tester'", captured["sql"])

    def test_purge_node_audits_deleted_rows(self):
        captured = {}
        with patch.object(soconfig, "docker_psql",
                          side_effect=lambda sql: captured.setdefault("sql", sql)):
            soconfig.purge_node("h1_sensor", user_id="tester", note="unit")

        self.assertIn("DELETE FROM settings", captured["sql"])
        self.assertIn("WHERE node_id = 'h1_sensor'", captured["sql"])
        self.assertIn("INSERT INTO audit_settings", captured["sql"])

    def test_delete_prefix_removes_children_and_audits(self):
        captured = {}
        with patch.object(soconfig, "docker_psql",
                          side_effect=lambda sql: captured.setdefault("sql", sql)):
            soconfig.delete_setting_prefix("elasticfleet", node_id="h1_sensor",
                                           user_id="tester", note="unit")

        self.assertIn("DELETE FROM settings", captured["sql"])
        self.assertIn("setting_id = 'elasticfleet'", captured["sql"])
        self.assertIn("'elasticfleet.'", captured["sql"])
        self.assertIn("INSERT INTO audit_settings", captured["sql"])

    def test_sync_yaml_replace_uses_path_node_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            minions = os.path.join(tmp, "minions")
            os.mkdir(minions)
            path = os.path.join(minions, "h1_sensor.sls")
            open(path, "w").close()

            calls = []
            args = soconfig.build_parser().parse_args([
                "sync-yaml-mutation", path, "replace", "suricata.enabled", "true"
            ])
            with patch.object(soconfig, "upsert_setting",
                              side_effect=lambda *a, **kw: calls.append((a, kw))):
                soconfig.cmd_sync_yaml_mutation(args)

        self.assertEqual(calls[0][0], ("suricata.enabled", True))
        self.assertEqual(calls[0][1]["node_id"], "h1_sensor")

    def test_sync_yaml_remove_deletes_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            minions = os.path.join(tmp, "minions")
            os.mkdir(minions)
            path = os.path.join(minions, "h1_sensor.sls")
            open(path, "w").close()

            calls = []
            args = soconfig.build_parser().parse_args([
                "sync-yaml-mutation", path, "remove", "elasticfleet"
            ])
            with patch.object(soconfig, "delete_setting_prefix",
                              side_effect=lambda *a, **kw: calls.append((a, kw))):
                soconfig.cmd_sync_yaml_mutation(args)

        self.assertEqual(calls[0][0], ("elasticfleet",))
        self.assertEqual(calls[0][1]["node_id"], "h1_sensor")


if __name__ == "__main__":
    unittest.main()
