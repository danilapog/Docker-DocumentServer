import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('security_scan', Path(__file__).with_name('security-scan.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
A = 'sha256:' + 'a' * 64
B = 'sha256:' + 'b' * 64


def manifest(arch, digest):
    return {'platform': {'os': 'linux', 'architecture': arch}, 'digest': digest}


def report():
    return {'SchemaVersion': 2, 'Results': [{'Target': 'ubuntu', 'Vulnerabilities': [
        {'VulnerabilityID': 'CVE-test', 'Severity': 'HIGH', 'FixedVersion': '1.2'},
        {'VulnerabilityID': 'CVE-test2', 'Severity': 'CRITICAL'},
    ]}]}


class AuditTest(unittest.TestCase):
    def test_actual_config(self):
        config = json.loads((Path(__file__).resolve().parents[1] / 'secure-rebuild.json').read_text())
        rows = s.plan(config)['include']
        expected = {f"onlyoffice/documentserver{suffix}:{entry['release_tag']}"
                    for entries in config['releases'].values() for entry in entries for suffix in entry['editions']}
        self.assertEqual({r['image'] for r in rows}, expected)
        self.assertEqual(len(rows), len(expected))
        self.assertEqual(s.plan(config, '9.3.1.1', 'enterprise')['include'][0]['image'],
                         'onlyoffice/documentserver-ee:9.3.1.1')

    def test_community_and_deduplication(self):
        entry = {'release_tag': '1.2.3.4', 'editions': {'': {'latest': True}}}
        self.assertEqual(s.plan({'releases': {'v1': [entry, entry]}})['include'], [
            {'release': '1.2.3.4', 'edition': 'community', 'image': 'onlyoffice/documentserver:1.2.3.4'}])

    def test_no_match_and_bad_suffix(self):
        with self.assertRaises(ValueError):
            s.plan({'releases': {}}, '1.2.3.4')
        with self.assertRaises(ValueError):
            s.plan({'releases': {'v1': [{'release_tag': '1.2.3.4', 'editions': {'-unknown': {}}}]}})

    def test_manifest_attestations(self):
        attestation = manifest('amd64', B)
        attestation['annotations'] = {'vnd.docker.reference.type': 'attestation-manifest'}
        self.assertEqual(s.platform_digests({'manifests': [manifest('amd64', A), manifest('arm64', B), attestation]}),
                         {'amd64': A, 'arm64': B})

    def test_missing_and_ambiguous_platforms(self):
        self.assertEqual(s.platform_digests({'manifests': [manifest('amd64', A), manifest('amd64', B)]}),
                         {'amd64': None, 'arm64': None})
        with self.assertRaises(ValueError):
            s.platform_digests({'config': {}})

    def test_counts(self):
        self.assertEqual(s.counts(report()), ({'HIGH': 1, 'CRITICAL': 1}, {'HIGH': 1}))
        self.assertEqual(s.counts({'SchemaVersion': 2, 'Results': [{'Target': 'ubuntu'}]}), ({}, {}))
        with self.assertRaises(ValueError):
            s.counts({'SchemaVersion': 2, 'Results': []})

    def test_scan_both_digests_and_findings_nonblocking(self):
        def fake_run(cmd, check):
            Path(cmd[cmd.index('--output') + 1]).write_text(json.dumps(report()))
        with tempfile.TemporaryDirectory() as tmp, patch.object(s.subprocess, 'check_output', return_value=json.dumps(
                {'manifests': [manifest('amd64', A), manifest('arm64', B)]}).encode()) as inspect, \
                patch.object(s.subprocess, 'run', side_effect=fake_run) as trivy:
            self.assertEqual(s.scan('onlyoffice/documentserver-ee:1.2.3.4', Path(tmp)), 0)
            self.assertEqual(inspect.call_count, 1)
            self.assertEqual([c.args[0][-1] for c in trivy.call_args_list],
                             ['onlyoffice/documentserver-ee@' + A, 'onlyoffice/documentserver-ee@' + B])
            self.assertEqual(len(json.loads((Path(tmp) / 'summary.json').read_text())['platforms']), 2)

    def test_scan_error_does_not_skip_other_arch(self):
        def fake_run(cmd, check):
            if cmd[-1].endswith(A):
                raise subprocess.CalledProcessError(1, cmd)
            Path(cmd[cmd.index('--output') + 1]).write_text(json.dumps(report()))
        with tempfile.TemporaryDirectory() as tmp, patch.object(s.subprocess, 'check_output', return_value=json.dumps(
                {'manifests': [manifest('amd64', A), manifest('arm64', B)]}).encode()), \
                patch.object(s.subprocess, 'run', side_effect=fake_run) as trivy:
            self.assertEqual(s.scan('onlyoffice/documentserver-de:1.2.3.4', Path(tmp)), 1)
            self.assertEqual(trivy.call_count, 2)
            self.assertEqual([r['status'] for r in json.loads((Path(tmp) / 'summary.json').read_text())['platforms']],
                             ['error', 'ok'])


if __name__ == '__main__':
    unittest.main()
