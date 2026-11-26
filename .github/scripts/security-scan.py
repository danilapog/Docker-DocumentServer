#!/usr/bin/env python3
"""Audit stable DocumentServer image manifests from secure-rebuild.json."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess

EDITIONS = {'': 'community', '-ee': 'enterprise', '-de': 'developer'}
ARCHES = ('amd64', 'arm64')
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
TAG = re.compile(r'\d+\.\d+\.\d+\.\d+\Z')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
IMAGE = re.compile(r'onlyoffice/documentserver(?:-ee|-de)?:\d+\.\d+\.\d+\.\d+\Z')


def plan(config, release='', edition='all'):
    if release and not TAG.fullmatch(release):
        raise ValueError('Expected a full four-component stable release tag')
    if edition not in ('all', *EDITIONS.values()):
        raise ValueError('Unknown edition')
    rows = {}
    for entries in config['releases'].values():
        for entry in entries:
            tag = entry['release_tag']
            if not isinstance(tag, str) or not TAG.fullmatch(tag):
                raise ValueError(f'Invalid release_tag: {tag!r}')
            if not entry['editions']:
                raise ValueError(f'No editions for {tag}')
            for suffix in entry['editions']:
                if suffix not in EDITIONS:
                    raise ValueError(f'Unknown edition suffix: {suffix!r}')
                name = EDITIONS[suffix]
                if (release and tag != release) or (edition != 'all' and name != edition):
                    continue
                image = f'onlyoffice/documentserver{suffix}:{tag}'
                rows[image] = {'release': tag, 'edition': name, 'image': image}
    if not rows:
        raise ValueError('No configured stable images match the requested filters')
    if len(rows) > 256:
        raise ValueError('GitHub Actions matrix exceeds 256 jobs; split the release set')
    return {'include': list(rows.values())}


def platform_digests(index):
    """Resolve runnable manifests; ignore provenance/SBOM attestation manifests."""
    manifests = index.get('manifests')
    if not isinstance(manifests, list):
        raise ValueError('Expected a multi-platform index (amd64 and arm64)')
    result = {}
    for arch in ARCHES:
        matches = [m.get('digest', '') for m in manifests
                   if m.get('platform', {}).get('os') == 'linux'
                   and m.get('platform', {}).get('architecture') == arch
                   and m.get('annotations', {}).get('vnd.docker.reference.type') != 'attestation-manifest']
        if len(matches) == 1 and DIGEST.fullmatch(matches[0]):
            result[arch] = matches[0]
        else:
            result[arch] = None
    return result


def counts(report):
    # A malformed or empty result must not be interpreted as a clean scan.
    results = report.get('Results')
    if report.get('SchemaVersion') != 2 or not isinstance(results, list) or not results:
        raise ValueError('Invalid or empty Trivy report (expected schema 2 and scan targets)')
    total, fixed = Counter(), Counter()
    for target in results:
        for vuln in target.get('Vulnerabilities') or []:
            severity = vuln.get('Severity', 'UNKNOWN')
            if severity not in SEVERITIES:
                severity = 'UNKNOWN'
            total[severity] += 1
            if vuln.get('FixedVersion'):
                fixed[severity] += 1
    return dict(total), dict(fixed)


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def summary(image, rows):
    lines = [f'### {image}', '',
             '| Platform | Status | Critical | High | Medium | Low | Unknown | Fixable C/H |',
             '|---|---|---:|---:|---:|---:|---:|---:|']
    for row in rows:
        if row['status'] == 'ok':
            total, fixed = row['findings'], row['fixable']
            values = ' | '.join(str(total.get(s, 0)) for s in SEVERITIES)
            lines.append(f"| linux/{row['arch']} | OK | {values} | {fixed.get('CRITICAL', 0) + fixed.get('HIGH', 0)} |")
        else:
            lines.append(f"| linux/{row['arch']} | ERROR | - | - | - | - | - | - |")
    lines += ['', 'Counts are vulnerability findings, not unique CVE IDs.',
              'A successful audit means scans completed; it does not mean zero CVEs.', '']
    text = '\n'.join(lines) + '\n'
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as f:
            f.write(text)
    return text


def scan(image, output):
    if not IMAGE.fullmatch(image):
        raise ValueError('Expected a configured stable DocumentServer image reference')
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    try:
        # One tag resolution per job: both platform digests come from the same index.
        raw = subprocess.check_output(['docker', 'buildx', 'imagetools', 'inspect', '--raw', image])
        index = json.loads(raw)
        (output / 'manifest.json').write_bytes(raw)
        digests = platform_digests(index)
    except (subprocess.CalledProcessError, OSError, ValueError) as exc:
        digests = {arch: None for arch in ARCHES}
        print(f'Manifest resolution failed: {exc}')
    for arch, digest in digests.items():
        row = {'arch': arch, 'digest': digest, 'status': 'error'}
        rows.append(row)
        if digest is None:
            row['error'] = 'Missing or ambiguous platform manifest, or registry resolution failed'
            continue
        ref = f"{image.rsplit(':', 1)[0]}@{digest}"
        row['ref'] = ref
        report = output / f'{arch}.json'
        try:
            subprocess.run(['trivy', 'image', '--image-src', 'remote', '--platform', f'linux/{arch}',
                            '--scanners', 'vuln', '--format', 'json', '--exit-code', '0',
                            '--ignorefile', '', '--no-progress', '--timeout', '25m',
                            '--output', str(report), ref], check=True)
            row['findings'], row['fixable'] = counts(json.loads(report.read_text(encoding='utf-8')))
            row['status'] = 'ok'
        except (subprocess.CalledProcessError, OSError, ValueError, TypeError, AttributeError) as exc:
            row['error'] = str(exc)
    write_json(output / 'summary.json', {'image': image, 'scanned_at': datetime.now(timezone.utc).isoformat(),
                                         'platforms': rows})
    (output / 'summary.md').write_text(summary(image, rows), encoding='utf-8')
    return 0 if all(row['status'] == 'ok' for row in rows) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('plan')
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--release', default='')
    p.add_argument('--edition', default='all', choices=('all', *EDITIONS.values()))
    p = sub.add_parser('scan')
    p.add_argument('--image', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'plan':
        matrix = plan(json.loads(args.config.read_text(encoding='utf-8')), args.release, args.edition)
        print(json.dumps(matrix, indent=2))
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
                f.write('matrix=' + json.dumps(matrix, separators=(',', ':')) + '\n')
        return 0
    return scan(args.image, args.output)


if __name__ == '__main__':
    raise SystemExit(main())
