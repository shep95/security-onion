import json
import os
import re
import sys

MAX_ARTIFACT_BYTES = 65536
MAX_VALUE_LENGTH = 4096
HTTP_TIMEOUT_SECONDS = 30


def checkSupportedType(meta, artifact_type):
    if artifact_type not in meta['supportedTypes']:
        sys.exit(126)
    else:
        return True


def verifyNonEmptyListValue(conf, key):
    if key not in conf or not isinstance(conf[key], list) or len(conf[key]) == 0:
        sys.exit(126)


def parseArtifact(artifact):
    if len(artifact) > MAX_ARTIFACT_BYTES:
        sys.exit(126)
    data = json.loads(artifact)
    if not isinstance(data, dict):
        sys.exit(126)
    if 'artifactType' not in data or 'value' not in data:
        sys.exit(126)
    if not isinstance(data['artifactType'], str) or not isinstance(data['value'], str):
        sys.exit(126)
    if len(data['value']) > MAX_VALUE_LENGTH:
        sys.exit(126)
    return data


def escapeWildcard(value):
    """Escape Elasticsearch wildcard metacharacters to prevent query injection."""
    return re.sub(r'([\\*?])', r'\\\1', value)


def safeResolvePath(base_dir, relative_path):
    """Resolve a path and ensure it stays within base_dir."""
    base = os.path.realpath(base_dir)
    resolved = os.path.realpath(os.path.join(base, relative_path))
    if not resolved.startswith(base + os.sep) and resolved != base:
        sys.exit(126)
    return resolved


def loadMetadata(file):
    dir = os.path.dirname(os.path.realpath(file))
    filename = os.path.splitext(os.path.basename(os.path.realpath(file)))[0]
    with open(os.path.join(dir, filename + ".json"), "r") as metafile:
        return json.load(metafile)


def minimize_results(results: dict, max_response_keys: int = 20) -> dict:
    """Theory 4: Return summary-focused enrichment output for SOC/AI consumption."""
    if not isinstance(results, dict):
        return results
    out = {k: results[k] for k in ('status', 'summary') if k in results}
    response = results.get('response')
    if isinstance(response, dict):
        out['response'] = dict(list(response.items())[:max_response_keys])
    elif response is not None:
        out['response'] = response
    return out


def guarded_request(provider: str, request_fn):
    """Theory 5: circuit-breaker wrapped HTTP callable."""
    try:
        import circuit_breaker
        if circuit_breaker.is_open(provider):
            sys.exit(126)
        result = request_fn()
        circuit_breaker.record_success(provider)
        return result
    except ImportError:
        return request_fn()
    except Exception:
        try:
            import circuit_breaker
            circuit_breaker.record_failure(provider)
        except ImportError:
            pass
        raise


def loadConfig(path):
    import yaml
    allowed_root = os.path.realpath(os.path.dirname(os.path.realpath(__file__)))
    resolved = os.path.realpath(path)
    if not resolved.startswith(allowed_root + os.sep) and resolved != allowed_root:
        sys.exit(126)
    with open(str(resolved), "r") as conffile:
        return yaml.safe_load(conffile)
