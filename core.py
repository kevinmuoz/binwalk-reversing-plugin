from __future__ import annotations

import datetime
import logging
import os
import shlex
import shutil
from typing import Any, Optional, Tuple, List, Dict
import pybinwalk


log = logging.getLogger("Binwalk")

def resolve_disk_path(raw_path: str, extracted_suffix: str = "__extracted") -> Tuple[Optional[str], str]:
    if not raw_path:
        return None, "input path is empty"

    try:
        if os.path.exists(raw_path):
            return raw_path, "input path exists"
    except Exception:
        pass

    if raw_path.endswith(extracted_suffix):
        candidate = raw_path[: -len(extracted_suffix)]
        try:
            if os.path.exists(candidate):
                return candidate, "resolved from __extracted suffix"
            return None, "candidate from __extracted does not exist"
        except Exception:
            return None, "candidate check failed"

    return None, "input path does not exist"

def make_job_outdir(root: str, target_path: str) -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(target_path) or "unknown"
    safe = base.replace(os.sep, "_")
    return os.path.join(root, f"{safe}.{ts}")

def _which_external(cmd: Optional[str]) -> Tuple[bool, str]:
    if not cmd:
        return False, ""
    if not isinstance(cmd, str):
        cmd = str(cmd)

    try:
        parts = shlex.split(cmd)
    except Exception:
        parts = cmd.split()

    if not parts:
        return False, ""
    bin_name = parts[0]
    return (shutil.which(bin_name) is not None), bin_name

class BinwalkCore:
    """
    Minimal core wrapper around pybinwalk.
    """

    def __init__(self, extracted_suffix: str = "__extracted"):
        self._pybinwalk = pybinwalk
        self._extracted_suffix = extracted_suffix

    def scan_disk(self, input_path: str, deep: bool) -> List[Any]:
        resolved, reason = resolve_disk_path(input_path, self._extracted_suffix)
        log.debug("resolve_disk_path: %s (%r)", reason, input_path)

        if resolved is None:
            log.info("Extraction skipped: %s (%r)", reason, input_path)
            return []

        bw = self._pybinwalk.Binwalk.configure(full_search=True) if deep else self._pybinwalk.Binwalk()
        log.debug("bw.base_output_directory=%r", bw.base_output_directory)
        log.debug("bw.base_target_file=%r", bw.base_target_file)

        return bw.scan_path(resolved)

    def extract_disk(self, input_path: str, output_root: str, deep: bool = False) -> Tuple[int, str, Dict[str, int]]:
        """
        Extraction pipeline:
        - Resolve disk path
        - Create job output directory
        - Configure binwalk output directorio
        - Read bytes once
        - Scan -> use file_map -> extract_bytes
        - Count successes and return stats
        """
        resolved, reason = resolve_disk_path(input_path, self._extracted_suffix)
        log.debug("resolve_disk_path: %s (%r)", reason, input_path)
        if resolved is None:
            log.error("Extraction failed: input file must be available on disk.")
            return 0, "", {"matches": 0, "attempted": 0, "success": 0}

        os.makedirs(output_root, exist_ok=True)
        job_dir = make_job_outdir(output_root, resolved)
        os.makedirs(job_dir, exist_ok=True)

        bw = self._pybinwalk.Binwalk.configure(
            target_file_name=os.path.basename(resolved),
            output_directory=job_dir,
            full_search=bool(deep),
        )
        log.debug("bw.base_output_directory=%r", bw.base_output_directory)
        log.debug("bw.base_target_file=%r", bw.base_target_file)

        res = bw.analyze_path(bw.base_target_file, do_extraction=True)
        file_map = res.file_map
        extraction_map = res.extractions

        declined = 0
        no_extractor = 0
        external_missing = 0
        external_ok = 0
        internal = 0

        for r in file_map:
            try:
                if getattr(r, "extraction_declined", False):
                    declined += 1
                    continue

                pe = r.preferred_extractor
                if pe is None:
                    no_extractor += 1
                    continue

                util = pe.utility
                kind = util.kind
                val = getattr(util, "value", None)

                if kind == "none":
                    no_extractor += 1
                elif kind == "internal":
                    internal += 1
                elif kind == "external":
                    ok, bin_name = _which_external(val)
                    if ok:
                        external_ok += 1
                    else:
                        external_missing += 1
                        log.info("missing external dependency: %s (signature=%s)", bin_name or val, getattr(r, "name", "?"))
            except Exception:
                pass

        attempted = 0
        success = 0

        for k, ex in extraction_map.items():
            attempted += 1
            try:
                ok = getattr(ex, "success", False)
                ext = getattr(ex, "extractor", None)
                out_dir = getattr(ex, "output_directory", None)

                if ok:
                    success += 1

                log.info(
                    "extraction: key=%r success=%r extractor=%r output_directory=%r",
                    k, ok, ext, out_dir
                )

            except Exception as e:
                log.info("extraction: key=%r (log failed: %s)", k, e)

        stats = {
            "matches": len(file_map),
            "attempted": attempted,
            "success": success,
            "declined": declined,
            "no_extractor": no_extractor,
            "internal": internal,
            "external_ok": external_ok,
            "external_missing": external_missing,
        }

        return success, job_dir, stats
