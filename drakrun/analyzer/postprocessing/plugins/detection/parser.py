import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Union
from .models import Log, SystemCall, WinApiCall

logger = logging.getLogger(__name__)


class LogParser:
    @staticmethod
    def parse_entry(entry: Dict[str, Any]) -> Optional[Log]:
        plugin = entry.get("Plugin")

        entry_with_raw = {**entry, "raw": entry}

        try:
            if plugin == "syscall":
                return SystemCall.model_validate(entry_with_raw)

            elif plugin == "apimon":
                event_type = entry.get("Event")
                if event_type == "api_called":
                    return WinApiCall.model_validate(entry_with_raw)
        except Exception as e:
            logger.error(f"Failed to parse {plugin} entry: {e}")
            logger.debug(f"Entry data: {entry}")
            return None

        return None

    @classmethod
    def parse_file(cls, log_file: Union[str, Path]) -> Iterator[Log]:
        """Parse a log file and yield Log objects."""
        log_path = Path(log_file)

        with log_path.open("r") as f:
            for line_no, line in enumerate(f, start=1):
                try:
                    line = line.strip()
                    if not line:
                        continue

                    entry = json.loads(line)
                    log_obj = cls.parse_entry(entry)

                    if log_obj is not None:
                        yield log_obj

                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse JSON at line {line_no} in {log_path}")
                except Exception:
                    logger.exception(f"Unexpected error at line {line_no} in {log_path}")