import logging
from pathlib import Path
from typing import Iterator, Optional, Union
import msgspec
from .models import Log, SystemCall, WinApiCall

logger = logging.getLogger(__name__)


class LogParser:
    def parse_entry(self, line: bytes) -> Optional[Log]:
        """Parse a single JSON line into a Log object."""
        try:
            raw_dict = msgspec.json.decode(line)
            raw_dict["raw"] = raw_dict.copy()

            match (raw_dict.get("Plugin"), raw_dict.get("Event")):
                case ("syscall", _):
                    return msgspec.convert(raw_dict, SystemCall)

                case ("apimon", "api_called"):
                    if isinstance(raw_dict.get("Arguments"), list):
                        raw_dict["Arguments"] = dict(
                            arg.split("=", 1) for arg in raw_dict["Arguments"]
                        )
                    return msgspec.convert(raw_dict, WinApiCall)

                case _:
                    return None

        except msgspec.DecodeError as e:
            logger.error(f"Failed to decode entry: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to parse entry: {e}")
            return None

    def parse_file(self, log_file: Union[str, Path]) -> Iterator[Log]:
        """Parse a log file and yield Log objects."""
        log_path = Path(log_file)

        with log_path.open("rb") as f:
            for line_no, line in enumerate(f, start=1):
                try:
                    line = line.strip()
                    if not line:
                        continue

                    log_obj = self.parse_entry(line)

                    if log_obj is not None:
                        yield log_obj

                except Exception:
                    logger.exception(f"Unexpected error at line {line_no} in {log_path}")