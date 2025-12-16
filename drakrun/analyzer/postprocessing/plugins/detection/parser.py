class LogParser:
    @staticmethod
    def parse(entry: Dict[str, Any]) -> Optional[Log]:
        plugin = entry.get("Plugin")
        
        if plugin == "syscall":
            return SystemCall.model_validate(entry)
        
        elif plugin == "apimon":
            event_type = entry.get("Event")
            if event_type == "api_called":
                return WinApiCall.model_validate(entry)
            
        return None