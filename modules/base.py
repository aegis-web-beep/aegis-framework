from abc import ABC, abstractmethod
from aiohttp import ClientSession

class BaseModule(ABC):
    def __init__(self, auditor_instance):
        self.auditor = auditor_instance

    @abstractmethod
    async def run_audit(self, session: ClientSession) -> bool:
        pass
