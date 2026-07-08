# aegis/state.py
import asyncio

SHELL_OPENED = False
SHELL_LOCK = asyncio.Lock()
SHELL_TASK = None
