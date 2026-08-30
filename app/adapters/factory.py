from typing import Dict, Type
from app.adapters.base import BaseAdapter, AdapterError
from app.adapters.mock_adapter import MockAdapter
from app.adapters.digitalai_adapter import DigitalAIAdapter
from app.config import AdaptersConfig


class AdapterFactory:
    """Factory creating configured downstream adapter instances."""

    _registry: Dict[str, Type[BaseAdapter]] = {
        "mock": MockAdapter,
        "digitalai": DigitalAIAdapter,
    }

    @classmethod
    def create_adapter(cls, config: AdaptersConfig) -> BaseAdapter:
        adapter_name = config.active.lower()
        if adapter_name not in cls._registry:
            raise AdapterError(
                f"Unknown adapter '{adapter_name}'. Registered adapters: {list(cls._registry.keys())}"
            )

        adapter_cls = cls._registry[adapter_name]
        if adapter_name == "mock":
            return adapter_cls(config=config.mock)
        elif adapter_name == "digitalai":
            return adapter_cls(config=config.digitalai, timeout_seconds=config.timeout_seconds)

        return adapter_cls()

    @classmethod
    def register_adapter(cls, name: str, adapter_cls: Type[BaseAdapter]) -> None:
        cls._registry[name.lower()] = adapter_cls
