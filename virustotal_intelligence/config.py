import os
from dataclasses import asdict, dataclass, field, fields
from typing import ClassVar, Dict, List, Union, cast, no_type_check


@dataclass
class AbstractConfig:
    config_root: ClassVar[str] = "base"

    def __post_init__(self):
        required_fields = (x for x in fields(self) if x.metadata.get("required", False))
        for item in required_fields:
            _path = ".".join([self.config_root, item.name])
            if not getattr(self, item.name, None) and not isinstance(
                getattr(self, item.name, None), bool
            ):
                if (
                    "environ" in item.metadata
                    and os.environ.get(item.metadata["environ"], None) is None
                ):
                    raise ValueError(
                        f"Setting {_path} or environment variable {item.metadata['environ']} must be set!"
                    )
                elif (
                    "environ" in item.metadata
                    and not os.environ.get(item.metadata["environ"], None) is None
                ):
                    setattr(self, item.name, os.environ.get(item.metadata["environ"]))
                else:
                    raise ValueError(f"Setting {_path} must be set!")

        # Update from environment, if set, no validation needed
        optional_fields = (
            x for x in fields(self) if not x.metadata.get("required", False)
        )
        for item in optional_fields:
            if not getattr(self, item.name, None) or isinstance(
                getattr(self, item.name, None), bool
            ):
                if (
                    "environ" in item.metadata
                    and not os.environ.get(item.metadata["environ"], None) is None
                ):
                    _env_val = os.environ.get(item.metadata["environ"])
                    if isinstance(getattr(self, item.name, None), bool):
                        _env_val = _env_val.lower() == "true"
                    setattr(self, item.name, _env_val)


@dataclass
class OpenCTIConfig(AbstractConfig):
    config_root: ClassVar[str] = "opencti"
    token: str = field(
        default="", metadata={"environ": "OPENCTI_TOKEN", "required": True}
    )
    url: str = field(
        default="http://127.0.0.1:8080", metadata={"environ": "OPENCTI_URL"}
    )
    ssl_verify: bool = field(default=True, metadata={"environ": "OPENCTI_SSL_VERIFY"})
    json_logging: bool = field(
        default=False, metadata={"environ": "OPENCTI_JSON_LOGGING"}
    )


_default_opencti = {
    "url": "http://127.0.0.1:8080",
    "ssl_verify": True,
    "json_logging": False,
}


@dataclass
class ConnectorConfig(AbstractConfig):
    config_root: ClassVar[str] = "connector"
    id: str = field(default="", metadata={"environ": "CONNECTOR_ID", "required": True})
    type: str = field(default="", metadata={"environ": "CONNECTOR_TYPE"})
    live_stream_id: str = field(
        default="", metadata={"environ": "CONNECTOR_LIVE_STREAM_ID"}
    )
    name: str = field(default="", metadata={"environ": "CONNECTOR_NAME"})
    confidence_level: int = field(
        default=0, metadata={"environ": "CONNECTOR_CONFIDENCE_LEVEL"}
    )
    scope: str = field(default="", metadata={"environ": "CONNECTOR_SCOPE"})
    auto: bool = field(default=False, metadata={"environ": "CONNECTOR_AUTO"})
    only_contextual: bool = field(
        default=False, metadata={"environ": "CONNECTOR_ONLY_CONTEXTUAL"}
    )
    log_level: str = field(default="", metadata={"environ": "CONNECTOR_LOG_LEVEL"})
    # TODO: Implement run_and_terminate to do a single-shot connector run
    run_and_terminate: bool = field(
        default=False, metadata={"environ": "CONNECTOR_RUN_AND_TERMINATE"}
    )


_default_connector = {
    "name": "VirusTotal-LiveHunt",
    "type": "EXTERNAL_IMPORT",
    "confidence_level": 15,
    "scope": "virustotal-livehunt",
    "log_level": "WARN",
}


@dataclass
class LiveHuntConfig(AbstractConfig):
    config_root: ClassVar[str] = "livehunt"
    apikey: str = field(
        default="", metadata={"environ": "LIVEHUNT_APIKEY", "required": True}
    )
    system_id: str = field(default="", metadata={"environ": "LIVEHUNT_SYSTEM_ID"})
    """Filter the object types that get imported. Use this to import only files but not indicators, for example."""
    # TODO: Impelement optional import scopes
    import_scope: List[str] = field(
        default_factory=list, metadata={"environ": "LIVEHUNT_IMPORT_SCOPE"}
    )
    """How often to check the notification API for new results."""
    query_interval: int = field(
        default=0, metadata={"environ": "LIVEHUNT_QUERY_INTERVAL"}
    )
    """Use this option to filter livehunt notifications. You can use the ruleset name by replacing any '-' with '_'"""
    limit_tags: List[str] = field(
        default_factory=list, metadata={"environ": "LIVEHUNT_LIMIT_TAGS"}
    )
    """Specifies an earliest time to import. No notifications prior to this date will be imported."""
    since_date: str = field(default=None, metadata={"environ": "LIVEHUNT_SINCE_DATE"})

    """Adds tags to imported file object with the rule name (e.g. `yara:my_yara_rulename`) and a `livehunt` tag. """
    tag_with_rule: bool = field(
        default=None, metadata={"environ": "LIVEHUNT_TAG_WITH_RULE"}
    )

    def __post_init__(self):
        super().__post_init__()
        if isinstance(self.import_scope, str):
            self.import_scope = self.import_scope.split(",")
        if isinstance(self.limit_tags, str):
            self.limit_tags = self.limit_tags.split(",")


_default_livehunt = {
    "import_scope": ["indicator", "sighting", "file"],
    "query_interval": 300,
    "limit_tags": [],
    "since_date": None,
    "tag_with_rule": False,
}


@dataclass
class GlobalConfig:
    opencti: OpenCTIConfig = cast(OpenCTIConfig, field(default_factory=dict))
    connector: ConnectorConfig = cast(ConnectorConfig, field(default_factory=dict))
    livehunt: LiveHuntConfig = cast(LiveHuntConfig, field(default_factory=dict))

    def __post_init__(self):
        self.opencti = OpenCTIConfig(**(_default_opencti | self.opencti))
        self.connector = ConnectorConfig(**(_default_connector | self.connector))
        self.livehunt = LiveHuntConfig(**(_default_livehunt | self.livehunt))

    def get_dict(self) -> Dict[str, Dict[str, Union[str, bool, int]]]:
        return _drop_nones(asdict(self))


# minimum config
# config = GlobalConfig(**{"opencti": {"token": "foo", "url": "http://example.com"}, "connector": {"id": "bar"}, "livehunt":{"apikey": "baz"}})


@no_type_check
def _drop_nones(d: dict) -> dict:
    """Recursively drop Nones in dict d and return a new dict"""
    dd = {}
    for k, v in d.items():
        if isinstance(v, dict):
            dd[k] = _drop_nones(v)
        elif isinstance(v, (list, set, tuple)):
            # note: Nones in lists are not dropped
            dd[k] = type(v)(_drop_nones(vv) if isinstance(vv, dict) else vv for vv in v)
        elif isinstance(v, str) and v:
            dd[k] = v
        elif v is not None:
            dd[k] = v
    return dd
