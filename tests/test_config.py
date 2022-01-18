import os
from unittest import mock

import pytest

from virustotal_intelligence.config import GlobalConfig

DEFAULT_CONFIG = {
    "opencti": {
        "url": "http://127.0.0.1:8080",
        "ssl_verify": True,
        "json_logging": False,
        "token": "<EXAMPLE-VALUE>",
    },
    "connector": {
        "auto": False,
        "live_stream_id": "",
        "id": "<EXAMPLE-VALUE>",
        "name": "VirusTotal-LiveHunt",
        "type": "EXTERNAL_IMPORT",
        "confidence_level": 15,
        "scope": "virustotal-livehunt",
        "log_level": "WARN",
        "only_contextual": False,
        "run_and_terminate": False,
    },
    "livehunt": {
        "apikey": "<EXAMPLE-VALUE>",
        "import_scope": ["indicator", "sighting", "file"],
        "query_interval": 300,
        "system_id": "",
        "limit_tags": [],
        "tag_with_rule": False,
    },
}


def test_default_config():
    # These are the minimum required values that must be present in either the file or environment
    _cfg: GlobalConfig = GlobalConfig(
        **{
            "opencti": {"token": "<EXAMPLE-VALUE>"},
            "connector": {"id": "<EXAMPLE-VALUE>"},
            "livehunt": {"apikey": "<EXAMPLE-VALUE>"},
        }
    )
    _cfg_dict = _cfg.get_dict()

    assert _cfg_dict == DEFAULT_CONFIG


def test_config_validation():

    with pytest.raises(ValueError):
        _cfg: GlobalConfig = GlobalConfig({})  # noqa F841

    with pytest.raises(ValueError) as excinfo:
        _cfg: GlobalConfig = GlobalConfig(  # noqa F841
            **{
                "connector": {"id": "<EXAMPLE-VALUE>"},
                "livehunt": {"apikey": "<EXAMPLE-VALUE>"},
            }
        )
    assert "OPENCTI_TOKEN" in str(excinfo)

    with pytest.raises(ValueError) as excinfo:
        _cfg: GlobalConfig = GlobalConfig(  # noqa F841
            **{
                "opencti": {"token": "<EXAMPLE-VALUE>"},
                "livehunt": {"apikey": "<EXAMPLE-VALUE>"},
            }
        )
    assert "CONNECTOR_ID" in str(excinfo)

    with pytest.raises(ValueError) as excinfo:
        _cfg: GlobalConfig = GlobalConfig(  # noqa F841
            **{
                "opencti": {"token": "<EXAMPLE-VALUE>"},
                "connector": {"id": "<EXAMPLE-VALUE>"},
            }
        )
    assert "LIVEHUNT_APIKEY" in str(excinfo)


ENV_CONFIG = {
    "opencti": {
        "url": "http://127.0.0.1:8080",
        "ssl_verify": True,
        "json_logging": True,
        "token": "<EXAMPLE-VALUE>",
    },
    "connector": {
        "auto": False,
        "id": "<EXAMPLE-VALUE>",
        "name": "VirusTotal-LiveHunt",
        "type": "EXTERNAL_IMPORT",
        "confidence_level": 15,
        "scope": "virustotal-livehunt",
        "log_level": "WARN",
        "live_stream_id": "",
        "only_contextual": False,
        "run_and_terminate": False,
    },
    "livehunt": {
        "import_scope": ["indicator", "sighting", "file"],
        "query_interval": 300,
        "limit_tags": ["ELASTIC_OPENCTI"],
        "tag_with_rule": False,
        "apikey": "<EXAMPLE-VALUE>",
        "system_id": "",
    },
}


def test_env_config():
    with mock.patch.dict(
        os.environ,
        {
            "OPENCTI_TOKEN": "<EXAMPLE-VALUE>",
            "CONNECTOR_ID": "<EXAMPLE-VALUE>",
            "LIVEHUNT_APIKEY": "<EXAMPLE-VALUE>",
            "LIVEHUNT_LIMIT_TAGS": "ELASTIC_OPENCTI",
            "OPENCTI_JSON_LOGGING": "True",
        },
    ):
        _cfg: GlobalConfig = GlobalConfig({})
        _cfg_dict = _cfg.get_dict()

        assert _cfg_dict == ENV_CONFIG


SIMULATED_FILE_CONFIG = {
    "opencti": {
        "url": "http://example.com",
        "ssl_verify": True,
        "json_logging": False,
        "token": "<EXAMPLE-VALUE>",
    },
    "connector": {
        "auto": False,
        "live_stream_id": "",
        "id": "<EXAMPLE-VALUE>",
        "name": "VirusTotal-LiveHunt",
        "type": "EXTERNAL_IMPORT",
        "confidence_level": 15,
        "scope": "virustotal-livehunt",
        "log_level": "WARN",
        "only_contextual": False,
        "run_and_terminate": False,
    },
    "livehunt": {
        "apikey": "<EXAMPLE-VALUE>",
        "import_scope": ["indicator", "sighting", "file"],
        "query_interval": 300,
        "system_id": "",
        "limit_tags": [],
        "tag_with_rule": False,
    },
}


def test_file_config():

    _simulated_file_config = {
        "opencti": {"token": "<EXAMPLE-VALUE>", "url": "http://example.com"},
        "connector": {
            "id": "<EXAMPLE-VALUE>",
        },
        "livehunt": {
            "apikey": "<EXAMPLE-VALUE>",
        },
    }
    _cfg: GlobalConfig = GlobalConfig(**_simulated_file_config)
    _cfg_dict = _cfg.get_dict()

    assert _cfg_dict == SIMULATED_FILE_CONFIG
