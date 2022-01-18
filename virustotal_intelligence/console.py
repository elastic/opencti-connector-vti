#!/usr/bin/env python3
"""
Usage:  connector [-v | -vv | -vvv | -q | --debug] [-c FILE] [-d DIR]
        connector --version

Runs the VirusTotal Live Hunt OpenCTI connector using provided config.yml
file. See config.reference.yml for full configuration options and optional
environment variables.

Options:
    -h --help                   show this help message and exit
    --version                   show version and exit
    -c FILE --config=FILE       path to YAML configuration [default: config.yml]
    -v                          increase verbosity (can be used up to 3 times)
    -q                          quiet mode
    --debug                     enable debug logging for all Python modules
"""
# code: language=python spaces=4 insertspaces

import logging
import os
from importlib.metadata import version
from typing import Dict, NoReturn, Union

from docopt import docopt
from ruamel.yaml import YAML

from . import LOGGER_NAME, __version__
from .connector import VTLiveHuntConnector

logger = logging.getLogger(LOGGER_NAME)


def setup_logger(args: Dict[str, str]) -> None:
    _verbosity: int = 0
    _loggername = LOGGER_NAME
    if not args["-q"] is True:
        _verbosity = 30 + (int(args["-v"]) * -10)
        # If this is set to 0, it defaults to the root logger configuration,
        # which we don't want to manipulate because it will spam from other modules
        if _verbosity == 0:
            _verbosity = 5
    else:
        _verbosity = 40
    if args["--debug"] is True:
        # Enable full logging for all loggers
        _loggername = None
        _verbosity = 10
    # TODO: It'd be great to handle an optional JSON output
    logger = logging.getLogger(name=__name__)

    if _verbosity < 20:
        FORMAT = "[%(asctime)s.%(msecs)03d][%(filename)20s:%(lineno)-4s][%(threadName)s][ %(funcName)20s() ][%(levelname)s] %(message)s"
    else:
        FORMAT = "[%(asctime)s.%(msecs)03d][%(levelname)s] %(message)s"

    logger = logging.getLogger(_loggername)
    logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%dT%H:%M:%S")
    logger.setLevel(_verbosity)


def load_config(filename: str) -> Union[Dict[str, Dict[str, str]], NoReturn]:
    logger.debug(f"load_config: {filename}")
    _yaml = YAML()
    if os.path.exists(filename):
        with open(filename) as f:
            return _yaml.load(f)
    else:
        return {}


def main() -> None:
    cti_ver = version("pycti")
    my_version: str = (
        f"{__name__} {__version__}\n" f"pyopencti                       { cti_ver }\n"
    )
    arguments: Dict[str, str] = docopt(__doc__, version=my_version)
    setup_logger(arguments)
    logger.debug("logger setup complete")

    _cfg: dict[str, dict] = {}
    if "--config" in arguments and os.path.exists(arguments["--config"]):
        _cfg = load_config(arguments["--config"])

    _connector = VTLiveHuntConnector(_cfg)
    _connector.run()
