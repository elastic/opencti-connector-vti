import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, NoReturn, TypedDict, Union

import ecs_logging
import vt
from plyara import Plyara
from plyara.utils import rebuild_yara_rule
from pycti import OpenCTIConnectorHelper
from stix2.v21 import Bundle as StixBundle
from stix2.v21 import File as StixFile
from stix2.v21 import Identity as StixIdentity
from stix2.v21 import Indicator as StixIndicator
from stix2.v21 import ObservedData as StixObservedData
from stix2.v21 import Sighting as StixSighting

from . import LOGGER_NAME
from .config import GlobalConfig

logger = logging.getLogger(LOGGER_NAME)

QueryFilterType = TypedDict(
    "QueryFilterType", {"key": str, "operator": str, "values": List[str]}
)


def SetupECSLogging() -> None:
    logger = logging.getLogger()

    # Remove existing stream handler
    _handlers = []
    for h in logger.handlers:
        if type(h) == logging.StreamHandler:
            _handlers.append(h)

    for h in _handlers:
        logger.removeHandler(h)

    # Add new ECS handler
    handler = logging.StreamHandler()
    handler.setFormatter(ecs_logging.StdlibFormatter())
    logger.addHandler(handler)


class VTLiveHuntConnector(object):
    def __init__(self, config: Dict[str, dict]):
        # Check for config file parameter
        self.config = GlobalConfig(**config)  # type: ignore

        # Update log level setting from config setting
        _cur_level = logger.getEffectiveLevel()
        if _cur_level >= logging.WARNING:
            logger.setLevel(self.config.connector.log_level)

        if self.config.opencti.json_logging:
            SetupECSLogging()

        logger.debug(f"Parsed config: {self.config.get_dict()}")

        self.shutdown_event: threading.Event = threading.Event()
        self.helper = OpenCTIConnectorHelper(config=self.config.get_dict())
        logger.info("Connected to OpenCTI")

        self.vt = vt.Client(self.config.livehunt.apikey)

        self.last_ts = 0
        self._identity: StixIdentity = None

    @property
    def identity(self):
        if not self._identity:
            _result = None
            if self.config.livehunt.system_id:
                _result = self.helper.api.identity.read(
                    id=self.config.livehunt.system_id
                )

            else:  # try lookup by connector name
                _filters: List[QueryFilterType] = [
                    {"key": "entity_type", "operator": "match", "values": ["System"]},
                    {
                        "key": "name",
                        "operator": "match",
                        "values": [self.helper.get_name()],
                    },
                ]
                _results = self.helper.api.identity.list(filters=_filters)
                if _results:
                    _result = _results[0]

            if _result:
                logger.debug(f"Found myself!: {_result}")
                self._identity = StixIdentity(
                    # BUG workaround, see https://github.com/OpenCTI-Platform/opencti/issues/1716
                    id=_result["standard_id"].replace("system--", "identity--"),
                    created=_result["created_at"],
                    modified=_result["updated_at"],
                    name=_result["name"],
                    identity_class=_result["entity_type"].lower(),
                    contact_information=_result["contact_information"],
                    type="identity",
                )
            else:
                # We'll have to create an identity
                self._identity = StixIdentity(
                    name=self.helper.get_name(),
                    identity_class="system",
                    description="VirusTotal LiveHunt connector for OpenCTI",
                )

        return self._identity

    def _sleep(self, delay_sec: int = 10):
        sleep_delay = (
            delay_sec if delay_sec is not None else self.config.livehunt.query_interval
        )
        time.sleep(sleep_delay)

    def _cleanup(self):
        self.vt.close()
        self.helper.stop()
        logger.info("Disconnected from OpenCTI")

    def run(self) -> None:
        logger.info("Entering main loop.")
        while not self.shutdown_event.is_set():
            try:

                for _note in self.get_notifications():
                    self.process_hunting_notification(_note)

                logger.debug(
                    f"Sleeping {self.config.livehunt.query_interval} seconds until next VT LiveHunt poll."
                )
                self._sleep(delay_sec=self.config.livehunt.query_interval)

            except (KeyboardInterrupt, SystemExit):
                logger.info("VT LiveHunt connector stopping...")
                self.shutdown_event.set()
                self._cleanup()

                exit(0)
            except Exception as e:  # noqa: B902
                logger.error("VT LiveHunt connector internal error: {0}", str(e))
                self._sleep()

    def get_notifications(self) -> vt.Iterator:
        _path: str = "/intelligence/hunting_notifications"
        _params: Dict[Any, Any] = {}

        _filters: List[str] = []
        for tag in self.config.livehunt.limit_tags:
            _filters.append(f"tag:{tag}")

        if self.last_ts:
            _filters.append(f"date:{self.last_ts}+")
        elif self.config.livehunt.since_date:
            _filters.append(f"date:{self.config.livehunt.since_date}+")

        _params["filter"] = ""
        if _filters:
            for item in _filters:
                _params["filter"] += f"{item} "

        logger.debug("Getting notifications with following filters:")
        logger.debug(_params["filter"])

        _cursor = None
        for _item in self.vt.iterator(path=_path, params=_params, cursor=_cursor):
            self.last_ts = max(self.last_ts, int(_item.date.timestamp()))
            yield _item

    def process_hunting_notification(self, note: vt.Object):
        logger.debug(f"Processing notification {note.id}")
        # Extract file hash. id format is: ruleset_id-rule_id-sha256-timestamp
        _rulesetID, _ruleID, _sha256, _timestamp = note.id.split("-")

        _timestamp = int(_timestamp)

        # Lookup indicator in OpenCTI
        _rule: Dict[str, Any] = self.get_opencti_rule(name=note.rule_name)
        _vt_rule = self.get_vt_rule(name=note.rule_name, ruleset_id=_rulesetID)

        _tags = note.rule_tags
        if self.config.livehunt.tag_with_rule:
            _tags.append(
                "onweek"
            )  # TODO: Remove this static tag and make "additional_tags" config option
            _tags.append(f"yara:{note.rule_name}".lower())

        _indicator: StixIndicator = None

        _indicator_fields: Dict[str, Union[str, Dict[str, str]]] = {
            "name": note.rule_name,
            "labels": _tags,
            "pattern_type": "yara",
            "pattern": rebuild_yara_rule(_vt_rule),
            "custom_properties": {},
        }

        if _vt_rule:
            _props: dict[str, str] = {}
            for entry in _vt_rule["metadata"]:
                if "x_virustotal_ruleset" in entry:
                    _props["x_virustotal_ruleset"] = entry["x_virustotal_ruleset"]
                if "x_virustotal_ruleset_id" in entry:
                    _props["x_virustotal_ruleset_id"] = entry["x_virustotal_ruleset_id"]
                if "x_opencti_id" in entry:
                    _props["x_opencti_id"] = entry["x_opencti_id"]

            _indicator_fields["custom_properties"] = _props

        if _rule:
            # Found the rule, let's make a sighting
            _indicator = StixIndicator(id=_rule["standard_id"], **_indicator_fields)
        else:
            logger.info(f"Rule {note.rule_name} not found in OpenCTI")
            _indicator = StixIndicator(**_indicator_fields)

        _file = StixFile(
            hashes={"SHA-256": _sha256},
            custom_properties={"x_opencti_labels": _tags},
        )
        _obs_data = StixObservedData(
            created_by_ref=self.identity.id,
            object_refs=[_file.id],
            first_observed=datetime.fromtimestamp(_timestamp, timezone.utc),
            last_observed=datetime.fromtimestamp(_timestamp, timezone.utc),
            number_observed=1,
            labels=_tags,
        )

        _sighting = StixSighting(
            created_by_ref=self.identity.id,
            sighting_of_ref=_indicator.id,
            first_seen=datetime.fromtimestamp(_timestamp, timezone.utc),
            # BUG workaround, fixed in stix2 v3.0.0, See https://github.com/oasis-open/cti-python-stix2/pull/504
            last_seen=datetime.fromtimestamp(_timestamp + 1, timezone.utc),
            observed_data_refs=[_obs_data.id],
            count=1,
            where_sighted_refs=[self.identity.id],
            labels=_tags,
        )

        _bundle = StixBundle(
            objects=[self.identity, _indicator, _file, _obs_data, _sighting],
            allow_custom=True,
        )

        logger.debug(f"Sending bundle id {_bundle.id}: {_bundle.serialize()}")
        self.helper.send_stix2_bundle(_bundle.serialize())

    def get_opencti_rule(
        self, name: str = None, id: str = None
    ) -> Union[NoReturn, Dict[str, Any]]:

        # Default filter is simply to match yara rules
        _filters: List[QueryFilterType] = [
            {"key": "pattern_type", "operator": "match", "values": ["yara"]}
        ]

        if id:
            _search = id
        elif name:
            _search = name

        _results = self.helper.api.indicator.list(filters=_filters, search=_search)

        if len(_results) > 1:
            logger.warning("Received more than a single result! Selecting first")

        if len(_results) == 0:
            logger.warning(
                f"Couldn't find a match for YARA rule named {name} or id {id}"
            )
            return None
        else:
            return _results[0]

    def get_vt_rule(self, name: str, ruleset_id: str) -> Dict[str, Any]:
        """
        Finds the requested yara rule name in a given VT ruleset ID. Returns a Plyara-parsed rule dict
        """
        _ruleset: vt.Object = self.get_vt_ruleset(id=ruleset_id)

        _parser = Plyara()
        _rule_list = _parser.parse_string(_ruleset.rules)
        logger.debug(f"Parsed rules: {_rule_list}")
        try:
            _rule = next(filter(lambda rule: rule["rule_name"] == name, _rule_list))
        except StopIteration:
            logger.error(f"Rule {name} wasn't found in VT ruleset {ruleset_id}.")
            return {}

        ruleset_set = False
        rulesetid_set = False
        if "metadata" not in _rule:
            _rule["metadata"] = []

        for entry in _rule["metadata"]:
            if "x_virustotal_ruleset" in entry:
                entry["x_virustotal_ruleset"] = _ruleset["name"]
                ruleset_set = True
            if "x_virustotal_ruleset_id" in entry:
                entry["x_virustotal_ruleset_id"] = _ruleset["id"]
                rulesetid_set = True

        if not ruleset_set:
            _rule["metadata"].append({"x_virustotal_ruleset": _ruleset.name})
        if not rulesetid_set:
            _rule["metadata"].append({"x_virustotal_ruleset_id": _ruleset.id})

        return _rule

    def get_vt_ruleset(self, id: str = None, name: str = None) -> vt.Object:
        _path: str = "/intelligence/hunting_rulesets"
        _result: Dict = None
        if id:
            _result = self.vt.get_object(path=f"{_path}/{id}")
            return _result

        elif name:
            _params: Dict[Any, Any] = {"filter": f"name:{name}"}
            for item in self.vt.iterator(path=_path, params=_params):
                # TODO: How do we handle if there's more than one match?
                _result = item
                break

            return _result

        else:
            logger.error("Either ID or Name must be specified to get ruleset.")
