# VirusTotal Intelligence Live Hunt Connector

This connector allows organizations to feed their OpenCTI platform with sightings from their VirusTotal Live Hunts.

## Quick Start

We recommend running this connector from a container, when appropriate. If you build the container according to the directions below, you can pass in a detailed config, or specify configuration via environment variables. By default the container looks for a config at the path `/app/config.yml`. You should specify a different location if you need with the `-c` flag. Review the usage:

```shell
docker run --rm -ti vti-connector:latest --help
```

It's probably easiest to grab a copy of the reference config (`config.reference.yml`) and rename it `config.yml`. Make the necessary changes for your environment and pass it into the container.

```shell
docker run --rm -ti --volume $(pwd)/config.yml:/app/config.yml vti-connector:latest
```

### Requirements

- OpenCTI Platform >= 5.0.3
- Python 3.9.x (may work with lower version 3.x, but it was developed with 3.9)
- VirusTotal Enterprise subscription

### Configuration

Detailed configuration can be managed via the configuration file as noted in the quick start. The script looks for `config.yml` in the current directory, but a different path can be given on the command line. The "current directory" is `/app` in the
Docker container.

Optionally, many of the configuration points can be handled solely by environment variables as noted in the table below. This can be helpful to spin up a quick container to only specify what you need beyond the defaults. Lastly, the environment
variable `CONNECTOR_JSON_CONFIG` takes a JSON equivalent of the `config.yml` and will override all configuration values.

| YAML Parameter               | Environment Var              | Mandatory | Description                                                                                                             |
|------------------------------|------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------------|
| `opencti.token`              | `OPENCTI_TOKEN`              | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                             |
| `opencti.url`                | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                                                                                        |
| `opencti.ssl_verify`         | `OPENCTI_SSL_VERIFY`         | No        | Set to `False` to disable TLS certificate validation. Defaults to `True`                                                |
| `connector.confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | Yes       | The default confidence level for created sightings (a number between 0 and 100).                                        |
| `connector.id`               | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                      |
| `connector.log_level`        | `CONNECTOR_LOG_LEVEL`        | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                           |
| `connector.mode`             | `CONNECTOR_MODE`             | No        | Must be 'ecs' for ECS-formatted threat indicator documents or 'stix' for raw OpenCTI STIX documents. Defaults to 'ecs'. |
| `connector.name`             | `CONNECTOR_NAME`             | Yes       | The name of the Elastic instance, to identify it if you have multiple Elastic instances connectors.                     |
| `connector.scope`            | `CONNECTOR_SCOPE`            | Yes       | Must be `elastic`, not used in this connector.                                                                          |
| `connector.type`             | `CONNECTOR_TYPE`             | Yes       | Must be `STREAM` (this is the connector type).                                                                          |

## Building Container

To build the container to run on Docker, Kubernetes, or other OCI runtime, simply run the build from this directory.

```shell
docker build -t vti-connector:latest .
```

## Building virtual environment

This connector uses [Python Poetry](https://python-poetry.org/) to manage dependencies. If you want to run the project locally, create a virtual environment using your favorite tool (I like pyenv, but the virtualenv module would be just fine). See the
Poetry installation docs on how to install it.

```shell
# Install runtime dependencies
poetry install --no-dev

# Configure connector as noted above
cp config.reference.yml config.yml

# Run main script, it was installed to your virtualenv bin/ dir.
connector
```

If you want to run tests and do other development things use poetry to install those deps.

```shell
poetry install

# Run all tests tests (flake8, black, isort, unit tests in tests/ dir)
pytest
```
