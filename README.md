# gdetect library & client

A Python client and a library for GLIMPS Gmalware detect.

GLIMPS Gmalware detect is a solution from GLIMPS *Inc.* for a better detection of malware. Contact us at <contact@glimps.re> for more information !  

## Description

`gdetect` library aims to simplify use of *GLIMPS Detect*, a malware detection solution from GLIMPS *Inc.*.
This tool can be used by two ways:

* As *shell* CLI: `python3 -m gdetect /path/to/my/binary`
* As python library (see below).

## Installation

### From PyPI

```bash
python3 -m pip install gdetect
```

## Usage

### As shell *CLI* tool

Before launch the tool, you can set the path to your GDetect URL and your authentication token into environment variables with:

`export API_URL=https://my.gdetect.service.tld` for the URL;  
`export API_TOKEN=abcdef01-23456789-abcdef01-23456789-abcdef01` for the token.

You can use *gdetect* in your shell like this:

* `python3 -m gdetect /path/to/my/binary` to send your binary to API. This command return an UUID to you (*send* is the default command, so you don't need to specify this).
* `python3 -m gdetect get my_returned_uuid` to get your result.
* To have some help: `python3 -m gdetect --help`:

```bash
Usage: python -m gdetect [OPTIONS] COMMAND [ARGS]...

Options:
  --url TEXT      url to GLIMPS Detect API
  --token TEXT    authentication token
  --password TEXT password used to extract archive
  --insecure      disable HTTPS check
  --no-cache      submit file even if a result already exists
  --help          Show this message and exit.

Commands:
  send*    send file to API.
  get      get result for given uuid.
  waitfor  send a file and wait for the result.
  search   get result for given sha256.
```

* `python3 -m gdetect waitfor /path/to/my/binary` allows you to send your binary and wait for a result (*blocking mode*). You can pass a `--timeout X` option with an integer to stop after X minutes.

### As a Python library

All stuff are done with a `Client` object from `gdetect.api`:

```python
from gdetect import Client # direct object import set in __init__ file

client=Client(url='https://path/to/my/gdetect/service', token='qwerty012345678')
uuid=client.push('my_bad_binary.exe')
# wait some minutes to get a result
result=client.get(uuid)
print(result)
```

Look at documentation for details about available methods, exceptions and more. To build internal documentation, uses `tox` tool inside your local clone of this repository (need extra packages: `pip install -r requirements-dev.txt`):

```bash
tox -e docs
```

All documentations are now inside `docs/_build/html` directory.

## Support

If you have any questions, open an *issue* on Github.

## Contributing

If you want to contribute, just follow the [Github PR flow](https://docs.github.com/en/get-started/quickstart/github-flow#create-a-pull-request).

Install all needed library from `requirements-dev.txt` ; update it if needed.

Coverage your code with test (please use `pytest` for that).

Before submit your *pull request*, please use `black` as formatter, `pylint` (`tox -e pylint`) and `flake8` (`tox -e flake8`) as linter and test your code throught many versions. To do that, you can use `tox` (look at `tox.ini` for options). Just launch `tox` to do that.

## Authors

***GLIMPS dev core team***

## License

This project is under **MIT License**.

## Project status

This project is in *Beta* development status. Feel free to participate !
