# blackbox-scan

This tool is a command-line client for the [BlackBox](https://bbs.ptsecurity.com/) API, that can help to integrate Dynamic Application Security Testing (DAST) into a CI/CD pipeline.

## Requirements

[Python](https://www.python.org/) version 3.6.2 or above is required to run the tool. The use of [virtualenv](https://docs.python.org/3/library/venv.html) is recommended.

To install required Python packages, run:

```shell
pip install -r requirements.txt
```

## Usage

### Synopsis

```
  blackbox-scan.py [OPTIONS]
```

### Options

```
Usage: blackbox-scan.py [OPTIONS]

Options:
  --blackbox-url TEXT
  --blackbox-api-token TEXT       [required]
  --target-url TEXT               [required]
  --ignore-ssl                    Skip verification of BlackBox API host
                                  certificate.
  --auto-create                   Automatically create a site if a site with
                                  the target URL was not found.
  --previous [wait|stop|fail]     What to do if the target is currently being
                                  scanned.
  --no-wait                       Do not wait until the started scan is
                                  finished.
  --shared-link                   Create shared link for scan.
  --scan-profile TEXT             Set scan profile UUID for new scan
  --fail-under-score INTEGER RANGE
                                  Fail with exit code 3 if report scoring is
                                  less then given score (set '1' or do not set
                                  to never fail).  [1<=x<=10]
  --help                          Show this message and exit.
```

### Environment

The following environment variables may be used instead of corresponding options:

- `BLACKBOX_URL`/`--blackbox-url`
- `BLACKBOX_API_TOKEN`/`--blackbox-api-token`
- `TARGET_URL`/`--target-url`
- `IGNORE_SSL`/`--ignore-ssl`
- `SCAN_PROFILE`/`--scan-profile`

## Example

```shell
export BLACKBOX_URL=https://bbs.ptsecurity.com/
export BLACKBOX_API_TOKEN=D4OPXw7mXCWjHER0lE48PCr4UkcfD86AwOwnio9I1w3HsOSS3Hxo9xi82hoWOB5deVYMk3kedgh0f9yq
export TARGET_URL=http://staging.example.com/

python blackbox-scan.py --auto-create --previous=stop
```

## Results

When a scan finishes without an error, the tool returns exit code `0` and prints JSON-formatted report to `stdout`. A report may be passed for processing to a tool such as [jq](https://stedolan.github.io/jq/).

Example output (reformatted for readability):

```json
{
    "url": "https://bbs.ptsecurity.com/sites/ccb7de77-ff51-464d-bf25-7ebcfe0403d6/scans/1",
    "vulns": {
        "issue_groups": [
            {
                "severity": "low",
                "category": "sensitive_data",
                "group_title": "server_software_version_disclosure",
                "vulns": [
                    {
                        "url": "http://staging.example.com/"
                    },
                    {
                        "url": "http://staging.example.com/upload.php"
                    }
                ]
            },
            {
                "severity": "high",
                "category": "insecure_design",
                "group_title": "fileupload",
                "vulns": [
                    {
                        "url": "http://staging.example.com/upload.php"
                    }
                ]
            },
            {
                "severity": "medium",
                "category": "cryptography",
                "group_title": "no_https_scheme",
                "vulns": [
                    {
                        "url": "https://staging.example.com/"
                    }
                ]
            }
        ],
        "error_page_groups": [
            {
                "group_title": "404",
                "category": "tech_info",
                "vulns": [
                    {
                        "url": "http://staging.example.com/cgi-bin/"
                    }
                ]
            },
            {
                "group_title": "501",
                "category": "tech_info",
                "vulns": [
                    {
                        "url": "http://staging.example.com/"
                    }
                ]
            }
        ],
        "cve_groups": [
            {
                "category": "cve",
                "group_title": "Apache 2.4.43",
                "vulns": [
                    {
                        "cve_id": "CVE-2021-26691",
                        "vector": "(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
                    },
                    {
                        "cve_id": "CVE-2020-9490",
                        "vector": "(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)"
                    }
                ]
            }
        ]
    },
    "score": 1,
    "sharedLink": "https://bbs.ptsecurity.com/shared/dee4Lyx"
}
```

In case an error occurs, the tool returns non-zero exit code and prints error log messages to `stderr`:

```
2021-12-03 13:24:52,517 ERROR [root] BlackBox error: the scan did not succeed, see UI for the error reason: http://bbs.ptsecurity.com/sites/ccb7de77-ff51-464d-bf25-7ebcfe0403d6/scans/1
```

## Bugs and Issues

To report a problem related to the tool, please create a new issue.

## Terms

For BlackBox terms of use, see [BlackBox License](https://bbs.ptsecurity.com/license).

## License

For the tool licensing terms, see [LICENSE](LICENSE) file.
