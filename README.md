# InfinityX OSINT Scanner

Created by Infinity.

One authorized domain. Fifty public checks. A black-and-red terminal, then a finished story: who registered the name, where DNS sends it, what the site answers, what the certificate says, and how mail policy is published.

InfinityX OSINT Scanner is passive reconnaissance for Kali Linux. You give it a domain you own or are allowed to assess. It gathers public WHOIS, DNS, HTTP, TLS, hosting, and email-authentication data, explains every result, and writes `report.txt`, `report.json`, and `report.html`. It does not guess passwords, exploit services, or scan ports.

Type `AGREE` before a scan starts. That confirmation is required even when you pass `--domain`.

## What the tool does

- It validates the domain and rejects localhost, internal names, and non-public addresses.
- It reads public WHOIS, DNS, HTTP, HTTPS, and the TLS certificate.
- It asks RIPEstat for ASN data and a geolocation estimate, and it asks crt.sh for certificate-transparency rows.
- It explains every check: what was found, what it means, how confident the result is, and what an administrator could do next.
- It writes `report.txt`, `report.json`, and `report.html` in a timestamped folder, with raw outputs and a redacted log.

## What the tool does not do

- It does not guess passwords, bypass logins, exploit vulnerabilities, or scan ports.
- It does not guess DKIM selectors.
- It does not follow redirects to localhost, private networks, link-local addresses, or cloud metadata services.
- It does not treat a missing HTTP header, a server banner, or a technology name as proof of a vulnerability.
- It does not declare a website safe or compromised. Passive collection cannot prove either of those things.
- Traceroute is off unless you pass `--enable-traceroute` and the `traceroute` command is installed.

## Requirements

- Python 3.10 or newer
- The Python packages in `requirements.txt` (`rich`, `requests`, `dnspython`, `cryptography`)
- Optional Kali packages: `whois`, `traceroute`, `whatweb`

The intended system is Kali Linux. The same Python code can run elsewhere. Optional commands that are not installed are marked `SKIPPED`.

## Install

Run these commands from the project directory, as a normal user. Do not use `sudo su`. `install.sh` refuses to run as root, and the files are not in your home directory until you clone or `cd` into the project.

```bash
git clone https://github.com/Infinity-X202/infinityx-osint.git
cd infinityx-osint
chmod +x install.sh
./install.sh
source .venv/bin/activate
python main.py
```

If `install.sh` says `No such file or directory`, you are not in the project folder. `pwd` should end in `infinityx-osint`.

`install.sh` lists the system packages and installs them only after you answer `y`. It refuses to run as root. Create the virtual environment as a normal user.

A direct launch, which still asks for authorization:

```bash
python main.py --domain example.com
```

Help and version:

```bash
python main.py --help
python main.py --version
```

Traceroute, only when you are authorized to send those probes:

```bash
python main.py --domain example.com --enable-traceroute
```

## Reports

Each scan creates `reports/<timestamp>_<domain>/`:

- `report.txt` — full written analysis
- `report.json` — every check and finding
- `report.html` — dashboard with summary cards, filters, and expandable details
- `raw_results/` — original WHOIS, HTTP, certificate, and lookup output
- `logs/scan.log` — execution log with secret-like values redacted

## Checks

The 50 checks are grouped as domain and WHOIS, DNS, website and HTTP, TLS, network and infrastructure, and email policy. Overlapping data, such as one WHOIS conversation or one homepage response, is fetched once and labeled as shared evidence.

## Safety notes

HTTP connections are pinned to an address that both 1.1.1.1 and 8.8.8.8 classified as public. Environment proxies are ignored so a proxy cannot bypass that check. Response bodies are capped. Cookie and authorization header values are not stored. System proxy variables and API keys are not required and are not written into reports.

Geolocation is an estimate and is often wrong for CDN and anycast addresses. Certificate-transparency names can be historical.

## Tests

From the project directory, with the virtual environment active:

```bash
python -m unittest discover -s tests -v
```
