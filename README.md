# zteOnu

A single-file Python script to interact with ZTE ONU factory mode.

> For security research and your own devices only.

## Install

```bash
pip install requests pycryptodome
```

## Usage

```bash
python3 zte_onu.py <ip> -m <your-mac> [options]
```

| Option | Required | Description |
|--------|:---:|-------------|
| `ip` | ✔️ | Device IP |
| `-m` | ✔️ | Your NIC MAC, e.g. `AA:BB:CC:DD:EE:FF` |
| `-port` | — | Web port (default `8080`) |
| `-u` | — | Username(s) |
| `-p` | — | Password(s) |
| `-slaveip` | — | Append `&slaveip=<ip>` to step 5 |
| `-close` | — | Close factory mode |
| `-all` | — | Try all credentials |
| `-v` | — | Verbose output |

## Examples

```bash
# Basic
python3 zte_onu.py 192.168.1.1 -m AA:BB:CC:DD:EE:FF

# Verbose
python3 zte_onu.py 192.168.1.1 -m AA:BB:CC:DD:EE:FF -v

# Custom credentials
python3 zte_onu.py 192.168.1.1 -m AA:BB:CC:DD:EE:FF -u telecomadmin -p 'nE7jA%5m'

# Close factory mode
python3 zte_onu.py 192.168.1.1 -m AA:BB:CC:DD:EE:FF -close
```

## License

AGPL-3.0. See [LICENSE](LICENSE).
