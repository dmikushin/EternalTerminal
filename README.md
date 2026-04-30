# Eternal Terminal (SSH-compatibility fork)

Eternal Terminal is a remote shell that automatically reconnects without interrupting the session.

This fork adds **full OpenSSH-compatible port forwarding** (`-L`, `-R`, `-D`) and escape sequences (`~C`, `~.`, `~?`), making `et` a drop-in replacement for `ssh` in tunneling scenarios.

Upstream: <https://github.com/MisterTea/EternalTerminal>

## Installing

### Static binaries (any Linux, no dependencies)

Download a fully static musl-linked binary from the
[latest release](https://github.com/dmikushin/EternalTerminal/releases/latest):

```bash
# x86_64
curl -LO https://github.com/dmikushin/EternalTerminal/releases/download/v6.2.11/et-v6.2.11-linux-x86_64.tar.gz
tar xzf et-v6.2.11-linux-x86_64.tar.gz

# aarch64
curl -LO https://github.com/dmikushin/EternalTerminal/releases/download/v6.2.11/et-v6.2.11-linux-arm64.tar.gz
tar xzf et-v6.2.11-linux-arm64.tar.gz

# Install (client: et; server: etserver + etterminal)
sudo install -m 0755 et-* etserver-* etterminal-* /usr/local/bin/
```

### macOS (Homebrew)

The upstream Homebrew formula installs `et` without the forwarding extensions.
To get this fork's features, build from source (see below).

### Docker

See the [autoet](https://github.com/dmikushin/autossh-docker) container for
a ready-made tunnel image that uses this fork.

## Building from Source

### Dependencies

| OS | Command |
|----|---------|
| **Debian/Ubuntu** | `sudo apt install build-essential cmake ninja-build git libsodium-dev libprotobuf-dev protobuf-compiler libutempter-dev libcurl4-openssl-dev pkg-config` |
| **Fedora** | `sudo dnf install cmake gcc-c++ git libsodium-devel protobuf-devel protobuf-compiler gflags-devel libcurl-devel` |
| **macOS** | `brew install cmake libsodium protobuf` |
| **Alpine** | `apk add build-base cmake git libsodium-dev protobuf-dev openssl-dev zlib-dev` |

### Build

```bash
git clone --recurse-submodules https://github.com/dmikushin/EternalTerminal.git
cd EternalTerminal
mkdir build && cd build
cmake .. -DDISABLE_VCPKG=ON -DDISABLE_TELEMETRY=ON
make -j$(nproc)
sudo make install
```

For Alpine/musl, add `-DWITH_STACKTRACE=OFF` (musl lacks `backtrace(3)`).

## Verifying

- Client: `which et`
- Server: `systemctl status et` (enable with `sudo systemctl enable --now et`)

## Configuring

Edit `/etc/et.cfg` to change server settings (e.g. listening port).

## Using

ET uses SSH for handshaking and encryption. Make sure `ssh user@hostname` works first. ET uses TCP port 2022 by default.

```bash
et hostname                          # default port 2022
et user@hostname:8000                # custom port, explicit user
et hostname --jumphost jump_host     # via jumphost
```

### Port forwarding (identical to ssh)

```bash
# Local forward (-L): binds locally, connects on the server side
et -L 8080:remote-db:5432 hostname
et -L 127.0.0.1:8080:remote-db:5432 hostname   # explicit bind address
et -L /tmp/local.sock:remote-db:5432 hostname   # UNIX-domain source
et -L 8080:/var/run/remote.sock hostname         # UNIX-domain destination

# Remote forward (-R): binds on the server, connects on the client side
et -R 9090:localhost:3000 hostname
et -R 0.0.0.0:9090:localhost:3000 hostname       # wildcard bind on server

# Dynamic forward (-D): built-in SOCKS5 proxy
et -D 1080 hostname                              # SOCKS5 on 127.0.0.1:1080
et -D '*:1080' hostname                          # SOCKS5 on all interfaces

# Multiple forwards in one command
et -L 8080:db:5432 -R 9090:localhost:3000 -D 1080 hostname

# Additional flags
et -g ...           # gateway ports: default bind 0.0.0.0 instead of 127.0.0.1
et --exit-on-forward-failure ...   # exit if any forward fails (ssh ExitOnForwardFailure=yes)
```

ET-style port pairs (`-L "18000:8000,18001-18003:8001-8003"`) are also accepted for backward compatibility. Dynamic port allocation (`-L 0:host:port`) is supported and the assigned port is printed on stderr.

### Escape sequences (identical to ssh)

Type at the start of a line during a session:

| Sequence | Action |
|----------|--------|
| `~C` | Open a command line to add/cancel forwards (`-L`, `-R`, `-KL port`, `-KR port`) |
| `~.` | Terminate the session |
| `~?` | Print help |
| `~~` | Send a literal `~` |

### SSH config

ET parses `~/.ssh/config` and `/etc/ssh/ssh_config`:

```ssh-config
Host dev
  HostName 192.168.1.1
  User fred
  Port 5555
  ProxyJump user@jumphost.example.org:22
```

```bash
et dev              # uses config above
et dev:8000         # override etserver port
```

## Reporting issues

Please [file an issue](https://github.com/dmikushin/EternalTerminal/issues).

## Developers

- Jason Gauci (upstream): https://github.com/MisterTea
- Ailing Zhang (upstream): https://github.com/ailzhang
- James Short (upstream): https://github.com/jshort
- Dmitry Mikushin (this fork): https://github.com/dmikushin
