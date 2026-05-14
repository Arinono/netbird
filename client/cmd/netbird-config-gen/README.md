# NetBird Config Generator

A standalone binary that generates NetBird client configuration files (`default.json`) without requiring the NetBird daemon to be running. This is particularly useful for automated provisioning and managed environments.

## Use Case

This tool addresses the need described in [GitHub issue #6037](https://github.com/netbirdio/netbird/issues/6037) - the ability to configure a NetBird client profile using CLI before the service is started.

## Building

From the repository root:

```bash
go build -o netbird-config-gen ./client/cmd/netbird-config-gen/
```

Or install it to your GOPATH/bin:

```bash
go install ./client/cmd/netbird-config-gen/
```

## Usage

### How to reset the config fully

```bash
sudo rm -rf /var/lib/netbird && sudo netbird service reset-params && sudo netbird service reconfigure
```

### Basic Example

Generate a config with custom management URL and block inbound connections:

```bash
sudo netbird-config-gen --management-url https://netbird.selfhosted.com --block-inbound
```

### Advanced Example

Generate config with multiple options:

```bash
sudo netbird-config-gen \
  --management-url https://my.netbird.io \
  --block-inbound \
  --block-lan-access \
  --disable-client-routes \
  --disable-dns \
  --interface-name wt0
```

### Update Existing Config

The tool can also update an existing configuration:

```bash
sudo netbird-config-gen \
  --config /var/lib/netbird/default.json \
  --disable-firewall \
  --enable-rosenpass
```

### Custom Config Path

By default, the tool writes to `/var/lib/netbird/default.json` (Linux) or appropriate paths for other OSes. You can override this:

```bash
sudo netbird-config-gen -c /custom/path/config.json -m https://my.netbird.io
```

## Available Flags

### Core Settings
- `-c, --config` - Path to config file (default: `/var/lib/netbird/default.json`)
- `-m, --management-url` - Management Service URL
- `--admin-url` - Admin Panel URL
- `--state-dir` - State directory for NetBird

### Network Settings
- `--external-ip-map` - External IP mappings
- `--dns-resolver-address` - Custom DNS resolver address
- `--extra-dns-labels` - Extra DNS labels
- `--interface-name` - WireGuard interface name
- `--wireguard-port` - WireGuard listening port
- `--mtu` - MTU for WireGuard interface
- `--network-monitor` - Enable network monitoring
- `--dns-router-interval` - DNS route update interval
- `--enable-lazy-connection` - Enable lazy connection

### Security Settings
- `--enable-rosenpass` - Enable Rosenpass post-quantum security
- `--rosenpass-permissive` - Enable Rosenpass permissive mode
- `-p, --preshared-key` - WireGuard PreSharedKey

### Feature Flags
- `--disable-auto-connect` - Disable auto-connect on startup
- `--allow-server-ssh` - Allow SSH server
- `--enable-ssh-root` - Enable SSH root login
- `--enable-ssh-sftp` - Enable SSH SFTP
- `--enable-ssh-local-port-forward` - Enable SSH local port forwarding
- `--enable-ssh-remote-port-forward` - Enable SSH remote port forwarding
- `--disable-ssh-auth` - Disable SSH authentication
- `--ssh-jwt-cache-ttl` - SSH JWT cache TTL in seconds
- `--disable-client-routes` - Disable client routes
- `--disable-server-routes` - Disable server routes
- `--disable-dns` - Disable DNS configuration
- `--disable-firewall` - Disable firewall configuration
- `--block-lan-access` - Block LAN access
- `--block-inbound` - Block inbound connections
- `--disable-ipv6` - Disable IPv6 overlay
- `--disable-notifications` - Disable notifications
- `--extra-iface-blacklist` - Extra interfaces to blacklist

## Integration with Lockdown

This tool works perfectly with the existing lockdown command:

```bash
# 1. Generate the configuration
sudo netbird-config-gen --management-url https://netbird.selfhosted.com --block-inbound

# 2. Lock down the client (disable further config changes)
sudo netbird service reconfigure --disable-update-settings --disable-profiles
```

## How It Works

The tool uses the same `profilemanager` package that the main NetBird client uses, ensuring:

1. **Consistent configuration format** - Generated files are 100% compatible with NetBird
2. **Proper key generation** - Automatically generates WireGuard private keys and SSH keys
3. **Smart defaults** - Applies the same defaults as `netbird up`
4. **Atomic updates** - Uses the same safe file writing mechanisms
5. **Correct permissions** - Sets 0600 permissions on generated files

## Platform Support

- Linux (default path: `/var/lib/netbird/default.json`)
- macOS (default path: `~/Library/Application Support/netbird/default.json`)
- Windows (default path: `%PROGRAMDATA%\Netbird\default.json`)
- FreeBSD (default path: `/var/db/netbird/default.json`)

## Environment Variables

- `NB_STATE_DIR` - Override the default state directory
