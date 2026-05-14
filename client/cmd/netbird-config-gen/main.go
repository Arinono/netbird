//go:build !ios && !android

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/util"
)

var (
	// Config paths
	configPath string
	stateDir   string

	// Management settings
	managementURL string
	adminURL      string

	// Network settings
	natExternalIPs   []string
	customDNSAddress string
	dnsLabels        []string
	interfaceName    string
	wireguardPort    uint16
	mtu              uint16
	networkMonitor   bool
	dnsRouteInterval time.Duration
	lazyConnEnabled  bool

	// Security settings
	rosenpassEnabled    bool
	rosenpassPermissive bool
	preSharedKey        string

	// Feature flags
	autoConnectDisabled               bool
	serverSSHAllowed                  bool
	enableSSHRoot                     bool
	enableSSHSFTP                     bool
	enableSSHLocalPortForwarding      bool
	enableSSHRemotePortForwarding     bool
	disableSSHAuth                    bool
	sshJWTCacheTTL                    int
	disableClientRoutes               bool
	disableServerRoutes               bool
	disableDNS                        bool
	disableFirewall                   bool
	blockLANAccess                    bool
	blockInbound                      bool
	disableIPv6                       bool
	disableNotifications              bool
	extraIFaceBlackList               []string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "netbird-config-gen",
	Short: "Generate NetBird client configuration files without starting the service",
	Long: `This tool generates the default.json configuration file for NetBird client
without requiring the daemon to be running. This is useful for automated provisioning
and managed environments where configuration needs to be created before the service starts.

Examples:
  # Generate default config with custom management URL and block inbound
  sudo netbird-config-gen --management-url https://netbird.selfhosted.com --block-inbound

  # Generate with multiple options
  sudo netbird-config-gen -c /var/lib/netbird/default.json -m https://my.netbird.io --block-inbound --disable-client-routes

  # Update existing config
  sudo netbird-config-gen --config /var/lib/netbird/default.json --block-lan-access`,
	RunE: generateConfig,
}

func init() {
	// Determine default paths based on OS
	defaultStateDir := "/var/lib/netbird"
	if runtime.GOOS == "windows" {
		defaultStateDir = filepath.Join(os.Getenv("PROGRAMDATA"), "Netbird")
	} else if runtime.GOOS == "freebsd" {
		defaultStateDir = "/var/db/netbird"
	}

	// Allow override via environment variable
	if envStateDir := os.Getenv("NB_STATE_DIR"); envStateDir != "" {
		defaultStateDir = envStateDir
	}

	defaultConfigPath := filepath.Join(defaultStateDir, "default.json")

	// Core flags
	rootCmd.Flags().StringVarP(&configPath, "config", "c", defaultConfigPath, "Path to the config file to generate")
	rootCmd.Flags().StringVar(&stateDir, "state-dir", defaultStateDir, "State directory for NetBird")

	// Management settings
	rootCmd.Flags().StringVarP(&managementURL, "management-url", "m", "", "Management Service URL [http|https]://[host]:[port]")
	rootCmd.Flags().StringVar(&adminURL, "admin-url", "", "Admin Panel URL [http|https]://[host]:[port]")

	// Network settings
	rootCmd.Flags().StringSliceVar(&natExternalIPs, "external-ip-map", nil, "External IP mappings (format: external[/internal])")
	rootCmd.Flags().StringVar(&customDNSAddress, "dns-resolver-address", "", "Custom DNS resolver address (ip:port)")
	rootCmd.Flags().StringSliceVar(&dnsLabels, "extra-dns-labels", nil, "Extra DNS labels")
	rootCmd.Flags().StringVar(&interfaceName, "interface-name", "", "WireGuard interface name")
	rootCmd.Flags().Uint16Var(&wireguardPort, "wireguard-port", 0, "WireGuard listening port")
	rootCmd.Flags().Uint16Var(&mtu, "mtu", 0, "MTU for WireGuard interface")
	rootCmd.Flags().BoolVar(&networkMonitor, "network-monitor", false, "Enable network monitoring")
	rootCmd.Flags().DurationVar(&dnsRouteInterval, "dns-router-interval", 0, "DNS route update interval")
	rootCmd.Flags().BoolVar(&lazyConnEnabled, "enable-lazy-connection", false, "Enable lazy connection")

	// Security settings
	rootCmd.Flags().BoolVar(&rosenpassEnabled, "enable-rosenpass", false, "Enable Rosenpass post-quantum security")
	rootCmd.Flags().BoolVar(&rosenpassPermissive, "rosenpass-permissive", false, "Enable Rosenpass permissive mode")
	rootCmd.Flags().StringVarP(&preSharedKey, "preshared-key", "p", "", "WireGuard PreSharedKey")

	// Feature flags - booleans need special handling
	rootCmd.Flags().BoolVar(&autoConnectDisabled, "disable-auto-connect", false, "Disable auto-connect on startup")
	rootCmd.Flags().BoolVar(&serverSSHAllowed, "allow-server-ssh", false, "Allow SSH server")
	rootCmd.Flags().BoolVar(&enableSSHRoot, "enable-ssh-root", false, "Enable SSH root login")
	rootCmd.Flags().BoolVar(&enableSSHSFTP, "enable-ssh-sftp", false, "Enable SSH SFTP")
	rootCmd.Flags().BoolVar(&enableSSHLocalPortForwarding, "enable-ssh-local-port-forward", false, "Enable SSH local port forwarding")
	rootCmd.Flags().BoolVar(&enableSSHRemotePortForwarding, "enable-ssh-remote-port-forward", false, "Enable SSH remote port forwarding")
	rootCmd.Flags().BoolVar(&disableSSHAuth, "disable-ssh-auth", false, "Disable SSH authentication")
	rootCmd.Flags().IntVar(&sshJWTCacheTTL, "ssh-jwt-cache-ttl", 0, "SSH JWT cache TTL in seconds")
	rootCmd.Flags().BoolVar(&disableClientRoutes, "disable-client-routes", false, "Disable client routes")
	rootCmd.Flags().BoolVar(&disableServerRoutes, "disable-server-routes", false, "Disable server routes")
	rootCmd.Flags().BoolVar(&disableDNS, "disable-dns", false, "Disable DNS configuration")
	rootCmd.Flags().BoolVar(&disableFirewall, "disable-firewall", false, "Disable firewall configuration")
	rootCmd.Flags().BoolVar(&blockLANAccess, "block-lan-access", false, "Block LAN access")
	rootCmd.Flags().BoolVar(&blockInbound, "block-inbound", false, "Block inbound connections")
	rootCmd.Flags().BoolVar(&disableIPv6, "disable-ipv6", false, "Disable IPv6 overlay")
	rootCmd.Flags().BoolVar(&disableNotifications, "disable-notifications", false, "Disable notifications")
	rootCmd.Flags().StringSliceVar(&extraIFaceBlackList, "extra-iface-blacklist", nil, "Extra interfaces to blacklist")
}

func generateConfig(cmd *cobra.Command, args []string) error {
	// Set up state directory if needed
	if stateDir != "" {
		profilemanager.DefaultConfigPathDir = stateDir
		profilemanager.DefaultConfigPath = filepath.Join(stateDir, "default.json")
	}

	// Ensure the directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0750); err != nil {
		return fmt.Errorf("failed to create config directory %s: %w", configDir, err)
	}

	// Build ConfigInput from flags
	input := profilemanager.ConfigInput{
		ConfigPath:          configPath,
		ManagementURL:       managementURL,
		AdminURL:            adminURL,
		NATExternalIPs:      natExternalIPs,
		ExtraIFaceBlackList: extraIFaceBlackList,
	}

	// Handle custom DNS address
	if cmd.Flags().Changed("dns-resolver-address") {
		if customDNSAddress != "" {
			input.CustomDNSAddress = []byte(customDNSAddress)
		} else {
			input.CustomDNSAddress = []byte("empty")
		}
	}

	// Handle DNS labels
	if cmd.Flags().Changed("extra-dns-labels") {
		labels, err := domain.ValidateDomains(dnsLabels)
		if err != nil {
			return fmt.Errorf("invalid DNS labels: %w", err)
		}
		input.DNSLabels = labels
	}

	// Handle optional settings - only set if changed
	if cmd.Flags().Changed("interface-name") && interfaceName != "" {
		input.InterfaceName = &interfaceName
	}

	if cmd.Flags().Changed("wireguard-port") && wireguardPort != 0 {
		wp := int(wireguardPort)
		input.WireguardPort = &wp
	}

	if cmd.Flags().Changed("mtu") && mtu != 0 {
		input.MTU = &mtu
	}

	if cmd.Flags().Changed("network-monitor") {
		input.NetworkMonitor = &networkMonitor
	}

	if cmd.Flags().Changed("dns-router-interval") && dnsRouteInterval != 0 {
		input.DNSRouteInterval = &dnsRouteInterval
	}

	if cmd.Flags().Changed("enable-lazy-connection") {
		input.LazyConnectionEnabled = &lazyConnEnabled
	}

	if cmd.Flags().Changed("enable-rosenpass") {
		input.RosenpassEnabled = &rosenpassEnabled
	}

	if cmd.Flags().Changed("rosenpass-permissive") {
		input.RosenpassPermissive = &rosenpassPermissive
	}

	if cmd.Flags().Changed("preshared-key") && preSharedKey != "" {
		input.PreSharedKey = &preSharedKey
	}

	if cmd.Flags().Changed("disable-auto-connect") {
		input.DisableAutoConnect = &autoConnectDisabled
	}

	if cmd.Flags().Changed("allow-server-ssh") {
		input.ServerSSHAllowed = &serverSSHAllowed
	}

	if cmd.Flags().Changed("enable-ssh-root") {
		input.EnableSSHRoot = &enableSSHRoot
	}

	if cmd.Flags().Changed("enable-ssh-sftp") {
		input.EnableSSHSFTP = &enableSSHSFTP
	}

	if cmd.Flags().Changed("enable-ssh-local-port-forward") {
		input.EnableSSHLocalPortForwarding = &enableSSHLocalPortForwarding
	}

	if cmd.Flags().Changed("enable-ssh-remote-port-forward") {
		input.EnableSSHRemotePortForwarding = &enableSSHRemotePortForwarding
	}

	if cmd.Flags().Changed("disable-ssh-auth") {
		input.DisableSSHAuth = &disableSSHAuth
	}

	if cmd.Flags().Changed("ssh-jwt-cache-ttl") && sshJWTCacheTTL != 0 {
		input.SSHJWTCacheTTL = &sshJWTCacheTTL
	}

	if cmd.Flags().Changed("disable-client-routes") {
		input.DisableClientRoutes = &disableClientRoutes
	}

	if cmd.Flags().Changed("disable-server-routes") {
		input.DisableServerRoutes = &disableServerRoutes
	}

	if cmd.Flags().Changed("disable-dns") {
		input.DisableDNS = &disableDNS
	}

	if cmd.Flags().Changed("disable-firewall") {
		input.DisableFirewall = &disableFirewall
	}

	if cmd.Flags().Changed("block-lan-access") {
		input.BlockLANAccess = &blockLANAccess
	}

	if cmd.Flags().Changed("block-inbound") {
		input.BlockInbound = &blockInbound
	}

	if cmd.Flags().Changed("disable-ipv6") {
		input.DisableIPv6 = &disableIPv6
	}

	if cmd.Flags().Changed("disable-notifications") {
		input.DisableNotifications = &disableNotifications
	}

	// Create or update the config
	var config *profilemanager.Config
	var err error

	configExists := false
	if _, err := os.Stat(configPath); err == nil {
		configExists = true
	}

	if configExists {
		// Update existing config
		config, err = profilemanager.UpdateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to update config: %w", err)
		}
		fmt.Printf("Updated existing config at %s\n", configPath)
	} else {
		// Create new config
		config, err = profilemanager.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to create config: %w", err)
		}
		fmt.Printf("Created new config at %s\n", configPath)
	}

	// Set proper permissions (0600 - owner read/write only)
	if err := util.EnforcePermission(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to set permissions on %s: %v\n", configPath, err)
	}

	// Print summary
	fmt.Printf("\nConfiguration Summary:\n")
	fmt.Printf("  Management URL: %s\n", config.ManagementURL)
	fmt.Printf("  Admin URL: %s\n", config.AdminURL)
	fmt.Printf("  WireGuard Interface: %s\n", config.WgIface)
	fmt.Printf("  WireGuard Port: %d\n", config.WgPort)
	fmt.Printf("  MTU: %d\n", config.MTU)
	fmt.Printf("  Block Inbound: %t\n", config.BlockInbound)
	fmt.Printf("  Block LAN Access: %t\n", config.BlockLANAccess)
	fmt.Printf("  Disable Client Routes: %t\n", config.DisableClientRoutes)
	fmt.Printf("  Disable DNS: %t\n", config.DisableDNS)
	fmt.Printf("  Disable Firewall: %t\n", config.DisableFirewall)

	return nil
}
