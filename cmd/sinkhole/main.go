package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"sinkhole/src/app"
	"sinkhole/src/config"
	"sinkhole/src/server/filter"
	"sinkhole/src/service"
	"sinkhole/src/store"
)

const Version = "1.0.0"

func printUsage() {
	fmt.Printf(`Sinkhole - Windows 11 Network Ad & Tracker Sinkhole (v%s)

Usage:
  sinkhole [command] [options]

Commands:
  run                   Run interactively in foreground console (default)
  service install       Register Sinkhole as an automatic Windows Service
  service uninstall     Stop and remove the Windows Service
  service start         Start the installed Windows Service
  service stop          Stop the running Windows Service
  service status        Query the current status of the Windows Service
  check <domain>        Query active rules to test if a domain is blocked
  version               Display version info

Options:
  --data <dir>          Path to persistent storage directory (default: %%ProgramData%%\Sinkhole)
  --debug               Enable debug logging

Examples:
  sinkhole run
  sinkhole service install
  sinkhole service start
  sinkhole check doubleclick.net
`, Version)
}

func main() {
	// If invoked directly by the Windows Service Control Manager, dispatch immediately.
	if service.IsService() {
		dataDir := config.DefaultDataDir()
		if err := service.RunAsService(dataDir, Version); err != nil {
			slog.Error("Service failed", "err", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) < 2 {
		runInteractive(config.DefaultDataDir(), false)
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "help", "-h", "--help":
		printUsage()

	case "version", "-v", "--version":
		fmt.Printf("Sinkhole v%s (Windows 11 DNS Engine)\n", Version)

	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		dataDir := fs.String("data", config.DefaultDataDir(), "Path to data directory")
		debug := fs.Bool("debug", false, "Enable verbose debug logs")
		_ = fs.Parse(os.Args[2:])
		runInteractive(*dataDir, *debug)

	case "service":
		if len(os.Args) < 3 {
			fmt.Println("Error: missing service subcommand (install, uninstall, start, stop, status)")
			os.Exit(1)
		}
		handleService(os.Args[2], os.Args[3:])

	case "check":
		if len(os.Args) < 3 {
			fmt.Println("Usage: sinkhole check <domain>")
			os.Exit(1)
		}
		checkDomain(os.Args[2])

	default:
		// If unknown command, treat as domain check or show usage
		if _, ok := filter.NormalizeDomain(cmd, false); ok {
			checkDomain(cmd)
			return
		}
		printUsage()
		os.Exit(1)
	}
}

func runInteractive(dataDir string, debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	fmt.Printf("Starting Sinkhole v%s (Interactive Console Mode)...\n", Version)
	fmt.Printf("Data directory: %s\n", dataDir)

	application, err := app.New(dataDir, Version, logger)
	if err != nil {
		logger.Error("Failed to initialize sinkhole", "err", err)
		os.Exit(1)
	}

	if err := application.Start(); err != nil {
		logger.Error("Failed to start server", "err", err)
		os.Exit(1)
	}

	cfg := application.GetConfig()
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("✓ DNS Server active on: %v (UDP & TCP)\n", cfg.DNSListen)
	fmt.Printf("✓ Admin Dashboard:     http://%s\n", cfg.WebListen)
	fmt.Printf("✓ Press Ctrl+C to shut down cleanly.\n")
	fmt.Println("----------------------------------------------------------------")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nReceived shutdown signal. Stopping...")
	application.Stop()
	fmt.Println("Sinkhole exited.")
}

func handleService(subcmd string, args []string) {
	switch subcmd {
	case "install":
		fs := flag.NewFlagSet("install", flag.ExitOnError)
		dataDir := fs.String("data", config.DefaultDataDir(), "Data directory")
		_ = fs.Parse(args)

		exe, err := os.Executable()
		if err != nil {
			fmt.Printf("Error resolving executable path: %v\n", err)
			os.Exit(1)
		}
		if err := service.Install(exe, *dataDir); err != nil {
			fmt.Printf("Failed to install Windows service: %v\n(Ensure you run terminal as Administrator)\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Windows service '%s' successfully installed.\n", service.ServiceName)
		fmt.Printf("  Binary: %s\n", exe)
		fmt.Printf("  Run 'sinkhole service start' or start from services.msc\n")

	case "uninstall":
		if err := service.Uninstall(); err != nil {
			fmt.Printf("Failed to uninstall service: %v\n(Ensure you run terminal as Administrator)\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Windows service '%s' successfully removed.\n", service.ServiceName)

	case "start":
		if err := service.Start(); err != nil {
			fmt.Printf("Failed to start service: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Windows service '%s' started.\n", service.ServiceName)

	case "stop":
		if err := service.Stop(); err != nil {
			fmt.Printf("Failed to stop service: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Windows service '%s' stopped.\n", service.ServiceName)

	case "status":
		st, err := service.Status()
		if err != nil {
			fmt.Printf("Status check failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Service '%s': %s\n", service.ServiceName, st)

	default:
		fmt.Printf("Unknown service subcommand: %s\n", subcmd)
		os.Exit(1)
	}
}

func checkDomain(domain string) {
	dataDir := config.DefaultDataDir()
	st, err := store.Open(dataDir)
	if err != nil {
		fmt.Printf("Cannot access database in %s: %v\n", dataDir, err)
		return
	}
	defer st.Close()

	engine := filter.NewEngine()
	rules, err := st.ListRules()
	if err == nil {
		engine.SetCustomRules(rules)
	}

	// Rebuild from cached lists
	listsDir := filepath.Join(dataDir, "lists")
	b := filter.NewBuilder(100000)
	if bls, err := st.ListBlocklists(); err == nil {
		for _, bl := range bls {
			if !bl.Enabled {
				continue
			}
			f, err := os.Open(filepath.Join(listsDir, fmt.Sprintf("%d.txt", bl.ID)))
			if err != nil {
				continue
			}
			id := uint32(bl.ID)
			b.SetListName(id, bl.Name)
			_, _ = filter.Parse(f, func(r filter.Rule) { b.Add(id, r) })
			f.Close()
		}
	}
	engine.SetLists(b.Build())

	d, ok := filter.NormalizeDomain(domain, false)
	if !ok {
		fmt.Printf("Invalid domain: %s\n", domain)
		return
	}

	res := engine.Match(d)
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("Domain: %s\n", d)
	if res.Blocked {
		fmt.Printf("Result: BLOCKED (Sinkholed) ❌\n")
		fmt.Printf("Source: %s\n", res.ListName)
		fmt.Printf("Rule:   %s\n", res.Rule)
	} else {
		fmt.Printf("Result: PERMITTED (Allowed) ✅\n")
		if res.Reason != "" {
			fmt.Printf("Reason: %s\n", res.Reason)
		} else {
			fmt.Printf("Reason: Not in any active blocklist\n")
		}
	}
	fmt.Println("----------------------------------------------------------------")
}
