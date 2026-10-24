//go:build windows

package service

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"sinkhole/src/app"
)

const (
	ServiceName = "SinkholeDNS"
	DisplayName = "Sinkhole DNS Ad & Tracker Filter"
	Description = "High-performance local DNS sinkhole server that blocks network ads, trackers, and telemetry on Windows 11."
)

// IsService reports whether the process is running as a Windows Service.
func IsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}

// sinkholeService implements svc.Handler.
type sinkholeService struct {
	dataDir string
	version string
}

func (s *sinkholeService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	// Open or create log file in ProgramData/Sinkhole/sinkhole.log
	logFile, err := os.OpenFile(filepath.Join(s.dataDir, "sinkhole.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	var logger *slog.Logger
	if err == nil {
		defer logFile.Close()
		logger = slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	logger.Info("Windows service starting", "version", s.version, "data_dir", s.dataDir)
	changes <- svc.Status{State: svc.StartPending}

	application, err := app.New(s.dataDir, s.version, logger)
	if err != nil {
		logger.Error("Failed to initialize sinkhole application", "err", err)
		return false, 1
	}

	if err := application.Start(); err != nil {
		logger.Error("Failed to start sinkhole server", "err", err)
		return false, 2
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	logger.Info("Windows service is now running")

	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			logger.Info("Received stop request from Service Control Manager")
			changes <- svc.Status{State: svc.StopPending}
			application.Stop()
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		default:
			logger.Warn("Unexpected service control request", "cmd", req.Cmd)
		}
	}

	return false, 0
}

// RunAsService starts the service control dispatcher.
func RunAsService(dataDir, version string) error {
	return svc.Run(ServiceName, &sinkholeService{dataDir: dataDir, version: version})
}

// Install registers the application as an auto-starting Windows service.
func Install(exePath, dataDir string) error {
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return err
		}
	}
	exePath, err := filepath.Abs(exePath)
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", ServiceName)
	}

	// Build service config: StartType Automatic, delayed start
	cfg := mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		DisplayName:      DisplayName,
		Description:      Description,
		DelayedAutoStart: true,
	}

	args := []string{"run"}
	if dataDir != "" {
		args = append(args, "--data", dataDir)
	}

	s, err = m.CreateService(ServiceName, exePath, cfg, args...)
	if err != nil {
		return fmt.Errorf("create service %s: %w", ServiceName, err)
	}
	defer s.Close()

	// Configure recovery action: restart on crash after 5 seconds
	recovery := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	_ = s.SetRecoveryActions(recovery, 86400)

	_ = eventlog.InstallAsEventCreate(ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)

	return nil
}

// Uninstall stops and deletes the service registration.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", ServiceName)
	}
	defer s.Close()

	// Try to stop if running
	_, _ = s.Control(svc.Stop)

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("delete service %s: %w", ServiceName, err)
	}

	_ = eventlog.Remove(ServiceName)
	return nil
}

// Start instructs the SCM to start the service.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", ServiceName, err)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("start service %s: %w", ServiceName, err)
	}
	return nil
}

// Stop instructs the SCM to stop the service.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", ServiceName, err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("stop service %s: %w", ServiceName, err)
	}

	timeout := time.Now().Add(10 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(timeout) {
			return fmt.Errorf("service stop timed out")
		}
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("query service status: %w", err)
		}
	}
	return nil
}

// Status returns human-readable service status.
func Status() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "Unknown", fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return "Not Installed", nil
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return "Error", err
	}
	switch st.State {
	case svc.Stopped:
		return "Stopped", nil
	case svc.StartPending:
		return "Start Pending", nil
	case svc.StopPending:
		return "Stop Pending", nil
	case svc.Running:
		return "Running", nil
	case svc.ContinuePending:
		return "Continue Pending", nil
	case svc.PausePending:
		return "Pause Pending", nil
	case svc.Paused:
		return "Paused", nil
	}
	return "Unknown", nil
}
