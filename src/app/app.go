package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"sinkhole/src/config"
	"sinkhole/src/server"
	"sinkhole/src/server/blocklists"
	"sinkhole/src/server/ca"
	"sinkhole/src/server/cache"
	"sinkhole/src/server/content"
	"sinkhole/src/server/filter"
	"sinkhole/src/server/proxy"
	"sinkhole/src/server/stats"
	"sinkhole/src/server/upstream"
	"sinkhole/src/store"
	"sinkhole/src/web"
)

// App is the top-level application coordinator managing all subsystems.
type App struct {
	Version string
	DataDir string
	Log     *slog.Logger

	mu         sync.RWMutex
	cfg        config.Config
	st         *store.Store
	engine     *filter.Engine
	cache      *cache.Cache
	boot       *upstream.Bootstrap
	ups        *upstream.Group
	stats      *stats.Stats
	rec        *server.Recorder
	dnsSrv     *server.Server
	lists      *blocklists.Manager
	caInstance *ca.CA
	cosmetic   *content.CosmeticEngine
	proxySrv   *proxy.Proxy
	hub        *web.Hub
	webSrv     *web.Server
	startedAt  time.Time

	ctx    context.Context
	cancel context.CancelFunc
}

// New creates and initializes an App instance.
func New(dataDir string, version string, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if dataDir == "" {
		dataDir = config.DefaultDataDir()
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w", dataDir, err)
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}

	cfg, isNew, err := st.LoadConfig()
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("load config: %w", err)
	}
	if isNew {
		_ = st.SeedDefaults()
	}

	ctx, cancel := context.WithCancel(context.Background())

	a := &App{
		Version:   version,
		DataDir:   dataDir,
		Log:       logger,
		cfg:       cfg,
		st:        st,
		engine:    filter.NewEngine(),
		stats:     stats.New(),
		startedAt: time.Now(),
		ctx:       ctx,
		cancel:    cancel,
	}

	// In-memory cache
	a.cache = cache.New(cfg.CacheSize, cfg.CacheMinTTL, cfg.CacheMaxTTL)

	// Bootstrap & Upstreams
	a.boot = upstream.NewBootstrap(cfg.Bootstrap)
	ups, err := upstream.NewGroup(cfg, a.boot)
	if err != nil {
		cancel()
		_ = st.Close()
		return nil, fmt.Errorf("init upstream resolvers: %w", err)
	}
	a.ups = ups

	// Query recorder & stats pipeline
	a.rec = server.NewRecorder(st, a.stats, logger, cfg.LogQueries)

	// DNS Server
	opts := server.OptionsFromConfig(cfg)
	a.dnsSrv = server.New(logger, a.engine, a.cache, a.ups, a.rec, opts)

	// Blocklist manager
	mgr, err := blocklists.New(st, a.engine, dataDir, a.boot, logger)
	if err != nil {
		cancel()
		_ = st.Close()
		return nil, fmt.Errorf("init blocklist manager: %w", err)
	}
	a.lists = mgr

	// Root Certificate Authority (for HTTPS inspection)
	caInst, err := ca.LoadOrGenerate(filepath.Join(dataDir, "certs"))
	if err != nil {
		logger.Warn("init Root CA failed", "err", err)
	}
	a.caInstance = caInst

	// Cosmetic & Scriptlet Engine
	a.cosmetic = content.NewCosmeticEngine()

	// HTTPS & YouTube Inspection Proxy
	a.proxySrv = proxy.New(cfg.ProxyListen, a.caInstance, a.engine, a.cosmetic, logger)
	a.proxySrv.SetYouTubeShield(content.YouTubeShield{
		Enabled:       cfg.YouTubeShield.Enabled,
		BlockPrerolls: cfg.YouTubeShield.BlockPrerolls,
		BlockBanners:  cfg.YouTubeShield.BlockBanners,
		BlockShorts:   cfg.YouTubeShield.BlockShorts,
	})

	// Web SSE hub
	a.hub = web.NewHub(a.stats)
	a.rec.SetPublisher(a.hub)

	// Web Dashboard server
	a.webSrv = web.New(web.Deps{
		Log:         logger,
		Store:       st,
		Engine:      a.engine,
		Stats:       a.stats,
		Lists:       a.lists,
		Cache:       a.cache,
		Boot:        a.boot,
		Hub:         a.hub,
		Version:     version,
		DataDir:     dataDir,
		Started:     a.startedAt,
		CA:          a.caInstance,
		Cosmetic:    a.cosmetic,
		Proxy:       a.proxySrv,
		Config:      a.GetConfig,
		ApplyConfig: a.ApplyConfig,
		DNSBound:    a.dnsSrv.Bound,
		ReloadRules: a.ReloadCustomRules,
		BgCtx:       ctx,
	})

	return a, nil
}

// Start boots all background workers, loads initial lists and rules, and starts listeners.
func (a *App) Start() error {
	// 1. Reload custom rules from store
	if err := a.ReloadCustomRules(); err != nil {
		a.Log.Warn("load custom rules", "err", err)
	}

	// 2. Restore historical counters for today from query log
	todayStart := stats.DayStart(time.Now()).UnixMilli()
	dayAgo := time.Now().Add(-24 * time.Hour).UnixMilli()
	if agg, err := a.st.AggregateSince(todayStart, dayAgo); err == nil {
		a.stats.Restore(agg)
	}

	// 3. Rebuild in-memory filter from cached list files
	if err := a.lists.Rebuild(); err != nil {
		a.Log.Warn("initial blocklist rebuild", "err", err)
	}

	// 4. Start Query Recorder & Hub background loops
	go a.rec.Run(a.ctx)
	go a.hub.Run(a.ctx)

	// Forward Proxy inspection events to Web SSE Hub
	if a.proxySrv != nil {
		go func() {
			for {
				select {
				case <-a.ctx.Done():
					return
				case ev := <-a.proxySrv.EventChannel():
					a.hub.PublishEvent(ev)
				}
			}
		}()
	}

	// 5. Start DNS Server on configured addresses (0.0.0.0:53 UDP+TCP)
	if err := a.dnsSrv.Start(a.cfg.DNSListen); err != nil {
		return fmt.Errorf("start DNS server: %w", err)
	}

	// 6. Start HTTPS & YouTube Filtering Proxy
	if a.cfg.HTTPSFiltering && a.proxySrv != nil {
		if err := a.proxySrv.Start(); err != nil {
			a.Log.Warn("start HTTPS inspection proxy failed", "err", err)
		}
	}

	// 7. Start Web Dashboard HTTP server
	if a.cfg.WebListen != "" {
		if err := a.webSrv.Start(a.cfg.WebListen); err != nil {
			a.Log.Error("start web dashboard failed", "addr", a.cfg.WebListen, "err", err)
		}
	}

	// 7. Start blocklist background scheduler (refresh & periodic checks)
	go a.lists.RunScheduler(a.ctx, func() int {
		return a.GetConfig().UpdateIntervalHours
	})

	// 8. If no rules loaded yet, download defaults in background
	if a.engine.ListRuleCount() == 0 {
		go func() {
			ctx, cancel := context.WithTimeout(a.ctx, 5*time.Minute)
			defer cancel()
			_ = a.lists.UpdateAll(ctx, false, 0)
		}()
	}

	a.Log.Info("Sinkhole initialized successfully", "data_dir", a.DataDir, "rules", a.engine.ListRuleCount())
	return nil
}

// Stop gracefully terminates all subsystems.
func (a *App) Stop() {
	a.Log.Info("Stopping sinkhole services...")
	a.cancel()

	// 1. Stop DNS listeners
	if a.dnsSrv != nil {
		a.dnsSrv.Stop()
	}

	// 2. Stop HTTPS Proxy
	if a.proxySrv != nil {
		a.proxySrv.Stop()
	}

	// 3. Stop Web server
	if a.webSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		a.webSrv.Stop(ctx)
		cancel()
	}

	// 3. Flush recorder queues to SQLite
	if a.rec != nil {
		a.rec.Wait()
	}

	// 4. Close database
	if a.st != nil {
		_ = a.st.Close()
	}

	a.Log.Info("Sinkhole stopped cleanly")
}

// GetConfig returns the active configuration.
func (a *App) GetConfig() config.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

// ApplyConfig validates and updates runtime settings without downtime when possible.
func (a *App) ApplyConfig(newCfg config.Config) (restartRequired bool, err error) {
	newCfg.Normalize()
	if err := newCfg.Validate(); err != nil {
		return false, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.cfg

	// Save to DB
	if err := a.st.SaveConfig(newCfg); err != nil {
		return false, fmt.Errorf("persist config: %w", err)
	}

	// Hot reload DNS options
	opts := server.OptionsFromConfig(newCfg)
	a.dnsSrv.SetOptions(opts)

	// Hot reload Cache
	a.cache.Configure(newCfg.CacheSize, newCfg.CacheMinTTL, newCfg.CacheMaxTTL)

	// Hot reload Upstreams
	a.boot.SetServers(newCfg.Bootstrap)
	if err := a.ups.Configure(newCfg, a.boot); err != nil {
		a.Log.Error("hot reload upstreams failed", "err", err)
	}

	// Query logging setting
	a.rec.SetPersist(newCfg.LogQueries)

	// Hot reload YouTube Shield parameters
	if a.proxySrv != nil {
		a.proxySrv.SetYouTubeShield(content.YouTubeShield{
			Enabled:       newCfg.YouTubeShield.Enabled,
			BlockPrerolls: newCfg.YouTubeShield.BlockPrerolls,
			BlockBanners:  newCfg.YouTubeShield.BlockBanners,
			BlockShorts:   newCfg.YouTubeShield.BlockShorts,
		})
	}

	a.cfg = newCfg

	// Check if listen addresses changed (requires service restart to re-bind)
	if !slicesEqual(old.DNSListen, newCfg.DNSListen) || old.WebListen != newCfg.WebListen {
		restartRequired = true
	}

	return restartRequired, nil
}

// ReloadCustomRules loads custom block/allow rules from store into memory.
func (a *App) ReloadCustomRules() error {
	rules, err := a.st.ListRules()
	if err != nil {
		return err
	}
	a.engine.SetCustomRules(rules)
	return nil
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
