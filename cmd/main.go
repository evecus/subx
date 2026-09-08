package main

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"substore/internal/config"
	"substore/internal/downloader"
	"substore/internal/scheduler"
	"substore/internal/server"
	"substore/internal/store"
)

// migrateLegacyDB renames a pre-rename substore.db (plus its -shm/-wal
// companions) to subx.db, so existing deployments keep their data across
// the upgrade. It only runs when subx.db does not exist yet.
func migrateLegacyDB(dataDir string) {
	newDB := filepath.Join(dataDir, "subx.db")
	if _, err := os.Stat(newDB); err == nil {
		return
	}
	oldDB := filepath.Join(dataDir, "substore.db")
	if _, err := os.Stat(oldDB); err != nil {
		return
	}
	moved := 0
	for _, suffix := range []string{"", "-shm", "-wal"} {
		if err := os.Rename(oldDB+suffix, newDB+suffix); err == nil {
			moved++
		}
	}
	if moved > 0 {
		log.Printf("migrated legacy database: %s -> %s (moved %d file(s))", oldDB, newDB, moved)
	}
}

func main() {
	cfg := config.Load()
	migrateLegacyDB(cfg.DataDir)

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()

	srv := server.New(cfg, st)
	if err := srv.BootstrapAdmin(); err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	}

	runner := scheduler.NewRunner(st, downloader.SettingsFetcher(st.GetSettings))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner.Start(ctx)

	if err := srv.Run(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
