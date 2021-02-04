package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	ds "github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	log "github.com/ipfs/go-log/v2"
	"go.uber.org/zap"
)

func init() {
	log.SetLogLevel("*", "error")
	log.SetLogLevel("gemini", "info")
	logger.SugaredLogger = *(logger.SugaredLogger.
		Desugar().
		WithOptions(zap.AddCaller()).
		Sugar())
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-c
		logger.Infof("Aborting on signal: %s", s)
		cancel()
	}()

	ds := dssync.MutexWrap(ds.NewMapDatastore())

	cfg := Config{
		ListenIP:    "0.0.0.0",
		ListenPort:  "9088",
		ReadTimeout: 0,
		//ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout: 5 * time.Second,
		//IdleTimeout:       30 * time.Second,
		//MaxHeaderBytes: 512,

		GatewayTimeout: 30 * time.Second,
	}

	gw, err := NewGateway(ctx, ds, cfg)
	if err != nil {
		logger.Error(err)
		return
	}

	err = gw.ListenAndServe()
	if err != nil {
		logger.Error(err)
		return
	}
}
