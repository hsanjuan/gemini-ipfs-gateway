package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	xdg "github.com/adrg/xdg"
	ds "github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	badger "github.com/ipfs/go-ds-badger"
	log "github.com/ipfs/go-log/v2"
	crypto "github.com/libp2p/go-libp2p-core/crypto"
	cli "github.com/urfave/cli/v2"
	zap "go.uber.org/zap"
)

const appName = "gemini-ipfs-gateway"

func init() {
	log.SetLogLevel("gemini", "info")
}

type key ecdsa.PrivateKey

func (k *key) MarshalJSON() ([]byte, error) {
	b, err := x509.MarshalECPrivateKey((*ecdsa.PrivateKey)(k))
	if err != nil {
		return nil, err
	}
	return json.Marshal(b)
}

func (k *key) UnmarshalJSON(b []byte) error {
	var b2 []byte
	err := json.Unmarshal(b, &b2)
	if err != nil {
		return err
	}
	parsed, err := x509.ParseECPrivateKey(b2)
	if err != nil {
		return err
	}
	*k = key(*parsed)
	return nil
}

type appConfig struct {
	PrivateKey *key `json:"private_key"`
}

func main() {
	dataFolder, err := xdg.DataFile(appName)
	if err != nil {
		logger.Error(err)
		logger.Error("error determining default data folder. Defaulting to \"data\".")
		dataFolder = "data"
	}
	configFolder, err := xdg.ConfigFile(appName)
	if err != nil {
		logger.Error(err)
		logger.Error("error determining default config folder. Defaulting to \"config\".")
		configFolder = "config"
	}

	app := &cli.App{
		Name:            appName,
		Usage:           "Access IPFS content using the Gemini Protocol",
		HideHelpCommand: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:      "data",
				Usage:     "Storage folder",
				Value:     dataFolder,
				TakesFile: true,
				EnvVars:   []string{"GIGW_DATA"},
			},
			&cli.StringFlag{
				Name:      "config",
				Usage:     "Config folder",
				Value:     configFolder,
				TakesFile: true,
				EnvVars:   []string{"GIGW_CONFIG"},
			},
			&cli.StringSliceFlag{
				Name:    "listen",
				Usage:   "Listen on `ip:port`",
				Value:   cli.NewStringSlice("0.0.0.0:2021", "[::]:2022"),
				EnvVars: []string{"GIGW_LISTEN"},
			},
			&cli.StringSliceFlag{
				Name:    "p2p-listen",
				Usage:   "Enable libp2p server mode and listen on `ip:port`",
				Value:   nil,
				EnvVars: []string{"GIGW_P2P_LISTEN"},
			},
			&cli.BoolFlag{
				Name:    "tls",
				Usage:   "Enable TLS with self-signed certificate",
				Value:   false,
				EnvVars: []string{"GIGW_TLS"},
			},
			&cli.BoolFlag{
				Name:    "inmem",
				Usage:   "Run fully in-memory, using a random identity",
				Value:   false,
				EnvVars: []string{"GIGW_INMEM"},
			},
			&cli.BoolFlag{
				Name:  "v",
				Usage: "Verbose (-vvv for full verbosity)",
				Value: false,
			},
			&cli.BoolFlag{
				Name:   "vv",
				Value:  false,
				Hidden: true,
			},
			&cli.BoolFlag{
				Name:   "vvv",
				Value:  false,
				Hidden: true,
			},
		},
		CustomAppHelpTemplate: `Usage: gemini-ipfs-gateway [FLAGS]

Flags:

   {{range $index, $option := .VisibleFlags}}{{if $index}}
   {{end}}{{$option}}{{end}}
`,

		Action: run,
	}

	err = app.Run(os.Args)
	if err != nil {
		logger.Error(err)
		fmt.Println("gemini-ipfs-gateway terminated abnormally")
	}

}

func run(cctx *cli.Context) error {
	ctx, cancel := context.WithCancel(cctx.Context)
	defer cancel()

	handleSigTerm(cancel)

	setupVerbosity(cctx.Bool("v"), cctx.Bool("vv"), cctx.Bool("vvv"))

	inMem := cctx.Bool("inmem")
	err := setupConfigFolder(inMem, cctx.String("config"))
	if err != nil {
		return err
	}

	id, err := setupIdentity(inMem, cctx.String("config"))
	if err != nil {
		return err
	}

	crt, err := setupCertificate(
		cctx.Bool("tls"),
		inMem,
		id,
		cctx.String("config"),
		cctx.StringSlice("listen"),
	)
	if err != nil {
		return err
	}

	ds, err := setupStorage(inMem, cctx.String("data"))
	if err != nil {
		return err
	}

	cfg := Config{
		Identity:    id,
		Certificate: crt,

		GatewayListenAddresses: cctx.StringSlice("listen"),
		PeerListenAddresses:    cctx.StringSlice("p2p-listen"),

		TLSListeners: cctx.Bool("tls"),

		ReadTimeout:    0,
		WriteTimeout:   5 * time.Second,
		GatewayTimeout: 30 * time.Second,
	}

	gw, err := NewGateway(ctx, ds, cfg)
	if err != nil {
		return err
	}

	err = gw.ListenAndServe()
	if err != nil {
		return err
	}
	return nil

}

func handleSigTerm(cancel context.CancelFunc) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(
		signalChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGHUP,
	)
	go func() {
		for {
			s := <-signalChan
			logger.Infof("Aborting on signal: %s", s)
			cancel()
		}
	}()
}

func setupStorage(inMem bool, storagePath string) (ds.Batching, error) {
	if inMem {
		logger.Info("In-memory datastore enabled")
		return dssync.MutexWrap(ds.NewMapDatastore()), nil
	}

	return badger.NewDatastore(storagePath, &badger.DefaultOptions)
}

func setupConfigFolder(inMem bool, configPath string) error {
	if inMem {
		return nil
	}

	_, err := os.Stat(configPath)

	// Check config folder exists.
	if os.IsNotExist(err) {
		err = os.MkdirAll(configPath, 0700)
		if err != nil {
			return fmt.Errorf("error creating config folder: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("error checking config folder: %w", err)
	}
	return nil
}

func setupIdentity(inMem bool, configPath string) (*ecdsa.PrivateKey, error) {
	if inMem {
		logger.Info("Using a new random in-memory private key")
		return ecdsa.GenerateKey(crypto.ECDSACurve, rand.Reader)
	}

	// Open config file.
	path := filepath.Join(configPath, "config.json")
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		pk, err := ecdsa.GenerateKey(crypto.ECDSACurve, rand.Reader)
		if err != nil {
			return nil, err
		}
		cfg := &appConfig{
			PrivateKey: (*key)(pk),
		}

		w, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return nil, fmt.Errorf("error generating configuration file: %w", err)
		}
		defer w.Close()

		enc := json.NewEncoder(w)
		err = enc.Encode(cfg)
		if err != nil {
			return nil, fmt.Errorf("error writing configuration file (%s): %w", path, err)
		}
		logger.Infof("Stored new configuration and private key at %s", path)
		return pk, nil
	} else if err != nil {
		return nil, fmt.Errorf("error opening configuration: %w", err)
	}

	defer f.Close()
	dec := json.NewDecoder(f)
	var cfg appConfig
	err = dec.Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("error parsing configuration (%s): %w", path, err)
	}
	logger.Infof("Private key loaded from %s", path)
	return (*ecdsa.PrivateKey)(cfg.PrivateKey), nil
}

func setupCertificate(tlsEnabled, inMem bool, pk *ecdsa.PrivateKey, configPath string, addrs []string) (tls.Certificate, error) {
	if !tlsEnabled {
		return tls.Certificate{}, nil
	}

	if inMem {
		// generate on the fly
		crt, err := makeCertificate(pk, addrs)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("error generating x509 certificate: %w", err)
		}
		return crt, nil
	}

	certPath := filepath.Join(configPath, "cert.pem")
	keyPath := filepath.Join(configPath, "key.pem")

	_, errCert := os.Stat(certPath)
	if errCert != nil && !os.IsNotExist(errCert) {
		return tls.Certificate{}, fmt.Errorf("error trying to read %s: %w", certPath, errCert)
	}
	certExist := errCert == nil

	_, errKey := os.Stat(keyPath)
	if errKey != nil && !os.IsNotExist(errKey) {
		return tls.Certificate{}, fmt.Errorf("error trying to read %s: %w", keyPath, errKey)
	}
	keyExist := errKey == nil

	if keyExist && certExist {
		logger.Infof("Loading custom gateway TLS certificate and key from %s and %s", certPath, keyPath)
		return tls.LoadX509KeyPair(certPath, keyPath)
	}

	// Return using identity key
	if certExist {
		// Attempt to load cached certificate
		pemCert, err := ioutil.ReadFile(certPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("error reading certificate: %w", err)
		}

		asnKey, err := x509.MarshalECPrivateKey(pk)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("marshaling private key: %w", err)
		}
		pemKey := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: asnKey,
		})
		logger.Infof("Loading cached TLS certificate from %s", certPath)
		return tls.X509KeyPair(pemCert, pemKey)
	}

	// Key not on disk. Cert not on disk.
	// Create cert. Save it to disk.
	crt, err := makeCertificate(pk, addrs)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error generating x509 certificate: %w", err)
	}
	blk := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Certificate[0],
	}

	w, err := os.OpenFile(certPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error creating certificate file: %w", err)
	}
	defer w.Close()
	err = pem.Encode(w, blk)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error writing certificate file: %w", err)
	}
	logger.Infof("Generated TLS certificate and saved it to %s", certPath)
	return crt, nil
}

func setupVerbosity(v, vv, vvv bool) {
	// Default
	log.SetLogLevel("*", "error")
	log.SetLogLevel("gemini", "info")

	switch {
	case vvv:
		log.SetLogLevel("*", "debug")
	case vv:
		log.SetLogLevel("swarm2", "info")
		fallthrough
	case v:
		logger.SugaredLogger = *(logger.SugaredLogger.
			Desugar().
			WithOptions(zap.AddCaller()).
			Sugar())
		log.SetLogLevel("gemini", "debug")
	}
}
