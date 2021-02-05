package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	gemini "git.sr.ht/~adnano/go-gemini"
	mimetype "github.com/gabriel-vasile/mimetype"
	ipfslite "github.com/hsanjuan/ipfs-lite"
	ds "github.com/ipfs/go-datastore"
	ipld "github.com/ipfs/go-ipld-format"
	logging "github.com/ipfs/go-log/v2"
	path "github.com/ipfs/go-path"
	resolver "github.com/ipfs/go-path/resolver"
	unixfs "github.com/ipfs/go-unixfs"
	unixfsio "github.com/ipfs/go-unixfs/io"
	crypto "github.com/libp2p/go-libp2p-core/crypto"
	host "github.com/libp2p/go-libp2p-core/host"
	routing "github.com/libp2p/go-libp2p-core/routing"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	zap "go.uber.org/zap"
)

var logger = logging.Logger("gemini")

type Config struct {
	Identity    *ecdsa.PrivateKey
	Certificate tls.Certificate

	GatewayListenAddresses []string
	PeerListenAddresses    []string

	TLSListeners bool

	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	GatewayTimeout time.Duration
}

type Gateway struct {
	ctx    context.Context
	cancel context.CancelFunc

	store ds.Batching
	cfg   Config
	key   crypto.PrivKey

	lite *ipfslite.Peer
	dht  routing.Routing
	h    host.Host

	server    *gemini.Server
	listeners []net.Listener
}

func NewGateway(ctx context.Context, store ds.Batching, cfg Config) (*Gateway, error) {
	ctx, cancel := context.WithCancel(ctx)

	// Key for libp2p host.
	priv, _, err := crypto.ECDSAKeyPairFromKey(cfg.Identity)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if cfg.TLSListeners {
		fingerprint := sha1.Sum(cfg.Certificate.Certificate[0])
		logger.Infof("Using TLS certificate with fingerprint %X", fingerprint)
	}

	var maddrs []ma.Multiaddr
	for _, pAddr := range cfg.PeerListenAddresses {
		tcpAddr, err := net.ResolveTCPAddr("tcp", pAddr)
		if err != nil {
			return nil, fmt.Errorf("error parsing peer listen address %s: %w", tcpAddr, err)
		}
		maddr, err := manet.FromNetAddr(tcpAddr)
		if err != nil {
			return nil, fmt.Errorf("error converting to multiaddress: %s: %w", tcpAddr, err)
		}
		maddrs = append(maddrs, maddr)
	}

	h, dht, err := setupLibp2p(
		ctx,
		priv,
		maddrs,
		store,
		libp2pOptionsExtra...,
	)

	if err != nil {
		logger.Error(err)
		return nil, err
	}

	logger.Info("ipfs-lite node starting")
	logger.Infof("IPFS Peer ID: %s", h.ID())

	lite, err := ipfslite.New(
		ctx, store, h, dht,
		&ipfslite.Config{
			ReprovideInterval: -1,
		},
	)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	lite.Bootstrap(ipfslite.DefaultBootstrapPeers())

	s := &gemini.Server{
		ReadTimeout: cfg.ReadTimeout,
		//ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout: cfg.WriteTimeout,
		//IdleTimeout:       cfg.IdleTimeout,
		//Handler:           logMux,
		//MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ErrorLog: zap.NewStdLog(logger.SugaredLogger.Desugar()),
	}

	gw := &Gateway{
		ctx:    ctx,
		cancel: cancel,
		store:  store,
		cfg:    cfg,
		key:    priv,
		lite:   lite,
		dht:    dht,
		h:      h,
		server: s,
	}

	// Shutdown gateway on context cancellation.
	go func() {
		<-gw.ctx.Done()
		for _, l := range gw.listeners {
			l.Close()
		}
	}()

	mux := &gemini.ServeMux{}
	mux.HandleFunc("/", gw.handle)
	s.Handle("*", &loggingResponder{r: mux})

	return gw, nil

}

func (gw *Gateway) ListenAndServe() error {
	var wg sync.WaitGroup

	tlsCfg := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: false,
		//InsecureSkipVerify:       true, // This is not insecure here. We will verify the cert chain ourselves.
		//ClientAuth:               tls.NoClientCert,
		Certificates: []tls.Certificate{gw.cfg.Certificate},

		//
		// VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
		// 	panic("tls config not specialized for peer")
		// },
		// Probably not needed
		NextProtos:             []string{"gemini"},
		SessionTicketsDisabled: true,
	}

	for _, addr := range gw.cfg.GatewayListenAddresses {
		var l net.Listener
		var err error
		if gw.cfg.TLSListeners {
			l, err = tls.Listen("tcp", addr, tlsCfg)
		} else {
			l, err = net.Listen("tcp", addr)
		}
		if err != nil {
			return fmt.Errorf("error listening on %s: %w", addr, err)
		}
		gw.listeners = append(gw.listeners, l)

		wg.Add(1)
		go func(addr string, l net.Listener) {
			defer wg.Done()
			logger.Infof("Gemini gateway listening on %s", addr)
			err = gw.server.Serve(l)
			select {
			case <-gw.ctx.Done():
			default:
				if err != nil {
					logger.Error(err)
				}
			}
		}(addr, l)
	}
	wg.Wait()
	return nil
}

func (gw *Gateway) handle(w *gemini.ResponseWriter, r *gemini.Request) {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/ipfs/"):
		gw.handleIPFS(w, r)
	case strings.HasPrefix(path, "/ipns/"):
		gw.handleIPNS(w, r)
	default:
		gw.handleRoot(w, r)
	}
}

func (gw *Gateway) handleIPFS(w *gemini.ResponseWriter, r *gemini.Request) {
	ctx, cancel := context.WithTimeout(gw.ctx, gw.cfg.GatewayTimeout)
	defer cancel()

	// path starts with /ipfs/
	p, err := path.ParsePath(r.URL.Path)
	if err != nil {
		err = fmt.Errorf("error parsing path: %w", err)
		logger.Debug(err)
		w.Header(gemini.StatusBadRequest, err.Error())
		return
	}
	segments := p.Segments()
	lastSegment := segments[len(segments)-1]

	session := gw.lite.Session(ctx)
	res := resolver.Resolver{
		DAG:         session,
		ResolveOnce: resolver.ResolveSingle,
	}

	logger.Info(p)
	n, err := res.ResolvePath(gw.ctx, p)
	if err != nil {
		err = fmt.Errorf("error resolving path: %w", err)
		logger.Debug(err)
		w.Header(gemini.StatusNotFound, err.Error())
		return
	}

	// unixfs?
	fsnode, err := unixfs.ExtractFSNode(n)
	if err != nil {
		err = fmt.Errorf("path is not a unixfs node (%s): %w", p, err)
		logger.Debug(err)
		w.Header(gemini.StatusPermanentFailure, err.Error())
		return
	}

	if fsnode.IsDir() {
		if !strings.HasSuffix(r.URL.Path, "/") {
			w.Header(gemini.StatusRedirect, r.URL.Path+"/")
			w.Flush()
			return
		}

		dir, err := unixfsio.NewDirectoryFromNode(gw.lite, n)
		if err != nil {
			err = fmt.Errorf("error reading unixfs: %w", err)
			logger.Debug(err)
			w.Header(gemini.StatusTemporaryFailure, err.Error())
			return
		}
		index, err := dir.Find(ctx, "index.gmi")
		if err == nil {
			rdr, err := gw.lite.GetFile(ctx, index.Cid())
			if err != nil {
				err = fmt.Errorf("error getting index.gmi: %w", err)
				logger.Debug(err)
				w.Header(gemini.StatusTemporaryFailure, err.Error())
				return
			}
			w.Header(gemini.StatusSuccess, "text/gemini")
			io.Copy(w, rdr) // no way of signaling errors anymore.
			return
		}

		// directory listing
		w.Header(gemini.StatusSuccess, "text/gemini")
		fmt.Fprintf(w, "# %s\n\n", lastSegment)
		fmt.Fprintf(w, "This is an IPFS directory. Here are its contents:\n\n")

		dir.ForEachLink(ctx, func(l *ipld.Link) error {
			fmt.Fprintf(w, "=> %s %s\n", l.Name, l.Name)
			return nil
		})
		return
	}

	// Not a directory.
	c := n.Cid()
	unixReader, err := gw.lite.GetFile(ctx, c)
	if err != nil {
		err = fmt.Errorf("error getting file: %w", err)
		logger.Debug(err)
		w.Header(gemini.StatusTemporaryFailure, err.Error())
		return
	}
	defer unixReader.Close()

	t, err := mimetype.DetectReader(unixReader)
	if err != nil {
		err = fmt.Errorf("error detecting mime type: %w", err)
		logger.Debug(err)
		w.Header(gemini.StatusTemporaryFailure, err.Error())
		return
	}
	_, err = unixReader.Seek(0, io.SeekStart)
	if err != nil {
		err = fmt.Errorf("error seeking back: %w", err)
		logger.Debug(err)
		w.Header(gemini.StatusPermanentFailure, err.Error())
		return
	}
	ct := t.String()
	logger.Debug(ct)

	// If the file name ends in .gmi, then set text/gemini
	// when it is a text file. Otherwise text/plain.
	if t.Extension() == ".txt" {
		if strings.HasSuffix(lastSegment, ".gmi") {
			ct = strings.Replace(ct, "plain", "gemini", 1)
		}
	}

	w.Header(gemini.StatusSuccess, ct)
	io.Copy(w, unixReader) // no way of signaling errors anymore.
}

func (gw *Gateway) handleIPNS(w *gemini.ResponseWriter, r *gemini.Request) {
	w.Header(gemini.StatusTemporaryFailure, "Not implemented yet!")
}

func (gw *Gateway) handleRoot(w *gemini.ResponseWriter, r *gemini.Request) {
	addr := r.URL.Host

	fmt.Fprintf(w, `# Gemini-IPFS Gateway

Welcome to IPFS!

This gateway allows to access IPFS resources using the Gemini protocol.

It works similar to the HTTP gateway. You can provide IPFS and IPNS paths as follows:

* gemini://%s/ipfs/<path>
* gemini://%s/ipns/<path>

Some useful links:

=> gemini://%s/ipfs/QmQjeN9YzTve5xoLTtVRMS6yDeK5orZ7TEcMHuCTp3K2Tc/ An example Gemini site hosted on IPFS.
=> gemini://%s/ipfs/QmV9YFgF7zfF25ykfsm5SqeUEdyF1MkLKwxNNaJg1fx98L/ Hackweek slides about this project.
=> gemini://gemini.circumlunar.space Gemini Homepage

`, addr, addr, addr, addr)
}

type loggingResponder struct {
	r gemini.Responder
}

func (lh *loggingResponder) Respond(w *gemini.ResponseWriter, r *gemini.Request) {
	logger.Infof("%s", r.URL)
	lh.r.Respond(w, r)
}
