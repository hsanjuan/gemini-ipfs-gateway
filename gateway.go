package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	gemini "git.sr.ht/~adnano/go-gemini"
	"github.com/gabriel-vasile/mimetype"
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
	zap "go.uber.org/zap"
)

var logger = logging.Logger("gemini")

type Config struct {
	ListenIP    string
	ListenPort  string
	ReadTimeout time.Duration
	//ReadHeaderTimeout time.Duration
	WriteTimeout time.Duration
	//IdleTimeout       time.Duration
	//MaxHeaderBytes    int

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

	server   *gemini.Server
	listener net.Listener
	tlsKey   *ecdsa.PrivateKey
	tls      *tls.Config
}

func NewGateway(ctx context.Context, store ds.Batching, cfg Config) (*Gateway, error) {
	ctx, cancel := context.WithCancel(ctx)

	ecdsaPriv, err := ecdsa.GenerateKey(crypto.ECDSACurve, rand.Reader)
	if err != nil {
		return nil, err
	}

	priv, _, err := crypto.ECDSAKeyPairFromKey(ecdsaPriv)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	netIP := net.ParseIP(cfg.ListenIP)

	tlsCfg, err := generateTLSconfig(ecdsaPriv, netIP)
	if err != nil {
		return nil, err
	}

	h, dht, err := setupLibp2p(
		ctx,
		priv,
		nil,
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
		tlsKey: ecdsaPriv,
		tls:    tlsCfg,
	}

	// Shutdown gateway on context cancellation.
	go func() {
		<-gw.ctx.Done()
		if gw.listener != nil {
			gw.listener.Close()
		}
	}()

	mux := &gemini.ServeMux{}
	mux.HandleFunc("/", gw.handle)
	s.Handle("*", &loggingResponder{r: mux})

	return gw, nil

}

func (gw *Gateway) ListenAndServe() error {
	listenAddr := fmt.Sprintf("%s:%s", gw.cfg.ListenIP, gw.cfg.ListenPort)
	listener, err := tls.Listen("tcp", listenAddr, gw.tls)
	//listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}

	gw.listener = listener

	logger.Infof("Listening on %s", listenAddr)

	err = gw.server.Serve(listener)
	select {
	case <-gw.ctx.Done():
		return nil
	default:
		return err
	}
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
		err = fmt.Errorf("path is not a unixfs node (%s): %w", err)
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
