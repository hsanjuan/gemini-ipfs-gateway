package main

import (
	"context"
	"time"

	ds "github.com/ipfs/go-datastore"
	ipns "github.com/ipfs/go-ipns"
	libp2p "github.com/libp2p/go-libp2p"
	connmgr "github.com/libp2p/go-libp2p-connmgr"
	crypto "github.com/libp2p/go-libp2p-core/crypto"
	host "github.com/libp2p/go-libp2p-core/host"
	routing "github.com/libp2p/go-libp2p-core/routing"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	dualdht "github.com/libp2p/go-libp2p-kad-dht/dual"
	noise "github.com/libp2p/go-libp2p-noise"
	libp2pquic "github.com/libp2p/go-libp2p-quic-transport"
	record "github.com/libp2p/go-libp2p-record"
	libp2ptls "github.com/libp2p/go-libp2p-tls"
	ma "github.com/multiformats/go-multiaddr"
)

var libp2pOptionsExtra = []libp2p.Option{
	//libp2p.NATPortMap(),
	libp2p.ConnectionManager(connmgr.NewConnManager(50, 100, 10*time.Second)),
	//libp2p.EnableAutoRelay(),
	//libp2p.EnableNATService(),
	libp2p.Security(noise.ID, noise.New),
	libp2p.Security(libp2ptls.ID, libp2ptls.New),
	libp2p.Transport(libp2pquic.NewTransport),
	libp2p.DefaultTransports,
}

func setupLibp2p(
	ctx context.Context,
	hostKey crypto.PrivKey,
	listenAddrs []ma.Multiaddr,
	ds ds.Batching,
	opts ...libp2p.Option,
) (host.Host, *dualdht.DHT, error) {

	var ddht *dualdht.DHT
	dhtMode := dht.ModeClient
	if len(listenAddrs) > 0 {
		dhtMode = dht.ModeAuto
	}
	var err error

	finalOpts := []libp2p.Option{
		libp2p.Identity(hostKey),
		libp2p.ListenAddrs(listenAddrs...),
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			ddht, err = newDHT(ctx, h, ds, dhtMode)
			return ddht, err
		}),
	}
	finalOpts = append(finalOpts, opts...)

	h, err := libp2p.New(
		ctx,
		finalOpts...,
	)
	if err != nil {
		return nil, nil, err
	}

	return h, ddht, nil
}

func newDHT(ctx context.Context, h host.Host, ds ds.Batching, mode dht.ModeOpt) (*dualdht.DHT, error) {
	dhtOpts := []dualdht.Option{
		dualdht.DHTOption(dht.NamespacedValidator("pk", record.PublicKeyValidator{})),
		dualdht.DHTOption(dht.NamespacedValidator("ipns", ipns.Validator{KeyBook: h.Peerstore()})),
		dualdht.DHTOption(dht.Concurrency(10)),
		dualdht.DHTOption(dht.Mode(mode)),
	}
	if ds != nil {
		dhtOpts = append(dhtOpts, dualdht.DHTOption(dht.Datastore(ds)))
	}

	return dualdht.New(ctx, h, dhtOpts...)

}
