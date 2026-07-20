package grpcapi_test

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/grpcapi"
	"github.com/powersvx/powersvx/internal/grpcapi/pb"
	"github.com/powersvx/powersvx/internal/resolver"
	"github.com/powersvx/powersvx/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestGRPCHealthAndLookup(t *testing.T) {
	cfg := config.Default()
	cfg.Resolver.Mode = "forward"
	cfg.Resolver.Forwarders = []string{"1.1.1.1:53"}
	res := resolver.New(cfg.Resolver)
	l1 := cache.NewL1(1000)
	tier := cache.NewTier(l1, nil, time.Minute, time.Minute)
	dnsSrv := server.New(cfg, server.Deps{Res: res, Cache: tier}, slog.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	gs, err := grpcapi.Start(addr, dnsSrv, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer gs.Stop()
	time.Sleep(50 * time.Millisecond)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h := healthpb.NewHealthClient(conn)
	hr, err := h.Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil || hr.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health: %v %#v", err, hr)
	}

	cli := pb.NewDNSClient(conn)
	lr, err := cli.Lookup(ctx, &pb.LookupRequest{Name: "example.com", Type: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if lr.Rcode == "" {
		t.Fatal("empty rcode")
	}
}
