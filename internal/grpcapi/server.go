package grpcapi

import (
	"context"
	"log/slog"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/grpcapi/pb"
	"github.com/powersvx/powersvx/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type DNSService struct {
	pb.UnimplementedDNSServer
	srv *server.Server
}

func (d *DNSService) Lookup(ctx context.Context, req *pb.LookupRequest) (*pb.LookupResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	qtype := dns.TypeA
	if t := strings.ToUpper(req.GetType()); t != "" {
		if v, ok := dns.StringToType[t]; ok {
			qtype = v
		}
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(req.GetName()), qtype)
	msg.RecursionDesired = true
	resp, _, err := d.srv.ServeDNSMsg(msg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup: %v", err)
	}
	out := &pb.LookupResponse{
		Rcode: dns.RcodeToString[resp.Rcode],
		Ad:    resp.AuthenticatedData,
	}
	for _, rr := range resp.Answer {
		out.Answers = append(out.Answers, rr.String())
	}
	return out, nil
}

type Server struct {
	gs  *grpc.Server
	ln  net.Listener
	log *slog.Logger
}

func Start(bind string, dnsSrv *server.Server, log *slog.Logger, apiToken string) (*Server, error) {
	if bind == "" {
		return nil, nil
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, err
	}
	opts := []grpc.ServerOption{}
	if apiToken != "" {
		opts = append(opts, grpc.UnaryInterceptor(tokenInterceptor(apiToken)))
	}
	gs := grpc.NewServer(opts...)
	pb.RegisterDNSServer(gs, &DNSService{srv: dnsSrv})
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(gs, hs)
	s := &Server{gs: gs, ln: ln, log: log}
	go func() {
		log.Info("gRPC API starting", "addr", bind, "auth", apiToken != "")
		if err := gs.Serve(ln); err != nil {
			log.Error("grpc serve", "err", err)
		}
	}()
	return s, nil
}

func tokenInterceptor(want string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if strings.HasPrefix(info.FullMethod, "/grpc.health.") {
			return handler(ctx, req)
		}
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		vals := md.Get("authorization")
		got := ""
		if len(vals) > 0 {
			got = vals[0]
		}
		got = strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
		got = strings.TrimSpace(strings.TrimPrefix(got, "bearer "))
		if got == "" {
			if t := md.Get("token"); len(t) > 0 {
				got = t[0]
			}
		}
		if got != want {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}
		return handler(ctx, req)
	}
}

func (s *Server) Stop() {
	if s == nil || s.gs == nil {
		return
	}
	s.gs.GracefulStop()
}
