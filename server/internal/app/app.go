package app

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/Puena/password-keeper/proto"
	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/adapters"
	"github.com/Puena/password-keeper/server/internal/api/v1/services"
	"github.com/Puena/password-keeper/server/internal/database"
	repositories "github.com/Puena/password-keeper/server/internal/repostiories"
	"github.com/Puena/password-keeper/server/internal/usecases"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/selector"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip" // enable compressiong for grpc.
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type citus interface {
	Connect(ctx context.Context) (*pgxpool.Pool, error)
	UpMigration() error
}

func initLogger(config *config.Config) (*zap.Logger, error) {
	if config.Release {
		return zap.NewProduction()
	}
	return zap.NewDevelopment()
}

func initPostgres(config *config.Config, logger *zap.Logger) citus {
	db := database.Init(config, logger)
	return db
}

func initTLS(config *config.Config, logger *zap.Logger) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
	return cert, err
}

func initServer(cert tls.Certificate, db *pgxpool.Pool, config *config.Config, logger *zap.Logger) *grpc.Server {
	rs := repositories.New(db, config, logger)
	us := usecases.New(adapters.UsecaseRepoAdapter(rs), config, logger)
	ss := services.New(us, config, logger)

	gs := grpc.NewServer(
		grpc.Creds(credentials.NewServerTLSFromCert(&cert)),
		grpc.ChainUnaryInterceptor(
			selector.UnaryServerInterceptor(auth.UnaryServerInterceptor(ss.AuthFunc), selector.MatchFunc(ss.DoAuth)),
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(func(p any) (err error) {
				logger.Error("panic in grpc server", zap.Any("panic", p))
				return status.Errorf(codes.Internal, "panic triggered: %v", p)
			})),
		),
		grpc.ChainStreamInterceptor(
			selector.StreamServerInterceptor(auth.StreamServerInterceptor(ss.AuthFunc), selector.MatchFunc(ss.DoAuth)),
		),
	)

	pb.RegisterKeeperServer(gs, ss)
	if !config.Release {
		reflection.Register(gs)
	}
	return gs
}

type app struct {
	config   *config.Config
	logger   *zap.Logger
	database citus
}

func Init(config *config.Config) (*app, error) {
	logger, err := initLogger(config)
	if err != nil {
		return nil, err
	}

	db := initPostgres(config, logger)

	return &app{
		config:   config,
		logger:   logger,
		database: db,
	}, nil
}

func (a *app) Run() error {
	a.logger.Info("start running server")

	// Prepare database
	a.logger.Info("prepare database")
	err := a.database.UpMigration()
	if err != nil {
		a.logger.Error("failed while doing database migration", zap.Error(err))
		return err
	}

	databaseCtx := context.Background()

	a.logger.Info("connect to database")
	pgx, err := a.database.Connect(databaseCtx)
	if err != nil {
		a.logger.Error("failed while connecting to database", zap.Error(err))
		return err
	}
	defer pgx.Close()

	// Prepare grpc server
	listen, err := net.Listen("tcp", a.config.Address)
	if err != nil {
		a.logger.Error("failed while start listening tcp", zap.String("address", a.config.Address))
		return err
	}
	tlsCert, err := initTLS(a.config, a.logger)
	if err != nil {
		a.logger.Error("failed while loading tls certificate", zap.Error(err))
		return err
	}
	server := initServer(tlsCert, pgx, a.config, a.logger)

	// Preapare waiting signal
	sig := make(chan os.Signal, 1)
	wait := make(chan error)
	defer close(wait)

	// Start serving server
	go func() {
		a.logger.Info("server listening on", zap.String("address", listen.Addr().String()))
		err := server.Serve(listen)
		if err != nil {
			a.logger.Error("failed while start serving grpc server", zap.Error(err))
			wait <- err
		}
	}()

	// Start listing signal notification
	go func() {
		signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	}()

	// Handle incoming signal
	go func() {
		s := <-sig
		a.logger.Info("catch", zap.Any("signal", s))
		a.logger.Info("start graceful database stop")
		pgx.Close()
		a.logger.Info("start graceful server stop")
		server.GracefulStop()
		wait <- nil
	}()

	// Wait until done
	err = <-wait
	if err != nil {
		return err
	}

	a.logger.Info("server shutdown")
	return nil
}
