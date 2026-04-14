package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net"

	pb "github.com/Ryo-del/test-grpc/gen"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DB struct {
	*sql.DB
}

type Server struct {
	pb.UnimplementedTODOServer
	DB *DB
}

func main() {

	conn, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=password dbname=postgres sslmode=disable")
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		return
	}
	defer conn.Close()

	slog.Info("Starting server")
	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		slog.Error("Failed to listen", "error", err)
		return
	}
	s := grpc.NewServer()
	pb.RegisterTODOServer(s, &Server{DB: &DB{conn}})

	if err := s.Serve(lis); err != nil {
		slog.Error("Failed to serve", "error", err)
		return
	}
}

func (s *Server) CreateItem(ctx context.Context, req *pb.CreateItemRequest) (*pb.CreateItemResponse, error) {
	if req.Title == "" {
		return nil, status.Error(codes.InvalidArgument, "title is required")
	}
	_, err := s.DB.ExecContext(ctx, "INSERT INTO items (title) VALUES ($1)", req.Title)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create item")
	} else {
		slog.Info("Item created successfully")
	}
	return &pb.CreateItemResponse{}, nil
}
