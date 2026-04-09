package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"

	pb "github.com/Ryo-del/test-grpc/gen"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
)

type db struct {
	*sql.DB
}
type server struct {
	pb.UnimplementedUserServiceServer
	db *db
}

func main() {
	connect, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=password dbname=postgres sslmode=disable")
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer connect.Close()

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()

	pb.RegisterUserServiceServer(s, &server{db: &db{connect}})

	log.Printf("server listening at %v", lis.Addr())

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
func (s *server) UploadLog(stream pb.UserService_UploadLogServer) error {
	batchSize := 100
	buffer := make([]*pb.LogEntry, 0, batchSize)

	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		buffer = append(buffer, res)

	}

	if len(buffer) == 0 {
		return stream.SendAndClose(&pb.UploadSummary{
			RecordCount: 0,
			Status:      "success",
		})
	}
	query := "INSERT INTO logs (device_id, message, level) VALUES "
	args := []interface{}{}
	for i, entry := range buffer {
		idx := i * 3
		query += fmt.Sprintf("($%d, $%d, $%d), ", idx+1, idx+2, idx+3)
		args = append(args, entry.DeviceId, entry.Message, entry.Level)
	}
	query = query[:len(query)-2]
	_, err := s.db.Exec(query, args...)
	if err != nil {
		return err
	}
	return stream.SendAndClose(&pb.UploadSummary{
		RecordCount: int32(len(buffer)),
		Status:      "success",
	})

}
