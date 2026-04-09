package main

import (
	"context"
	"log"

	pb "github.com/Ryo-del/test-grpc/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := pb.NewUserServiceClient(conn)

	stream, err := c.UploadLog(context.Background())
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	for i := 0; i < 10; i++ {
		err := stream.Send(&pb.LogEntry{
			DeviceId: int32(i),
			Message:  "test",
			Level:    "info",
		})
		if err != nil {
			log.Fatalf("could not greet: %v", err)
		}
	}
	
	res, err := stream.CloseAndRecv()
	if err != nil {
		log.Fatalf("close error: %v", err)
	}
	log.Printf("records: %d, status: %s", res.RecordCount, res.Status)
	log.Println("Отправлено 10 записей")
}
