package main

import (
	"log"
	"net/http"
)

func HelloHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello, World!"))
}
func main() {
	http.HandleFunc("/", HelloHandler)
	http.ListenAndServe(":8080", nil)
	log.Println("Server started on :8080")
}
