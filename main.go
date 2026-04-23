package main

import (
	"fmt"
	"net/http"
)

func Test(w http.ResponseWriter, r *http.Request) {
	fmt.Println("request from:", r.RemoteAddr)
	fmt.Fprintf(w, "hello world")
}

func main() {
	http.HandleFunc("/", Test)
	http.ListenAndServe(":8080", nil)
}
