package main

import (
	"fmt"
	"log/slog"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("got req", "header", r.Header)
		fmt.Fprintf(w, "Hello world!")
	})

	http.ListenAndServe(":8080", nil)
}
