package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	port := ":8080"

	slog.SetLogLoggerLevel(slog.LevelWarn)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("got req", "header", r.Header)
		fmt.Fprintf(w, "Hello world!\n")
	})

	log.Printf("server started @%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		slog.Error("error starting server", "err", err)
		os.Exit(1)
	}
}
