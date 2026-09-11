package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	addr := fmt.Sprintf(":%d", {{ .Values.port }})
	log.Printf("{{ .Values.serviceName }} listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
