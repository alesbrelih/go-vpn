package handler

import (
	"alesbrelih/go-vpn/internal/certificates"
	"archive/zip"
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"gopkg.in/yaml.v3"
)

func Handler(targetnetwork string) http.Handler {
	handler := http.NewServeMux()

	handler.HandleFunc("GET /certificate/{email}", func(w http.ResponseWriter, r *http.Request) {
		email := r.PathValue("email")

		cert, key, err := certificates.Generate(email, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			slog.Error("could not generate cert for", "email", email, "err", err)

			return
		}

		buff := new(bytes.Buffer)
		zipWriter := zip.NewWriter(buff)

		config := certificates.Config{
			Network: targetnetwork,
		}

		filename := "key.pem"
		config.Key = filename

		archiveKey, err := zipWriter.Create(filename)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			slog.Error("could not create file in archive", "filename", filename, "err", err)

			return
		}
		_, err = archiveKey.Write(key)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			slog.Error("could not write file contents", "filename", filename, "err", err)

			return
		}

		filename = "cert.pem"
		config.Cert = filename

		certKey, err := zipWriter.Create(filename)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			slog.Error("could not create file in archive", "filename", filename, "err", err)

			return
		}
		_, err = certKey.Write(cert)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			slog.Error("could not write file contents", "filename", filename, "err", err)

			return
		}

		filename = fmt.Sprintf("%s-vpn.config", email)
		configKey, err := zipWriter.Create(filename)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			slog.Error("could not create file in archive", "filename", filename, "err", err)

			return
		}

		marshalledCfg, err := yaml.Marshal(config)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			slog.Error("could not marshal vpn config", "err", err)

			return
		}

		_, err = configKey.Write(marshalledCfg)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			slog.Error("could not write file contents", "filename", filename, "err", err)

			return
		}

		err = zipWriter.Close()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			slog.Error("could not write zip", "err", err)

			return
		}

		http.ServeContent(w, r, "config.zip", time.Now(), bytes.NewReader(buff.Bytes()))
	})

	return handler
}
