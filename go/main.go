// Superslice callback receiver for Go 1.21+. Standard library only.
// Run: SUPERSLICE_WEBHOOK_SECRET=whsec_... go run .
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const toleranceS = 300

// Verify reports whether header (the Superslice-Signature value) signs rawBody with secret
// and its timestamp is within 5 minutes of now. Verify the raw bytes, before parsing JSON.
func Verify(secret, header string, rawBody []byte, now time.Time) bool {
	var t int64 = -1
	var signatures []string
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		if key == "t" {
			if n, err := strconv.ParseInt(value, 10, 64); err == nil && n >= 0 {
				t = n
			}
		} else if key == "v1" && value != "" {
			signatures = append(signatures, value)
		}
	}
	if t < 0 || len(signatures) == 0 {
		return false
	}
	if d := now.Unix() - t; d > toleranceS || d < -toleranceS {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(t, 10) + "."))
	mac.Write(rawBody)
	expected := []byte(hex.EncodeToString(mac.Sum(nil)))
	for _, s := range signatures {
		if hmac.Equal([]byte(s), expected) {
			return true
		}
	}
	return false
}

type event struct {
	Event   string `json:"event"`
	EventID string `json:"event_id"`
	Data    struct {
		ID     string `json:"id"`
		Result *struct {
			PrintTimeS float64 `json:"print_time_s"`
			FilamentG  float64 `json:"filament_g"`
		} `json:"result"`
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	} `json:"data"`
}

func handle(e event) {
	switch {
	case e.Event == "slice.completed" && e.Data.Result != nil:
		log.Printf("slice %s: %.0f s, %.2f g", e.Data.ID, e.Data.Result.PrintTimeS, e.Data.Result.FilamentG)
	case e.Event == "slice.failed" && e.Data.Error != nil:
		log.Printf("slice %s failed: %s", e.Data.ID, e.Data.Error.Code)
	}
}

func main() {
	secret := os.Getenv("SUPERSLICE_WEBHOOK_SECRET")
	if secret == "" {
		log.Fatal("set SUPERSLICE_WEBHOOK_SECRET")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	// Superslice may deliver an event more than once. Store event_id in your database in production.
	var mu sync.Mutex
	seen := map[string]bool{}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rawBody, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		if err != nil || r.Method != http.MethodPost || !Verify(secret, r.Header.Get("Superslice-Signature"), rawBody, time.Now()) {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}
		var e event
		if err := json.Unmarshal(rawBody, &e); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		mu.Lock()
		duplicate := seen[e.EventID]
		seen[e.EventID] = true
		mu.Unlock()
		if duplicate {
			io.WriteString(w, "duplicate")
			return
		}
		// Answer quickly; do slow work (emails, orders) after responding or in a queue.
		io.WriteString(w, "ok")
		go handle(e)
	})
	log.Printf("listening on %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
