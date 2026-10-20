package exec

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"testing"
)

// TestAbstractSocket sends to a server on a socket of Linux's abstract
// namespace, which has no file.
func TestAbstractSocket(t *testing.T) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	name := "@vegtam-test-" + hex.EncodeToString(b)
	hosts := socketServer(t, name)
	_, trace, err := New(Options{MaxBody: 1, Transport: Transport{Socket: name}}).Do(t.Context(), prepared(http.MethodGet, lit("http://abstract/x"), nil), testSecrets)
	if err != nil {
		t.Fatal(err)
	}
	if h := trace.Hops[0]; h.ResolvedBy != "--abstract-unix-socket" || len(*hosts) != 1 || (*hosts)[0] != "abstract" {
		t.Errorf("hop %+v; the server saw %q", h, *hosts)
	}
}
