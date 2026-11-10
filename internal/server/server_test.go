package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServerShutdownDrainsActiveRequest(t *testing.T) {
	s := newTestServer()
	entered := make(chan struct{})
	release := make(chan struct{})
	s.Handle("GET /slow", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(listener) }()
	s.SetReady(true)

	client := &http.Client{Timeout: 3 * time.Second}
	requestDone := make(chan error, 1)
	go func() {
		response, err := client.Get("http://" + listener.Addr().String() + "/slow")
		if err != nil {
			requestDone <- err
			return
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode != http.StatusNoContent {
			requestDone <- errors.New("wrong response status")
			return
		}
		requestDone <- nil
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("request never entered the handler")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- s.Shutdown(ctx) }()

	deadline := time.After(2 * time.Second)
	for s.Ready() {
		select {
		case <-deadline:
			close(release)
			t.Fatal("readiness did not become false during shutdown")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case err := <-shutdownDone:
		close(release)
		t.Fatalf("shutdown returned before the request finished: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	close(release)
	if err := <-requestDone; err != nil {
		t.Fatalf("active request failed: %v", err)
	}
	if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
	if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serve result = %v, want http.ErrServerClosed", err)
	}
}
