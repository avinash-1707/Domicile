package wire

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestHelloRoundTrip(t *testing.T) {
	for _, want := range []Hello{
		{Kind: HelloAuth, Name: "home", Secret: strings.Repeat("t", 255)},
		{Kind: HelloJoin, Name: "office", Secret: "one-time"},
	} {
		var buf bytes.Buffer
		if err := WriteHello(&buf, want); err != nil {
			t.Fatal(err)
		}
		got, err := ReadHello(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	}
}

func TestHelloReplyRoundTrip(t *testing.T) {
	for _, want := range []HelloReply{
		{Status: HelloOK, Observed: "203.0.113.7"},
		{Status: HelloOK, Credential: "new-credential", Observed: "2001:db8::7"},
		{Status: HelloOK},
		{Status: HelloUnauthorized},
	} {
		var buf bytes.Buffer
		if err := WriteHelloReply(&buf, want); err != nil {
			t.Fatal(err)
		}
		got, err := ReadHelloReply(&buf)
		if err != nil || got != want {
			t.Fatalf("got %+v, %v; want %+v", got, err, want)
		}
	}
}

func TestOpenRoundTrip(t *testing.T) {
	for _, want := range []Open{
		{Host: "reddit.com", Port: 443},
		{Host: "2001:db8::1", Port: 1},
		{Host: strings.Repeat("a", 255), Port: 65535},
	} {
		var buf bytes.Buffer
		if err := WriteOpen(&buf, want); err != nil {
			t.Fatal(err)
		}
		got, err := ReadOpen(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
		if buf.Len() != 0 {
			t.Fatalf("%d trailing bytes after frame", buf.Len())
		}
	}
}

func TestOpenReplyRoundTrip(t *testing.T) {
	for _, s := range []OpenStatus{OpenOK, OpenDNSFail, OpenDenied, OpenRefused, OpenTimeout, OpenUnreachable} {
		var buf bytes.Buffer
		if err := WriteOpenReply(&buf, s); err != nil {
			t.Fatal(err)
		}
		err := ReadOpenReply(&buf)
		if s == OpenOK {
			if err != nil {
				t.Fatalf("ok reply returned %v", err)
			}
			continue
		}
		var oe *OpenError
		if !errors.As(err, &oe) || oe.Status != s {
			t.Fatalf("status %v: got error %v", s, err)
		}
	}
}

func TestWriteRejectsInvalid(t *testing.T) {
	tests := []struct {
		name  string
		write func(io.Writer) error
	}{
		{"empty host", func(w io.Writer) error { return WriteOpen(w, Open{Host: "", Port: 443}) }},
		{"host too long", func(w io.Writer) error { return WriteOpen(w, Open{Host: strings.Repeat("a", 256), Port: 443}) }},
		{"port zero", func(w io.Writer) error { return WriteOpen(w, Open{Host: "a", Port: 0}) }},
		{"empty name", func(w io.Writer) error { return WriteHello(w, Hello{Kind: HelloAuth, Name: "", Secret: "t"}) }},
		{"empty secret", func(w io.Writer) error { return WriteHello(w, Hello{Kind: HelloAuth, Name: "home", Secret: ""}) }},
		{"unknown kind", func(w io.Writer) error { return WriteHello(w, Hello{Kind: 9, Name: "home", Secret: "t"}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.write(&buf); err == nil {
				t.Fatal("expected error")
			}
			if buf.Len() != 0 {
				t.Fatal("invalid frame was partly written")
			}
		})
	}
}

func TestReadRejectsMalformed(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		read    func(io.Reader) error
		wantErr error
	}{
		{"open wrong version", []byte{9, 1, 'a', 0, 80}, readOpen, ErrVersion},
		{"open truncated host", []byte{Version, 5, 'a', 'b'}, readOpen, io.ErrUnexpectedEOF},
		{"open missing port", []byte{Version, 1, 'a', 0}, readOpen, io.ErrUnexpectedEOF},
		{"open empty host", []byte{Version, 0, 0, 80}, readOpen, nil},
		{"open port zero", []byte{Version, 1, 'a', 0, 0}, readOpen, nil},
		{"open empty input", nil, readOpen, io.EOF},
		{"hello wrong version", []byte{9, 1, 1, 'a', 1, 'b'}, readHello, ErrVersion},
		{"hello unknown kind", []byte{Version, 7, 1, 'a', 1, 'b'}, readHello, nil},
		{"hello truncated secret", []byte{Version, 1, 1, 'a', 3, 'b'}, readHello, io.ErrUnexpectedEOF},
		{"reply empty", nil, ReadOpenReply, io.EOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.read(bytes.NewReader(tt.input))
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func readOpen(r io.Reader) error  { _, err := ReadOpen(r); return err }
func readHello(r io.Reader) error { _, err := ReadHello(r); return err }
