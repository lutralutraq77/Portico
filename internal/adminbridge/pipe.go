package adminbridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"portico.local/portico/internal/wire"
)

const maxHeader = 4096

type Hello struct {
	Version                int
	Origin, StateDirectory string
}

type PipeRequest struct {
	Version, ID                int
	Method, Path, Origin, Site string
	Length                     int
	Close                      bool
}

type PipeResponse struct {
	Version, ID, Status, Length int
	Headers                     map[string]string
	Failed                      bool
}

func readHeader(in io.Reader, result any) error {
	var length [4]byte
	if _, err := io.ReadFull(in, length[:]); err != nil {
		return fmt.Errorf("%w: header prefix read", ErrRejected)
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > maxHeader {
		return fmt.Errorf("%w: header length", ErrRejected)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(in, data); err != nil || wire.Decode(data, result) != nil {
		return ErrRejected
	}
	return nil
}

func writePacket(out io.Writer, header any, body []byte) error {
	data, err := json.Marshal(header)
	if err != nil || len(data) == 0 || len(data) > maxHeader || len(body) > MaxResponse {
		return ErrRejected
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	for _, part := range [][]byte{prefix[:], data, body} {
		if _, err := io.Copy(out, bytes.NewReader(part)); err != nil {
			return ErrRejected
		}
	}
	return nil
}

// Serve owns pollable anonymous-pipe handles from one explicitly launched
// administration process. Closing either handle must interrupt its pending I/O.
// There is no socket listener, bearer session, private-key export or signing RPC.
// Requests are serialized, bounded and numbered; malformed framing ends the
// entire channel rather than trying to find a later valid-looking request.
func Serve(parent context.Context, client *Client, in io.ReadCloser, out io.WriteCloser, stateDirectory string) error {
	if parent == nil || parent.Err() != nil || client == nil || in == nil || out == nil {
		return ErrRejected
	}
	defer in.Close()
	defer out.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stopClient := context.AfterFunc(client.context, cancel)
	defer stopClient()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = in.Close(); _ = out.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	if writePacket(out, Hello{Version: 1, Origin: client.origin, StateDirectory: stateDirectory}, nil) != nil {
		return ErrRejected
	}
	for id := 1; id <= 4096; id++ {
		var header PipeRequest
		if err := readHeader(in, &header); err != nil {
			return err
		}
		if header.Version != 1 || header.ID != id || header.Length < 0 || header.Length > wire.MaxBody {
			return ErrRejected
		}
		if header.Close {
			if header.Method != "" || header.Path != "" || header.Origin != "" || header.Site != "" || header.Length != 0 || ctx.Err() != nil {
				return ErrRejected
			}
			return writePacket(out, PipeResponse{Version: 1, ID: id, Status: 204}, nil)
		}
		body := make([]byte, header.Length)
		if _, err := io.ReadFull(in, body); err != nil {
			return ErrRejected
		}
		response, err := client.Exchange(ctx, Request{Method: header.Method, Path: header.Path, Origin: header.Origin, Site: header.Site, Body: body})
		clear(body)
		result := PipeResponse{Version: 1, ID: id, Status: response.Status, Length: len(response.Body), Headers: response.Headers, Failed: err != nil}
		if err != nil {
			response = Response{}
			result.Status, result.Length, result.Headers = 0, 0, nil
		}
		e := writePacket(out, result, response.Body)
		clear(response.Body)
		if e != nil || ctx.Err() != nil {
			return ErrRejected
		}
	}
	return ErrRejected
}
