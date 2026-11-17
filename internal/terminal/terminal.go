package terminal

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"golang.org/x/net/websocket"
)

type ResizeMessage struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wsHandler := websocket.Handler(func(ws *websocket.Conn) {
		var closeOnce sync.Once
		closeWS := func() {
			closeOnce.Do(func() {
				_ = ws.Close()
			})
		}
		defer closeWS()

		session, stream, err := StartSession()
		if err != nil {
			log.Printf("terminal: failed to start session: %v", err)
			_ = websocket.Message.Send(ws, []byte("\r\nFailed to spawn terminal shell: "+err.Error()+"\r\n"))
			return
		}
		defer session.Close()

		// Goroutine: stream PTY -> WebSocket (send raw binary frames to avoid split-UTF8 decode errors)
		go func() {
			buf := make([]byte, 32768)
			for {
				n, err := stream.Read(buf)
				if err != nil {
					log.Printf("terminal: stream.Read finished: %v", err)
					break
				}
				if n > 0 {
					// Send as raw bytes ([]byte) so websocket frame opcode is BinaryFrame (0x02)
					if err := websocket.Message.Send(ws, buf[:n]); err != nil {
						log.Printf("terminal: websocket.Message.Send error: %v", err)
						break
					}
				}
			}
			closeWS()
		}()

		// WebSocket -> stream PTY
		for {
			var raw []byte
			err := websocket.Message.Receive(ws, &raw)
			if err != nil {
				break
			}
			if len(raw) == 0 {
				continue
			}

			trimmed := bytes.TrimSpace(raw)
			if len(trimmed) > 0 && trimmed[0] == '{' {
				var rmsg ResizeMessage
				if err := json.Unmarshal(trimmed, &rmsg); err == nil && rmsg.Type == "resize" && rmsg.Cols > 0 && rmsg.Rows > 0 {
					_ = session.SetSize(rmsg.Cols, rmsg.Rows)
					continue
				}
			}

			// Write input to shell
			_, err = stream.Write(raw)
			if err != nil {
				break
			}
		}
	})

	wsHandler.ServeHTTP(w, r)
}
