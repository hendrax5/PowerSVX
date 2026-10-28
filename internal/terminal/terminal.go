package terminal

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

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
		defer ws.Close()

		session, stream, err := StartSession()
		if err != nil {
			log.Printf("terminal: failed to start session: %v", err)
			_ = websocket.Message.Send(ws, "\r\nFailed to spawn terminal shell: "+err.Error()+"\r\n")
			return
		}
		defer session.Close()

		// Goroutine: stream PTY -> WebSocket
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := stream.Read(buf)
				if err != nil {
					break
				}
				if n > 0 {
					if err := websocket.Message.Send(ws, string(buf[:n])); err != nil {
						break
					}
				}
			}
			ws.Close()
		}()

		// WebSocket -> stream PTY
		for {
			var msg string
			err := websocket.Message.Receive(ws, &msg)
			if err != nil {
				break
			}

			// Check for resize message
			if strings.HasPrefix(msg, `{"type":"resize"`) || strings.HasPrefix(msg, `{"type": "resize"`) {
				var rmsg ResizeMessage
				if err := json.Unmarshal([]byte(msg), &rmsg); err == nil && rmsg.Cols > 0 && rmsg.Rows > 0 {
					_ = session.SetSize(rmsg.Cols, rmsg.Rows)
					continue
				}
			}

			// Write input to shell
			_, err = stream.Write([]byte(msg))
			if err != nil {
				break
			}
		}
	})

	wsHandler.ServeHTTP(w, r)
}
