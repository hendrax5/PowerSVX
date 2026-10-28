//go:build windows

package terminal

import (
	"io"
	"os/exec"
)

type Session struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out io.ReadCloser
}

func StartSession() (*Session, io.ReadWriteCloser, error) {
	cmd := exec.Command("cmd.exe")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	rwc := &rwcBridge{r: out, w: in}
	return &Session{cmd: cmd, in: in, out: out}, rwc, nil
}

func (s *Session) SetSize(cols, rows uint16) error {
	return nil
}

func (s *Session) Close() error {
	if s.in != nil {
		s.in.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	return nil
}

type rwcBridge struct {
	r io.Reader
	w io.Writer
}

func (b *rwcBridge) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *rwcBridge) Write(p []byte) (int, error) { return b.w.Write(p) }
func (b *rwcBridge) Close() error               { return nil }
