//go:build !windows

package terminal

import (
	"io"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

type Session struct {
	cmd  *exec.Cmd
	ptmx *os.File
}

func StartSession() (*Session, io.ReadWriteCloser, error) {
	shell := "/bin/bash"
	if _, err := exec.LookPath("/bin/bash"); err != nil {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"LANG=C.UTF-8",
		"PS1=\\[\\e[1;38;5;208m\\]powersvx\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]# ",
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, nil, err
	}

	return &Session{cmd: cmd, ptmx: ptmx}, ptmx, nil
}

func (s *Session) SetSize(cols, rows uint16) error {
	if s.ptmx == nil {
		return nil
	}
	return pty.Setsize(s.ptmx, &pty.Winsize{
		Rows: rows,
		Cols: cols,
	})
}

func (s *Session) Close() error {
	if s.ptmx != nil {
		_ = s.ptmx.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	return nil
}
