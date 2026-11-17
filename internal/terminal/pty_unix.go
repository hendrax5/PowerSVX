//go:build !windows

package terminal

import (
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
)

type Session struct {
	cmd  *exec.Cmd
	ptmx *os.File
}

func safeTerminalEnv() []string {
	allow := []string{"PATH", "HOME", "USER", "LOGNAME", "SHELL"}
	env := make([]string, 0, len(allow)+6)
	for _, k := range allow {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	if os.Getenv("PATH") == "" {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	if os.Getenv("HOME") == "" {
		env = append(env, "HOME=/root")
	}
	return append(env,
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"LC_CTYPE=C.UTF-8",
		"PS1=\\[\\e[1;38;5;208m\\]powersvx\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]# ",
	)
}

func StartSession() (*Session, io.ReadWriteCloser, error) {
	shell := "/bin/bash"
	if _, err := exec.LookPath("/bin/bash"); err != nil {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell)
	cmd.Env = safeTerminalEnv()

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
		// pty.Start puts the shell into its own session (pgid == pid); kill the whole group.
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	return nil
}
