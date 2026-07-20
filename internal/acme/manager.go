package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/powersvx/powersvx/internal/config"
)

// Manager obtains/renews certificates via ACME DNS-01 using the local challenge store.
type Manager struct {
	cfg   config.ACMEConfig
	store *ChallengeStore
	log   *slog.Logger
}

func NewManager(cfg config.ACMEConfig, store *ChallengeStore, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{cfg: cfg, store: store, log: log}
}

type user struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *user) GetEmail() string                        { return u.Email }
func (u *user) GetRegistration() *registration.Resource { return u.Registration }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

type dnsProvider struct {
	store *ChallengeStore
}

func (p *dnsProvider) Present(domain, token, keyAuth string) error {
	_, value := dns01.GetRecord(domain, keyAuth)
	p.store.Present(domain, value)
	return nil
}

func (p *dnsProvider) CleanUp(domain, token, keyAuth string) error {
	p.store.CleanUp(domain)
	return nil
}

// Obtain requests certificates for configured domains and writes PEM files.
func (m *Manager) Obtain() error {
	if m == nil || !m.cfg.Enabled {
		return fmt.Errorf("acme disabled")
	}
	if m.cfg.Email == "" || len(m.cfg.Domains) == 0 {
		return fmt.Errorf("acme email and domains required")
	}
	dir := m.cfg.StorageDir
	if dir == "" {
		dir = "./certs/acme"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	u := &user{Email: m.cfg.Email, key: privateKey}

	legoCfg := lego.NewConfig(u)
	if m.cfg.Staging {
		legoCfg.CADirURL = lego.LEDirectoryStaging
	} else {
		legoCfg.CADirURL = lego.LEDirectoryProduction
	}
	legoCfg.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return err
	}
	if err := client.Challenge.SetDNS01Provider(&dnsProvider{store: m.store},
		dns01.DisableCompletePropagationRequirement(),
	); err != nil {
		return err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	u.Registration = reg

	req := certificate.ObtainRequest{Domains: m.cfg.Domains, Bundle: true}
	certs, err := client.Certificate.Obtain(req)
	if err != nil {
		return err
	}

	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, certs.Certificate, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, certs.PrivateKey, 0o600); err != nil {
		return err
	}
	m.log.Info("acme certificate obtained", "domains", m.cfg.Domains, "cert", certPath, "key", keyPath)
	return nil
}

// Status is a snapshot for the API.
func (m *Manager) Status() map[string]any {
	if m == nil {
		return map[string]any{"enabled": false}
	}
	dir := m.cfg.StorageDir
	if dir == "" {
		dir = "./certs/acme"
	}
	certPath := filepath.Join(dir, "fullchain.pem")
	_, err := os.Stat(certPath)
	return map[string]any{
		"enabled":         m.cfg.Enabled,
		"staging":         m.cfg.Staging,
		"email":           m.cfg.Email,
		"domains":         m.cfg.Domains,
		"storage_dir":     dir,
		"challenges":      m.store.Count(),
		"cert_present":    err == nil,
		"cert_path":       certPath,
		"last_checked_at": time.Now().UTC().Format(time.RFC3339),
	}
}
