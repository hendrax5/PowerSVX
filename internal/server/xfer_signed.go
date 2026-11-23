package server

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
)

// Transfers of signed zones (ADR-0004). The primary signs and a secondary serves
// what it receives, so an AXFR, and the full-zone answer an IXFR gets, carries
// the DNSKEY RRset, an RRSIG over every RRset, the NSEC or NSEC3 chain with its
// RRSIGs, and for NSEC3 the signed NSEC3PARAM.

// xferEnvelopeBytes bounds the answer section of one message of a TCP transfer.
// A message is at most 65535 bytes, and a signed zone does not fit in one.
const xferEnvelopeBytes = 16 << 10

// signatureCheckInterval is how often RefreshSignedZones runs.
const signatureCheckInterval = 10 * time.Minute

var errTransferAborted = errors.New("transfer aborted")

// sigPolicy is the timing of the signatures in transfers: [transfer]
// signature_validity_days and signature_refresh_days.
func (s *Server) sigPolicy() dnssec.SigPolicy {
	var p dnssec.SigPolicy
	if s.cfg != nil {
		p.Validity = time.Duration(s.cfg.Transfer.SignatureValidityDays) * 24 * time.Hour
		p.Refresh = time.Duration(s.cfg.Transfer.SignatureRefreshDays) * 24 * time.Hour
	}
	return p.Normalized()
}

// isDNSSECType is true for the types a transfer generates itself; any of them
// in the stored records is ignored, so a signed zone never carries two sets.
func isDNSSECType(t uint16) bool {
	switch t {
	case dns.TypeDNSKEY, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
		return true
	}
	return false
}

// signedZoneStream returns the producer of a full transfer of the signed zone
// made from recs, the snapshot of the zone the transfer is answered from (its
// SOA is soa). The zone is signed as the RRsets are emitted, so only the
// owner-name map and the denial chain are held besides the snapshot.
func (s *Server) signedZoneStream(zone string, soa dns.RR, recs []authoritative.Record, now time.Time) func(emit func(dns.RR) error) error {
	return func(emit func(dns.RR) error) error {
		zs, err := s.signer.ForTransfer(zone, s.sigPolicy(), now)
		if err != nil {
			return err
		}
		soaRR := soa.(*dns.SOA)
		negTTL := dnssec.NegativeTTL(soaRR)

		type setRef struct {
			key authoritative.SetKey
			idx []int
		}
		var order []*setRef
		sets := map[authoritative.SetKey]*setRef{}
		names := map[string][]uint16{dns.CanonicalName(zone): {dns.TypeSOA}}
		for i, rec := range recs {
			if rec.Type == dns.TypeSOA || isDNSSECType(rec.Type) || authoritative.RecordToRR(rec) == nil {
				continue
			}
			k := authoritative.SetKey{Name: config.NormalizeName(rec.Name), Type: rec.Type}
			ref := sets[k]
			if ref == nil {
				ref = &setRef{key: k}
				sets[k] = ref
				order = append(order, ref)
				names[k.Name] = append(names[k.Name], k.Type)
			}
			ref.idx = append(ref.idx, i)
		}

		emitSigned := func(rrs []dns.RR) error {
			for _, rr := range rrs {
				if err := emit(rr); err != nil {
					return err
				}
			}
			sig, err := zs.Sign(rrs)
			if err != nil {
				return err
			}
			return emit(sig)
		}

		if err := emit(soa); err != nil {
			return err
		}
		if err := emitSigned(zs.Keys()); err != nil {
			return err
		}
		if np := zs.NSEC3PARAM(negTTL); np != nil {
			if err := emitSigned([]dns.RR{np}); err != nil {
				return err
			}
		}
		sig, err := zs.Sign([]dns.RR{soa})
		if err != nil {
			return err
		}
		if err := emit(sig); err != nil {
			return err
		}
		for _, ref := range order {
			rrs := make([]dns.RR, 0, len(ref.idx))
			for _, i := range ref.idx {
				if rr := authoritative.RecordToRR(recs[i]); rr != nil {
					rrs = append(rrs, rr)
				}
			}
			if err := emitSigned(rrs); err != nil {
				return err
			}
		}
		for _, rr := range zs.Chain(names, negTTL) {
			if err := emitSigned([]dns.RR{rr}); err != nil {
				return err
			}
		}
		return emit(soa)
	}
}

// sendTransfer writes a transfer in as many messages as it needs over TCP (one
// over UDP, where only the short IXFR answer is ever sent in full). The stream
// is either rrs or what produce emits; the first RR must be the SOA and the last
// the SOA again. When production fails before anything was sent the client gets
// SERVFAIL; when it fails later the connection is closed, which a client takes
// for an incomplete transfer, never for a whole one.
func (s *Server) sendTransfer(w dns.ResponseWriter, req *dns.Msg, rrs []dns.RR, produce func(emit func(dns.RR) error) error) error {
	if produce == nil {
		produce = func(emit func(dns.RR) error) error {
			for _, rr := range rrs {
				if err := emit(rr); err != nil {
					return err
				}
			}
			return nil
		}
	}
	limit := math.MaxInt
	if protocolFromWriter(w) == "tcp" {
		limit = xferEnvelopeBytes
	}

	type outcome struct {
		err  error
		sent int
	}
	ch := make(chan *dns.Envelope)
	done := make(chan struct{})
	res := make(chan outcome, 1)
	go func() {
		defer close(ch)
		var batch []dns.RR
		size, sent := 0, 0
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			select {
			case ch <- &dns.Envelope{RR: batch}:
				sent++
				batch, size = nil, 0
				return nil
			case <-done:
				return errTransferAborted
			}
		}
		err := produce(func(rr dns.RR) error {
			n := dns.Len(rr)
			if size+n > limit && len(batch) > 0 {
				if err := flush(); err != nil {
					return err
				}
			}
			batch = append(batch, rr)
			size += n
			return nil
		})
		if err == nil {
			err = flush()
		}
		res <- outcome{err, sent}
	}()

	tr := new(dns.Transfer)
	outErr := tr.Out(w, req, ch)
	close(done)
	r := <-res
	if outErr != nil {
		return outErr
	}
	if r.err != nil {
		if r.sent == 0 {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
		} else {
			_ = w.Close()
		}
		return r.err
	}
	return nil
}

// RefreshSignedZones bumps the SOA serial of every zone this process signs whose
// transfer signatures differ from those its current serial was last bumped for:
// a new refresh interval began, a key was rolled, the zone was newly signed or its
// NSEC/NSEC3 policy changed. Secondaries are notified, and pull the zone with its
// new signatures. It returns the zones it bumped.
func (s *Server) RefreshSignedZones(now time.Time) []string {
	if s == nil || s.signer == nil || s.auth == nil {
		return nil
	}
	p := s.sigPolicy()
	var bumped []string
	for _, zi := range s.auth.ListZones() {
		if !s.signsLocally(zi.Name) {
			continue
		}
		fp, due := s.signer.TransferRefreshDue(zi.Name, p, now)
		if !due {
			continue
		}
		if _, ok := s.auth.BumpSOASerial(zi.Name); ok {
			bumped = append(bumped, zi.Name)
			s.NotifySecondaries(zi.Name)
		}
		if err := s.signer.MarkTransferRefreshed(zi.Name, fp); err != nil && s.log != nil {
			s.log.Warn("transfer signature state not saved", "zone", zi.Name, "err", err)
		}
	}
	return bumped
}

// RunSignatureRefresh runs RefreshSignedZones now and then until ctx ends.
func (s *Server) RunSignatureRefresh(ctx context.Context) {
	t := time.NewTicker(signatureCheckInterval)
	defer t.Stop()
	for {
		for _, z := range s.RefreshSignedZones(time.Now().UTC()) {
			if s.log != nil {
				s.log.Info("signed zone serial bumped for new transfer signatures", "zone", z)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
