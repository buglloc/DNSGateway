package ucloudflare

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/rs/zerolog"

	"github.com/buglloc/DNSGateway/internal/upstream"
)

var _ upstream.Tx = (*Tx)(nil)

type Tx struct {
	cfc    *cloudflare.API
	store  *Storage
	zoneID string
	log    zerolog.Logger
}

func (t *Tx) Delete(r upstream.Rule) error {
	_, err := t.store.Delete(r)
	return err
}

func (t *Tx) Append(r upstream.Rule) error {
	if r.ValueStr == "" {
		// TODO(buglloc): fix me
		r.ValueStr = fmt.Sprint(r.Value)
	}

	return t.store.Append(r)
}

func (t *Tx) Commit(ctx context.Context) error {
	if err := t.processDeletes(ctx, t.store.ToDelete()); err != nil {
		return fmt.Errorf("deletes failed: %w", err)
	}

	if err := t.processAdds(ctx, t.store.ToAdd()); err != nil {
		return fmt.Errorf("adds failed: %w", err)
	}

	return nil
}

func (t *Tx) processDeletes(ctx context.Context, recs []cloudflare.DNSRecord) error {
	for _, rr := range recs {
		if rr.ID == "" {
			t.log.Error().
				Str("name", rr.Name).
				Str("content", rr.Content).
				Msg("unable to delete record w/o ID")
			return fmt.Errorf("delete record %q: missing ID", rr.Name)
		}

		if err := t.cfc.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(t.zoneID), rr.ID); err != nil {
			t.log.Error().
				Str("id", rr.ID).
				Str("name", rr.Name).
				Str("content", rr.Content).
				Err(err).
				Msg("unable to delete record in CF")

			return fmt.Errorf("delete record %q[%s]: %w", rr.Name, rr.ID, err)
		}

		t.log.Info().
			Str("id", rr.ID).
			Str("name", rr.Name).
			Str("content", rr.Content).
			Msg("record deleted")
	}

	return nil
}

func (t *Tx) processAdds(ctx context.Context, recs []cloudflare.DNSRecord) error {
	for _, rr := range recs {
		record := cloudflare.CreateDNSRecordParams{
			Name:     rr.Name,
			Type:     strings.ToUpper(rr.Type),
			Content:  rr.Content,
			Data:     rr.Data,
			TTL:      rr.TTL,
			Proxied:  rr.Proxied,
			Priority: rr.Priority,
		}

		rsp, err := t.cfc.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(t.zoneID), record)
		if err != nil {
			t.log.Error().
				Str("name", rr.Name).
				Str("content", rr.Content).
				Err(err).
				Msg("unable to update record in CF")
			return fmt.Errorf("create record %q: %w", rr.Name, err)
		}

		t.log.Info().
			Str("id", rsp.ID).
			Str("name", rr.Name).
			Str("content", rr.Content).
			Msg("record added")
	}

	return nil
}

func (t *Tx) Close() {}
