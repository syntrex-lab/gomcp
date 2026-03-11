package transport

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/syntrex/gomcp/internal/domain/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWSTransport_StartStop(t *testing.T) {
	reg := peer.NewRegistry("test-node", 5*time.Minute)
	cfg := WSConfig{Port: 0, Host: "localhost", Enabled: true}
	tr := NewWSTransport(cfg, reg)

	// Port 0 → use default 9741, but we override with listener.
	err := tr.Start()
	require.NoError(t, err)

	addr := tr.Addr()
	assert.NotEmpty(t, addr)

	err = tr.Stop()
	assert.NoError(t, err)
}

func TestWSTransport_Ping(t *testing.T) {
	reg := peer.NewRegistry("ping-node", 5*time.Minute)
	cfg := WSConfig{Port: 0, Host: "localhost"}
	tr := NewWSTransport(cfg, reg)

	require.NoError(t, tr.Start())
	defer tr.Stop()

	ctx := context.Background()
	peerID, err := tr.Ping(ctx, tr.Addr())
	require.NoError(t, err)
	assert.Equal(t, reg.SelfID(), peerID)
}

func TestWSTransport_SyncPayload(t *testing.T) {
	reg := peer.NewRegistry("sync-node", 5*time.Minute)
	cfg := WSConfig{Port: 0}
	tr := NewWSTransport(cfg, reg)

	done := make(chan peer.SyncPayload, 1)
	tr.OnSync(func(p peer.SyncPayload) error {
		done <- p
		return nil
	})

	require.NoError(t, tr.Start())
	defer tr.Stop()

	payload := peer.SyncPayload{
		FromPeerID: "remote-1",
		GenomeHash: "abc123",
		Facts: []peer.SyncFact{
			{ID: "f1", Content: "test fact", Level: 0, IsGene: false},
		},
		SyncedAt: time.Now(),
	}

	ctx := context.Background()
	err := tr.SendSync(ctx, tr.Addr(), payload)
	require.NoError(t, err)

	received := <-done
	assert.Equal(t, "remote-1", received.FromPeerID)
	assert.Equal(t, "abc123", received.GenomeHash)
	assert.Len(t, received.Facts, 1)
	assert.Equal(t, "test fact", received.Facts[0].Content)
}

func TestWSTransport_DeltaSync(t *testing.T) {
	reg := peer.NewRegistry("delta-node", 5*time.Minute)
	cfg := WSConfig{Port: 0}
	tr := NewWSTransport(cfg, reg)

	require.NoError(t, tr.Start())
	defer tr.Stop()

	ctx := context.Background()
	req := peer.DeltaSyncRequest{
		FromPeerID: reg.SelfID(),
		GenomeHash: "test_hash",
		Since:      time.Now().Add(-1 * time.Hour),
		MaxBatch:   10,
	}

	resp, err := tr.SendDeltaSync(ctx, tr.Addr(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, reg.SelfID(), resp.FromPeerID)
	assert.False(t, resp.HasMore)
}

func TestFilterFactsSince(t *testing.T) {
	now := time.Now()
	facts := []peer.SyncFact{
		{ID: "old", Content: "old fact", CreatedAt: now.Add(-2 * time.Hour)},
		{ID: "new1", Content: "new fact 1", CreatedAt: now.Add(-30 * time.Minute)},
		{ID: "new2", Content: "new fact 2", CreatedAt: now.Add(-10 * time.Minute)},
	}

	// Filter since 1 hour ago.
	filtered, hasMore := peer.FilterFactsSince(facts, now.Add(-1*time.Hour), 100)
	assert.Len(t, filtered, 2)
	assert.False(t, hasMore)
	assert.Equal(t, "new1", filtered[0].ID)
	assert.Equal(t, "new2", filtered[1].ID)

	// Filter with small batch.
	filtered, hasMore = peer.FilterFactsSince(facts, now.Add(-1*time.Hour), 1)
	assert.Len(t, filtered, 1)
	assert.True(t, hasMore)
}

func TestMessage_JSON(t *testing.T) {
	msg := Message{
		Type:   "ping",
		From:   "node-1",
		SentAt: time.Now(),
	}
	data, err := json.Marshal(msg)
	require.NoError(t, err)

	var decoded Message
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "ping", decoded.Type)
	assert.Equal(t, "node-1", decoded.From)
}
