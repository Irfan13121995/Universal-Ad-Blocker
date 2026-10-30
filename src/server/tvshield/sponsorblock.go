// Package tvshield provides network-wide Smart TV YouTube ad skipping,
// unskippable ad auto-muting, and SponsorBlock segment skipping via YouTube's
// Lounge protocol and DIAL/SSDP discovery (compatible with Google TV / Android TV
// and Samsung Smart TVs running Tizen OS without root or custom certificates).
package tvshield

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultSponsorBlockAPI = "https://sponsor.ajay.app/api"

// Segment represents a merged skippable SponsorBlock interval in seconds.
type Segment struct {
	Start    float64  `json:"start"`
	End      float64  `json:"end"`
	Category string   `json:"category"`
	UUIDs    []string `json:"uuids,omitempty"`
}

type rawSBVideo struct {
	VideoID  string         `json:"videoID"`
	Segments []rawSBSegment `json:"segments"`
}

type rawSBSegment struct {
	Segment  [2]float64 `json:"segment"`
	UUID     string     `json:"UUID"`
	Category string     `json:"category"`
	Locked   int        `json:"locked"`
}

type sbCacheEntry struct {
	segments  []Segment
	expiresAt time.Time
}

// SponsorBlockClient queries SponsorBlock using privacy-preserving 4-hex SHA-256 prefixes.
type SponsorBlockClient struct {
	baseURL string
	http    *http.Client

	mu    sync.Mutex
	cache map[string]sbCacheEntry
}

// NewSponsorBlockClient creates a SponsorBlock client that bypasses any local system proxy.
func NewSponsorBlockClient() *SponsorBlockClient {
	return &SponsorBlockClient{
		baseURL: defaultSponsorBlockAPI,
		http: &http.Client{
			Timeout:   8 * time.Second,
			Transport: &http.Transport{Proxy: nil},
		},
		cache: make(map[string]sbCacheEntry),
	}
}

// HashPrefix computes the first 4 lowercase hex characters of SHA-256(videoID)
// for k-anonymous SponsorBlock lookups.
func HashPrefix(videoID string) string {
	sum := sha256.Sum256([]byte(videoID))
	return hex.EncodeToString(sum[:])[:4]
}

// GetSegments fetches and merges skippable segments for videoID across categories.
func (c *SponsorBlockClient) GetSegments(ctx context.Context, videoID string, categories []string) ([]Segment, error) {
	videoID = strings.TrimSpace(videoID)
	if videoID == "" || len(categories) == 0 {
		return nil, nil
	}

	cats := append([]string(nil), categories...)
	sort.Strings(cats)
	cacheKey := videoID + "|" + strings.Join(cats, ",")

	now := time.Now()
	c.mu.Lock()
	if ent, ok := c.cache[cacheKey]; ok && now.Before(ent.expiresAt) {
		out := append([]Segment(nil), ent.segments...)
		c.mu.Unlock()
		return out, nil
	}
	c.mu.Unlock()

	prefix := HashPrefix(videoID)
	q := url.Values{
		"actionType": {"skip"},
		"service":    {"YouTube"},
	}
	for _, cat := range cats {
		if cat = strings.TrimSpace(cat); cat != "" {
			q.Add("category", cat)
		}
	}

	reqURL := fmt.Sprintf("%s/skipSegments/%s?%s", strings.TrimRight(c.baseURL, "/"), prefix, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Sinkhole-TVShield/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 404 is normal when no segments exist in this hash bucket.
	if resp.StatusCode == http.StatusNotFound {
		c.storeCache(cacheKey, nil, 5*time.Minute)
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sponsorblock status %d", resp.StatusCode)
	}

	var bucket []rawSBVideo
	if err := json.NewDecoder(resp.Body).Decode(&bucket); err != nil {
		return nil, err
	}

	var matched *rawSBVideo
	for i := range bucket {
		if bucket[i].VideoID == videoID {
			matched = &bucket[i]
			break
		}
	}

	if matched == nil || len(matched.Segments) == 0 {
		c.storeCache(cacheKey, nil, 10*time.Minute)
		return nil, nil
	}

	merged, allLocked := MergeSegments(matched.Segments, 0.5)
	ttl := 10 * time.Minute
	if allLocked && len(merged) > 0 {
		ttl = 60 * time.Minute
	}
	c.storeCache(cacheKey, merged, ttl)
	return merged, nil
}

func (c *SponsorBlockClient) storeCache(key string, segs []Segment, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= 256 {
		now := time.Now()
		for k, v := range c.cache {
			if now.After(v.expiresAt) {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= 256 {
			c.cache = make(map[string]sbCacheEntry)
		}
	}
	c.cache[key] = sbCacheEntry{
		segments:  append([]Segment(nil), segs...),
		expiresAt: time.Now().Add(ttl),
	}
}

// MergeSegments combines overlapping or <1s-adjacent SponsorBlock segments into single jumps.
func MergeSegments(raw []rawSBSegment, minLength float64) ([]Segment, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	items := make([]rawSBSegment, 0, len(raw))
	allLocked := true
	for _, r := range raw {
		if r.Segment[1] <= r.Segment[0] {
			continue
		}
		if r.Locked != 1 {
			allLocked = false
		}
		items = append(items, r)
	}
	if len(items) == 0 {
		return nil, false
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Segment[0] == items[j].Segment[0] {
			return items[i].Segment[1] < items[j].Segment[1]
		}
		return items[i].Segment[0] < items[j].Segment[0]
	})

	var out []Segment
	for _, item := range items {
		start, end := item.Segment[0], item.Segment[1]
		if len(out) > 0 {
			prev := &out[len(out)-1]
			// Merge overlapping segments or segments separated by less than 1 second
			if start-prev.End < 1.0 {
				if end > prev.End {
					prev.End = end
				}
				if item.UUID != "" {
					prev.UUIDs = append(prev.UUIDs, item.UUID)
				}
				continue
			}
		}
		var uuids []string
		if item.UUID != "" {
			uuids = []string{item.UUID}
		}
		cat := item.Category
		if cat == "" {
			cat = "sponsor"
		}
		out = append(out, Segment{
			Start:    start,
			End:      end,
			Category: cat,
			UUIDs:    uuids,
		})
	}

	filtered := out[:0]
	for _, s := range out {
		if s.End-s.Start >= minLength {
			filtered = append(filtered, s)
		}
	}
	return filtered, allLocked
}
