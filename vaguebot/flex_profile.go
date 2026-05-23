package vaguebot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type profileFlexCardData struct {
	CID           string
	DisplayName   string
	StatusMessage string
	PictureURL    string
	CoverURL      string
}

const (
	profileFlexDefaultWidth     = 240
	profileFlexDefaultHeight    = 240
	profileFlexMinWidth         = 180
	profileFlexMaxWidth         = 720
	profileFlexMinHeight        = 180
	profileFlexMaxHeight        = 1400
	profileFlexDefaultMaxHeight = "0.88"
)

func (c *Client) BuildProfileVFlex(ctx context.Context, cid string) (string, string, error) {
	card, err := c.resolveProfileFlexCardData(ctx, cid)
	if err != nil {
		return "", "", err
	}

	cidLabel := card.CID
	if cidLabel == "" {
		cidLabel = "-"
	}

	infoChildren := make([]any, 0, 2)
	if card.PictureURL != "" {
		infoChildren = append(infoChildren, map[string]any{
			"type":         "image",
			"url":          card.PictureURL,
			"width":        56,
			"height":       56,
			"fit":          "cover",
			"borderRadius": 28,
		})
	}

	infoChildren = append(infoChildren, map[string]any{
		"type":      "box",
		"direction": "column",
		"flex":      1,
		"spacing":   4,
		"children": []any{
			map[string]any{
				"type":     "text",
				"text":     card.DisplayName,
				"weight":   "bold",
				"size":     16,
				"color":    "#FFFFFF",
				"maxLines": 2,
			},
			map[string]any{
				"type":     "text",
				"text":     card.StatusMessage,
				"size":     12,
				"color":    "#D0D0D0",
				"maxLines": 3,
			},
		},
	})

	bodyChildren := make([]any, 0, 4)
	if card.CoverURL != "" {
		bodyChildren = append(bodyChildren, map[string]any{
			"type":         "image",
			"url":          card.CoverURL,
			"fit":          "cover",
			"ratio":        2.0,
			"borderRadius": 10,
		})
	}

	bodyChildren = append(bodyChildren, map[string]any{
		"type":      "box",
		"direction": "row",
		"spacing":   10,
		"align":     "center",
		"children":  infoChildren,
	})

	bodyChildren = append(bodyChildren, map[string]any{
		"type":      "divider",
		"color":     "#00ccff",
		"thickness": 1,
	})

	bodyChildren = append(bodyChildren, map[string]any{
		"type":      "box",
		"direction": "row",
		"justify":   "spaceBetween",
		"align":     "center",
		"children": []any{
			map[string]any{
				"type":  "text",
				"text":  "Vague Profile",
				"size":  11,
				"color": "#9FA6B2",
			},
		},
	})

	altText := fmt.Sprintf("Profile %s", card.DisplayName)
	body := map[string]any{
		"type":            "box",
		"direction":       "column",
		"padding":         12,
		"spacing":         10,
		"backgroundColor": "#000000",
		"borderRadius":    14,
		"children":        bodyChildren,
	}
	if profileFlexDefaultWidth > 0 {
		body["width"] = clampProfileFlexDimension(
			profileFlexDefaultWidth,
			profileFlexMinWidth,
			profileFlexMaxWidth,
		)
	}
	if profileFlexDefaultHeight > 0 {
		body["height"] = clampProfileFlexDimension(
			profileFlexDefaultHeight,
			profileFlexMinHeight,
			profileFlexMaxHeight,
		)
	}

	doc := map[string]any{
		"type":    "vflex",
		"version": 2,
		"altText": altText,
		"meta": map[string]any{
			"safeArea":       "true",
			"maxHeightRatio": profileFlexDefaultMaxHeight,
		},
		"body": body,
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		return "", "", fmt.Errorf("build flex json: %w", err)
	}
	return altText, string(payload), nil
}

func clampProfileFlexDimension(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func (c *Client) resolveProfileFlexCardData(ctx context.Context, cid string) (profileFlexCardData, error) {
	targetCID := strings.TrimSpace(cid)
	if targetCID == "" {
		return profileFlexCardData{}, errors.New("target cid is required")
	}

	out := profileFlexCardData{CID: targetCID}

	contacts, contactErr := c.GetContacts(ctx, []string{targetCID})
	if contactErr == nil && len(contacts) > 0 && contacts[0] != nil {
		contact := contacts[0]
		out.DisplayName = strings.TrimSpace(contact.GetDisplayName())
		out.StatusMessage = strings.TrimSpace(contact.GetStatusMessage())
		out.PictureURL = strings.TrimSpace(contact.GetPictureProfile())
		out.CoverURL = strings.TrimSpace(contact.GetCoverPictureProfile())
	}

	// Fallback ke profile sendiri jika target sama dengan bot/self.
	if targetCID == strings.TrimSpace(c.CurrentCID()) {
		profile, err := c.GetProfile(ctx)
		if err == nil && profile != nil {
			if strings.TrimSpace(out.CID) == "" {
				out.CID = strings.TrimSpace(profile.GetCid())
			}
			if strings.TrimSpace(out.DisplayName) == "" {
				out.DisplayName = strings.TrimSpace(profile.GetDisplayName())
			}
			if strings.TrimSpace(out.StatusMessage) == "" {
				out.StatusMessage = strings.TrimSpace(profile.GetStatusMessage())
			}
			if strings.TrimSpace(out.PictureURL) == "" {
				out.PictureURL = strings.TrimSpace(profile.GetPictureProfile())
			}
			if strings.TrimSpace(out.CoverURL) == "" {
				out.CoverURL = strings.TrimSpace(profile.GetCoverPictureProfile())
			}
		}
	}

	if strings.TrimSpace(out.DisplayName) == "" {
		out.DisplayName = targetCID
	}
	if strings.TrimSpace(out.StatusMessage) == "" {
		out.StatusMessage = "No status message"
	}

	out.PictureURL = c.resolvePublicAssetURL(out.PictureURL)
	out.CoverURL = c.resolvePublicAssetURL(out.CoverURL)

	if out.PictureURL == "" && out.CoverURL == "" && contactErr != nil {
		return profileFlexCardData{}, fmt.Errorf("get contact: %w", contactErr)
	}
	return out, nil
}

func (c *Client) resolvePublicAssetURL(raw string) string {
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		return ""
	}
	lower := strings.ToLower(normalized)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return normalized
	}
	if strings.HasPrefix(normalized, "//") {
		return "https:" + normalized
	}

	base := strings.TrimSpace(os.Getenv("VAGUE_BOT_PUBLIC_BASE_URL"))
	if base == "" {
		base = defaultPublicBaseURLFromTarget(c.cfg.Target)
	}
	base = strings.TrimRight(base, "/")
	if base == "" {
		base = "https://link.vague-infinity.com"
	}
	if strings.HasPrefix(normalized, "/") {
		return base + normalized
	}
	return base + "/" + normalized
}

func defaultPublicBaseURLFromTarget(target string) string {
	normalized := strings.TrimSpace(target)
	normalized = strings.TrimPrefix(normalized, "dns://")
	normalized = strings.TrimPrefix(normalized, "http://")
	normalized = strings.TrimPrefix(normalized, "https://")
	if idx := strings.Index(normalized, "/"); idx >= 0 {
		normalized = normalized[:idx]
	}
	if strings.HasPrefix(normalized, "[") {
		if idx := strings.Index(normalized, "]"); idx >= 0 {
			host := normalized[1:idx]
			if host != "" {
				return "https://" + host
			}
			return ""
		}
	}
	if idx := strings.LastIndex(normalized, ":"); idx >= 0 {
		normalized = normalized[:idx]
	}
	if normalized == "" {
		return ""
	}
	return "https://" + normalized
}
