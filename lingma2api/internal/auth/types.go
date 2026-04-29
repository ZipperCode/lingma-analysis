package auth

import (
	"net/url"
	"time"
)

type AuthorizeConfig struct {
	ClientID    string
	RedirectURL string
	Scope       string
	AuthBaseURL string
}

type CallbackCapture struct {
	Path       string
	Query      url.Values
	ReceivedAt time.Time
	Referer    string
	Body       []byte // non-nil for POST /submit-userinfo
}
