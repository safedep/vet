// Package weburl checks the web links that vet reads from a file and
// shows to a person, such as the link of a policy rule.
package weburl

import "net/url"

// Valid reports whether s is an absolute http or https URL with a host and
// no user info. A link of another scheme can run script in a report. User
// info, as in https://good.example@evil.example/, hides the real host.
func Valid(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}
