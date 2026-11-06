module filippo.io/passkey/testdata/_chrome

go 1.26

require (
	filippo.io/passkey v0.0.0
	github.com/chromedp/cdproto v0.158.0
	github.com/chromedp/chromedp v0.21.0
)

require (
	filippo.io/mldsa v1.0.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20260623181947-01eb4420fa68 // indirect
)

replace filippo.io/passkey => ../..
