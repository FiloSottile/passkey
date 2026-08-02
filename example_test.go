package passkey_test

import (
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"

	"filippo.io/passkey"
)

func Example() {
	const page = `<!DOCTYPE html>
<meta charset="utf-8">
<title>passkey example</title>
<button id="login">Sign in</button>
<hr>
<input id="username" placeholder="username" autocomplete="username">
<button id="register">Sign up with a passkey</button>
<hr>
<p id="out"></p>
<script type="module">
addEventListener("unhandledrejection", e => out.textContent = e.reason)
const post = async (url, body) => {
const res = await fetch(url, { method: "POST", body })
if (!res.ok) throw new Error(await res.text())
return res
}
register.onclick = async () => {
const options = await (await post("/register", username.value)).json()
const credential = await navigator.credentials.create({
	publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
})
await post("/add-passkey", JSON.stringify(credential))
out.textContent = "Account created."
}
const loginOptions = () => post("/login/options").then(res => res.json())
let nextLogin = loginOptions()
login.onclick = async () => {
const options = await nextLogin
nextLogin = loginOptions() // requests are single-use
const credential = await navigator.credentials.get({
	publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
})
const res = await post("/login", JSON.stringify(credential))
out.textContent = "Signed in as " + await res.text() + "."
}
</script>
`

	rp, err := passkey.NewRelyingParty(&passkey.Options{
		// The RP ID is the site's registrable domain, so passkeys keep
		// working if sign-in later moves to a different origin.
		RPID:   "example.com",
		Origin: "https://login.example.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Stand-ins for the application's session and database.
	type user struct {
		username      string
		passkeyUserID string
		passkeys      []string
	}
	var sessionUser func(*http.Request) (*user, error)
	var sessionSignIn func(rw http.ResponseWriter, username string)
	var userByUserID func(passkeyUserID string) (*user, error)
	var registerNewUser func(username, passkeyUserID string) (*user, error)
	var requests sync.Map // request ID -> pending login request

	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, page)
	})

	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		username, _ := io.ReadAll(r.Body)
		// A user ID must be opaque and unique, so we generate a random one.
		u, err := registerNewUser(string(username), rand.Text())
		if err != nil {
			http.Error(w, "user already exists", http.StatusConflict)
			return
		}
		sessionSignIn(w, u.username)
		optionsJSON, err := rp.NewRegistration(
			passkey.User{ID: u.passkeyUserID, Name: u.username}, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(optionsJSON)
	})

	mux.HandleFunc("POST /add-passkey", func(w http.ResponseWriter, r *http.Request) {
		u, err := sessionUser(r)
		if err != nil {
			http.Error(w, "not signed in", http.StatusUnauthorized)
			return
		}
		responseJSON, _ := io.ReadAll(r.Body)
		record, err := rp.Register(responseJSON)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		u.passkeys = append(u.passkeys, record)
	})

	mux.HandleFunc("POST /login/options", func(w http.ResponseWriter, r *http.Request) {
		request, optionsJSON, err := rp.NewLogin()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		requests.Store(passkey.RequestID(request), request)
		w.Write(optionsJSON)
	})

	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		responseJSON, _ := io.ReadAll(r.Body)
		response, err := passkey.ParseResponse(responseJSON)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Each request is deleted after use, so it can't be replayed.
		request, ok := requests.LoadAndDelete(response.RequestID())
		// The asserted user ID is attacker-controlled until Login succeeds,
		// and is only used to look up the candidate passkey records.
		u, err := userByUserID(response.UnauthenticatedUserID())
		if !ok || err != nil {
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		if _, err := rp.Login(response, request.([]byte), u.passkeys); err != nil {
			switch {
			case errors.Is(err, passkey.ErrUnknownCredential):
				http.Error(w, "this passkey was removed from the account",
					http.StatusUnauthorized)
			case errors.Is(err, passkey.ErrRequestExpired):
				http.Error(w, "took too long, please try again", http.StatusUnauthorized)
			default:
				http.Error(w, "login failed", http.StatusUnauthorized)
			}
			return
		}
		sessionSignIn(w, u.username)
		io.WriteString(w, u.username)
	})
}
