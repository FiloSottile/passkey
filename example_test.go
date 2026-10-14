package passkey_test

import (
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

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
const loginOptions = () => fetch("/login/options").then(res => res.json())
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

	// The RP ID is the site's registrable domain, so passkeys keep
	// working if sign-in later moves to a different origin.
	rp, err := passkey.NewRelyingParty("example.com", "https://login.example.com",
		passkey.Options{})
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
			passkey.User{ID: u.passkeyUserID, Name: u.username},
			passkey.RegistrationOptions{})
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
			switch {
			case errors.Is(err, passkey.ErrUserVerificationUnavailable):
				http.Error(w, "this passkey can't verify it's you: set up a PIN "+
					"on your security key, or use a different authenticator",
					http.StatusBadRequest)
			default:
				http.Error(w, "registration failed", http.StatusBadRequest)
			}
			return
		}
		u.passkeys = append(u.passkeys, record)
	})

	mux.HandleFunc("GET /login/options", func(w http.ResponseWriter, r *http.Request) {
		request, optionsJSON, err := rp.NewLogin(passkey.LoginOptions{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		requests.Store(passkey.RequestID(request), request)
		w.Header().Set("Cache-Control", "no-store")
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

	// Evict expired pending requests to reclaim memory;
	// a production KV store would rely on a TTL instead.
	go func() {
		for range time.Tick(time.Minute) {
			requests.Range(func(key, value any) bool {
				created := passkey.RequestCreation(value.([]byte))
				if time.Since(created) > 5*time.Minute {
					requests.Delete(key)
				}
				return true
			})
		}
	}()

	// CSRF protection is critical to avoid POST /add-passkey
	// being abused to add a passkey to another user's account.
	handler := http.NewCrossOriginProtection().Handler(mux)

	log.Fatal(http.ListenAndServe("localhost:8080", handler))
}

func ExampleRelyingParty_NewRegistration() {
	rp, err := passkey.NewRelyingParty("example.com", "https://login.example.com",
		passkey.Options{})
	if err != nil {
		log.Fatal(err)
	}

	// Stand-in for the application's session and database.
	type user struct {
		username      string
		passkeyUserID string
		passkeys      []string
	}
	var sessionUser func(*http.Request) (*user, error)

	// The package-level example shows the complete flow, including the
	// client-side JavaScript, registration, and the login endpoints.
	//
	// This endpoint begins a registration ceremony for adding a new passkey
	// to an existing account.
	http.HandleFunc("GET /add-passkey/options", func(w http.ResponseWriter, r *http.Request) {
		u, err := sessionUser(r)
		if err != nil {
			http.Error(w, "not signed in", http.StatusUnauthorized)
			return
		}
		// Excluding the existing passkeys prevents the user from
		// registering the same authenticator twice.
		optionsJSON, err := rp.NewRegistration(
			passkey.User{ID: u.passkeyUserID, Name: u.username},
			passkey.RegistrationOptions{ExcludeCredentials: u.passkeys})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// The client passes the options to
		// PublicKeyCredential.parseCreationOptionsFromJSON() and then to
		// navigator.credentials.create(), and posts the result's toJSON()
		// to the endpoint that calls [passkey.RelyingParty.Register].
		w.Header().Set("Cache-Control", "no-store")
		w.Write(optionsJSON)
	})
}

func ExampleRelyingParty_Register() {
	rp, err := passkey.NewRelyingParty("example.com", "https://login.example.com",
		passkey.Options{})
	if err != nil {
		log.Fatal(err)
	}

	// Stand-ins for the application's session and database.
	type user struct {
		passkeys []string
	}
	var sessionUser func(*http.Request) (*user, error)

	// The package-level example shows the complete flow, including the
	// client-side JavaScript and the login endpoints.
	//
	// This endpoint stores a new passkey record for the signed-in user.
	//
	// CSRF protection is critical to avoid the endpoint being abused to
	// add a passkey to another user's account.
	http.Handle("POST /add-passkey", http.NewCrossOriginProtection().Handler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			u, err := sessionUser(r)
			if err != nil {
				http.Error(w, "not signed in", http.StatusUnauthorized)
				return
			}
			responseJSON, _ := io.ReadAll(r.Body)
			record, err := rp.Register(responseJSON)
			if err != nil {
				switch {
				case errors.Is(err, passkey.ErrUserVerificationUnavailable):
					http.Error(w, "this passkey can't verify it's you: set up a PIN "+
						"on your security key, or use a different authenticator",
						http.StatusBadRequest)
				default:
					http.Error(w, "registration failed", http.StatusBadRequest)
				}
				return
			}
			u.passkeys = append(u.passkeys, record)
		})))
}

func ExampleRelyingParty_NewLogin() {
	rp, err := passkey.NewRelyingParty("example.com", "https://login.example.com",
		passkey.Options{})
	if err != nil {
		log.Fatal(err)
	}

	var requests sync.Map // request ID -> pending login request

	// The package-level example shows the complete flow, including the
	// client-side JavaScript and the registration endpoints.
	//
	// This endpoint begins a login ceremony.
	http.HandleFunc("GET /login/options", func(w http.ResponseWriter, r *http.Request) {
		request, optionsJSON, err := rp.NewLogin(passkey.LoginOptions{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		requests.Store(passkey.RequestID(request), request)
		// The client passes the options to
		// PublicKeyCredential.parseRequestOptionsFromJSON() and then to
		// navigator.credentials.get(), and posts the result's toJSON()
		// to the endpoint that calls [passkey.RelyingParty.Login].
		w.Header().Set("Cache-Control", "no-store")
		w.Write(optionsJSON)
	})
}

func ExampleRelyingParty_Login() {
	rp, err := passkey.NewRelyingParty("example.com", "https://login.example.com",
		passkey.Options{})
	if err != nil {
		log.Fatal(err)
	}

	// Stand-ins for the application's session and database.
	type user struct {
		username string
		passkeys []string
	}
	var userByUserID func(passkeyUserID string) (*user, error)
	var sessionSignIn func(rw http.ResponseWriter, username string)
	var requests sync.Map // request ID -> pending login request

	// The package-level example shows the complete flow, including the
	// client-side JavaScript and the registration endpoints.
	//
	// This endpoint signs the user in.
	//
	// CSRF protection prevents login CSRF, where a cross-site request with
	// the attacker's own passkey signs the browser into the attacker's account.
	http.Handle("POST /login", http.NewCrossOriginProtection().Handler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			responseJSON, _ := io.ReadAll(r.Body)
			response, err := passkey.ParseResponse(responseJSON)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
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
		})))
}
