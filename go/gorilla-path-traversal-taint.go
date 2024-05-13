package main

import (
	"net/http"
	"os"
	"path"
    "github.com/gorilla/sessions"
    "github.com/gorilla/schema"
    "github.com/gorilla/rpc"
    "github.com/gorilla/securecookie"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

func MyHandler(w http.ResponseWriter, r *http.Request) {
	// Get a session. Get() always returns a session, even if empty.
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

    email := session.Values["email"]

	d := http.Dir("/")
	// ruleid: gorilla-path-traversal-taint
	f, err := d.Open(email)

	sanpath := path.Join("/", email)
	// ok: gorilla-path-traversal-taint
	os.Open(sanpath)
}

// gorilla/schema
var decoder = schema.NewDecoder()

type Person struct {
    Name  string
    Phone string
}

func MyHandler(w http.ResponseWriter, r *http.Request) {
    var person Person
    err := decoder.Decode(&person, r.PostForm)


	// ruleid: gorilla-path-traversal-taint
	os.Open(person.Name)
}

// Gorilla securecookie

func ReadCookieHandler(w http.ResponseWriter, r *http.Request) {

    // Hash keys should be at least 32 bytes long
    var hashKey = []byte("very-secret")
    // Block keys should be 16 bytes (AES-128) or 32 bytes (AES-256) long.
    // Shorter keys may weaken the encryption used.
    var blockKey = []byte("a-lot-secret")
    var s = securecookie.New(hashKey, blockKey)

	if cookie, err := r.Cookie("cookie-name"); err == nil {

		value := make(map[string]string)
		err = s.Decode("cookie-name", cookie.Value, &value);
	    // ruleid: gorilla-path-traversal-taint
	    os.Open(value["foo"])

        var cookies = map[string]*securecookie.SecureCookie{
	        "previous": securecookie.New(
	        	securecookie.GenerateRandomKey(64),
	        	securecookie.GenerateRandomKey(32),
	        ),
	        "current": securecookie.New(
	        	securecookie.GenerateRandomKey(64),
	        	securecookie.GenerateRandomKey(32),
	        ),
        }

        err = securecookie.DecodeMulti("cookie-name", cookie.Value, &value, cookies["current"], cookies["previous"])
	    // ruleid: gorilla-path-traversal-taint
	    os.Open(value["foo"])

	}
}
