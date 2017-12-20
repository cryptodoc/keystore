package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Key struct {
	ID       string `json:"id"`
	Created  int64  `json:"created"`
	Expire   int64  `json:"expire"`
	Password string `json:"password"`
	Secret   string `json:"secret"`
	Code     string `json:"-"`
	Attempts int    `json:"-"`
}

type KeyRequest struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

type KeyResponse struct {
	ID       string `json:"id"`
	Created  int64  `json:"created"`
	Expire   int64  `json:"expire"`
	Password string `json:"password"`
}

var mux = sync.Mutex{}
var lifetime int64 = 15 * 60
var maxAttempts = 15
var timeout = time.Second
var keys = make(map[string]Key)

type App struct{}

func (h *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers",
			"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	}

	log.Println(r.Method, r.URL.Path)

	if r.Method == "OPTIONS" {
		fmt.Fprint(w, "")
		return
	} else {
		if r.URL.Path == "/" {
			if r.Method == "POST" {
				AddKey(w, r)
				return
			}
		} else {
			if r.Method == "GET" {
				GetKey(w, r)
				return
			}
		}
	}

	http.NotFound(w, r)
}

func AddKey(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	var keyReq KeyRequest

	err := decoder.Decode(&keyReq)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}

	defer r.Body.Close()
	now := time.Now().Unix()

	key := Key{}
	key.ID = uuid.New().String()
	key.Created = now
	key.Expire = now + lifetime
	key.Code = keyReq.Code
	key.Secret = RandStringBytesMask(32)
	key.Password = keyReq.Password

	if _, ok := keys[key.ID]; ok {
		http.Error(w, "Conflict", 410)
		return
	}

	mux.Lock()
	keys[key.ID] = key
	mux.Unlock()

	buf, err := json.Marshal(key)

	if err != nil {
		fmt.Fprint(w, err)
		return
	}

	fmt.Fprint(w, string(buf))
}

func GetKey(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[1:]

	token, sign := SplitAuthHeader(r.Header.Get("Authorization"))

	if token == "" {
		http.Error(w, "Invalid bearer", 403)
		return
	}

	if key, ok := keys[id]; ok {
		now := time.Now().Unix()
		nowStr := strconv.Itoa(int(now - now%15))

		tokenHash := HexHash([]byte(key.Code), []byte(nowStr))
		signHash := HexHash(tokenHash, []byte(key.Secret))

		if string(tokenHash) != token || string(signHash) != sign {
			key.Attempts++

			if key.Attempts >= maxAttempts {
				// Erase data
				key.Password = ""
				key.Code = ""

				mux.Lock()
				delete(keys, key.ID)
				mux.Unlock()
				http.NotFound(w, r)
				return
			}

			keys[id] = key

			http.Error(w, "Wrong code", 403)
			return
		}

		// Update expiration
		key.Expire = now + lifetime
		mux.Lock()
		keys[id] = key
		mux.Unlock()

		keyRes := KeyResponse{
			ID:       key.ID,
			Created:  key.Created,
			Expire:   key.Expire,
			Password: key.Password,
		}

		buf, err := json.Marshal(keyRes)

		if err != nil {
			log.Print("err:", err)
			http.Error(w, "Internal error", 500)
			return
		}

		fmt.Fprint(w, string(buf))
	} else {
		http.NotFound(w, r)
	}
}

func HexHash(parts ...[]byte) []byte {
	hash := sha256.New()

	for _, str := range parts {
		hash.Write(str)
	}

	hashed := hash.Sum(nil)

	dst := make([]byte, hex.EncodedLen(len(hashed)))
	hex.Encode(dst, hashed)

	return dst
}

func SplitAuthHeader(header string) (string, string) {
	i := strings.Index(header, "Bearer ")

	if i != 0 {
		return "", ""
	}

	tail := header[7:]

	i = strings.Index(tail, ".")

	if i <= 0 {
		return "", ""
	}

	return tail[:i], tail[i+1:]
}

// TODO Get strong random func
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
)

func RandStringBytesMask(n int) string {
	b := make([]byte, n)
	for i := 0; i < n; {
		if idx := int(rand.Int63() & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i++
		}
	}
	return string(b)
}

func main() {
	app := &App{}

	go (func() {
		for {
			now := time.Now().Unix()
			for id, key := range keys {
				if key.Expire < now || key.Attempts >= maxAttempts {
					mux.Lock()
					delete(keys, id)
					mux.Unlock()
				}
			}

			time.Sleep(timeout)
		}
	})()

	err := http.ListenAndServe("localhost:8080", app)
	if err != nil {
		log.Fatal(err)
	}
}
