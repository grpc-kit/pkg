package admin

import (
	"context"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

func (a *KnownAdminAPI) authLogin(w http.ResponseWriter, r *http.Request) {
	authreq := adminv1.AuthLoginRequest{}

	xxx, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	defer r.Body.Close()

	err = protojson.Unmarshal(xxx, &authreq)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	hashPass, err := bcrypt.GenerateFromPassword([]byte(authreq.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	x, err := a.config.db.Users.Create().
		SetPreferredUsername(authreq.Username).
		Save(context.TODO())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	a.config.db.UserAuthLocal.Create().
		SetUserID(x.ID).
		SetPasswordHash(hashPass).
		SetMfaSecretEncrypted([]byte("hell world")).
		Save(context.TODO())

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	// { code: 0, data: { token: 'xxx' }, message: '登录成功' }
	w.Write([]byte(`{ "code": 0, "data": { "token": "xxx" }, "message": "登录成功" }`))
}
