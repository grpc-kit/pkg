package admin

import (
	"io"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

func (a *AdminAPI) authLogin(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	// { code: 0, data: { token: 'xxx' }, message: '登录成功' }
	w.Write([]byte(`{ "code": 0, "data": { "token": "xxx" }, "message": "登录成功" }`))
}
