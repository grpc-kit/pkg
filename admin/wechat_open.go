package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

type wechatOpen struct {
	logger *slog.Logger

	appid     string
	appSecret string
}

type wechatCode2SessionResponse struct {
	SessionKey string `json:"session_key"`
	Unionid    string `json:"unionid"`
	Errmsg     string `json:"errmsg"`
	Openid     string `json:"openid"`
	Errcode    int32  `json:"errcode"`
}

func newWechatOpen(logger *slog.Logger, appid, appSecret string) *wechatOpen {
	return &wechatOpen{
		logger:    logger,
		appid:     appid,
		appSecret: appSecret,
	}
}

// https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/user-login/code2Session.html
func (w *wechatOpen) code2Session(ctx context.Context, endpoint, jsCode string) (*wechatCode2SessionResponse, error) {
	authEndpoint := "https://api.weixin.qq.com/sns/jscode2session"

	if endpoint != "" {
		authEndpoint = endpoint
	}

	requestURL := fmt.Sprintf("%v?appid=%v&secret=%v&js_code=%v&grant_type=authorization_code", authEndpoint, w.appid, w.appSecret, jsCode)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		w.logger.ErrorContext(ctx, "wechat login error", "operation", "build_request", "error", err)
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.logger.ErrorContext(ctx, "wechat login error", "operation", "send_request", "error", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		w.logger.ErrorContext(ctx, "wechat login error", "operation", "read_response", "error", err)
		return nil, err
	}

	var result wechatCode2SessionResponse
	if err = json.Unmarshal(body, &result); err != nil {
		w.logger.ErrorContext(ctx, "wechat login error", "operation", "decode_response", "error", err)
		return nil, err
	}

	return &result, nil
}
