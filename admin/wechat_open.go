package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

type wechatOpen struct {
	logger *logrus.Entry

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

func newWechatOpen(logger *logrus.Entry, appid, appSecret string) *wechatOpen {
	return &wechatOpen{
		logger:    logger,
		appid:     appid,
		appSecret: appSecret,
	}
}

// https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/user-login/code2Session.html
func (w *wechatOpen) code2Session(endpoint, jsCode string) (*wechatCode2SessionResponse, error) {
	authEndpoint := "https://api.weixin.qq.com/sns/jscode2session"

	if endpoint != "" {
		authEndpoint = endpoint
	}

	requestURL := fmt.Sprintf("%v?appid=%v&secret=%v&js_code=%v&grant_type=authorization_code", authEndpoint, w.appid, w.appSecret, jsCode)

	resp, err := http.Get(requestURL)
	if err != nil {
		w.logger.Errorf("wechat login error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		w.logger.Errorf("wechat login error: %v", err)
		return nil, err
	}

	var result wechatCode2SessionResponse
	if err = json.Unmarshal(body, &result); err != nil {
		w.logger.Errorf("wechat login error: %v", err)
		return nil, err
	}

	return &result, nil
}
