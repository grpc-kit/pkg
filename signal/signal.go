package signal

import (
	"os"
	"os/signal"
	"syscall"
)

// WaitQuit 阻塞进程，直到接收到信号: SIGHUP、SIGQUIT、SIGTERM、SIGINT
func WaitQuit() {
	ch := make(chan os.Signal, 1)

	// SIGINT  用户按中断键时产生，如：Ctrl+C
	// SIGQUIT 用户在终端上按退出键时产生，如：Ctrl+\
	// SIGTERM 是kill默认的信号，用于在进程退出之前做好清理工作（优雅退出）
	// SIGKILL SIGSTOP 信号是不能被捕获的
	//signal.Notify(ch, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	signal.Notify(ch)

	receiveQuit := false

	for {
		si := <-ch
		switch si {
		case syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
			receiveQuit = true
		default:
			// fmt.Println("ignore receive signal:", si.String())
		}

		if receiveQuit {
			signal.Stop(ch)
			break
		}
	}
}
