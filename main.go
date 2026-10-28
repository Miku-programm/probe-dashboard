// probe-dashboard 是 v2node 探测日志的独立分析面板：只读取 ClickHouse 里的数据，不依赖 v2node。
// 前端打包在二进制里，浏览器只访问本服务，ClickHouse 账号只在服务端使用。
package main

import (
	"flag"
	"log"
	"os"
)

func main() {
	var cfg Config
	flag.StringVar(&cfg.Listen, "listen", "127.0.0.1:8088", "listen address")
	flag.StringVar(&cfg.CHURL, "ch-url", "http://127.0.0.1:8123", "ClickHouse HTTP url")
	flag.StringVar(&cfg.CHDatabase, "ch-db", "v2node", "ClickHouse database")
	flag.StringVar(&cfg.CHTable, "ch-table", "probe_events", "ClickHouse table")
	flag.StringVar(&cfg.CHUser, "ch-user", "default", "ClickHouse user (read-only recommended)")
	flag.StringVar(&cfg.CHPassword, "ch-password", "", "ClickHouse password (or env CH_PASSWORD)")
	flag.StringVar(&cfg.AuthUser, "auth-user", "", "dashboard basic auth user")
	flag.StringVar(&cfg.AuthPassword, "auth-password", "", "dashboard basic auth password (or env DASH_PASSWORD)")
	flag.BoolVar(&cfg.AllowRawSQL, "raw-sql", false, "allow running custom SELECT queries from the dashboard")
	flag.Parse()
	if cfg.CHPassword == "" {
		cfg.CHPassword = os.Getenv("CH_PASSWORD")
	}
	if cfg.AuthPassword == "" {
		cfg.AuthPassword = os.Getenv("DASH_PASSWORD")
	}
	s, err := New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Run())
}
