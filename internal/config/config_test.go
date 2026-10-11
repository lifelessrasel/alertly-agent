package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yml")
	content := "# written by install.sh\nendpoint: \"https://alertly.example/api/v1/\"\ntoken: \"alr_secret\"\ndocker: true\nlogs: false\ndownload_url: https://downloads.example/agent/\n" +
		"mysql_user: alertly\nmysql_password: 'p:ss'\nredis: 127.0.0.1:6379\nnginx_status_url: http://127.0.0.1/nginx_status\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	want := Config{
		Endpoint: "https://alertly.example/api/v1", Token: "alr_secret", Docker: true, Logs: false, DownloadURL: "https://downloads.example/agent",
		MySQLUser: "alertly", MySQLPassword: "p:ss", Redis: "127.0.0.1:6379", NginxStatusURL: "http://127.0.0.1/nginx_status",
	}
	if cfg != want {
		t.Fatalf("got %+v, want %+v", cfg, want)
	}
}

func TestLoadRequiresEndpointAndToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yml")
	if err := os.WriteFile(path, []byte("docker: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error")
	}
}
