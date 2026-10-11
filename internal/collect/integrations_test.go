package collect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIntegrationsAreOffUntilConfigured(t *testing.T) {
	if checker := NewIntegrationChecker(IntegrationConfig{}); checker != nil {
		t.Fatal("expected no checker without configuration")
	}
	var checker *IntegrationChecker
	if checker.Collect(context.Background()) != nil {
		t.Fatal("a nil checker reports nothing")
	}
}

func TestParseNginxStatus(t *testing.T) {
	status, ok := parseNginxStatus("Active connections: 291 \nserver accepts handled requests\n 16630948 16630946 31070465 \nReading: 6 Writing: 179 Waiting: 106 \n")
	want := nginxStubStatus{active: 291, accepts: 16630948, handled: 16630946, requests: 31070465, reading: 6, writing: 179, waiting: 106}
	if !ok || status != want {
		t.Fatalf("got %+v (%v), want %+v", status, ok, want)
	}
	if _, ok := parseNginxStatus("<html>It works!</html>"); ok {
		t.Fatal("an ordinary page is not a status page")
	}
}

func TestParseTabbedValues(t *testing.T) {
	got := parseTabbedValues("Questions\t1200\nSlow_queries\t3\nThreads_connected\t12\nmax_connections\t151\n")
	want := map[string]uint64{"Questions": 1200, "Slow_queries": 3, "Threads_connected": 12, "max_connections": 151}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRedisLogsInAndReadsInfo(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	replies := []string{
		"# Memory\r\nused_memory:1048576\r\nmaxmemory:2097152\r\n# Clients\r\nconnected_clients:7\r\n# Stats\r\ninstantaneous_ops_per_sec:42\r\nkeyspace_hits:100\r\nkeyspace_misses:100\r\nevicted_keys:5\r\n",
		"used_memory:1048576\r\nmaxmemory:2097152\r\nconnected_clients:7\r\ninstantaneous_ops_per_sec:42\r\nkeyspace_hits:190\r\nkeyspace_misses:110\r\nevicted_keys:5\r\n",
	}
	go func() {
		for _, info := range replies {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			reader := bufio.NewReader(conn)
			if command := readRESP(reader); !reflect.DeepEqual(command, []string{"AUTH", "s3cret"}) {
				fmt.Fprint(conn, "-ERR expected AUTH\r\n")
				conn.Close()
				continue
			}
			fmt.Fprint(conn, "+OK\r\n")
			readRESP(reader)
			fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(info), info)
			conn.Close()
		}
	}()

	checker := NewIntegrationChecker(IntegrationConfig{RedisAddress: listener.Addr().String(), RedisPassword: "s3cret"})
	first := checker.Collect(context.Background()).Redis
	if !first.Up || first.UsedMemoryBytes != 1048576 || first.MaxMemoryBytes != 2097152 || first.Clients != 7 || first.OpsPerSecond != 42 || first.HitRatePercent != nil {
		t.Fatalf("first check: %+v", first)
	}

	second := checker.Collect(context.Background()).Redis
	if second.HitRatePercent == nil || *second.HitRatePercent != 90 || second.EvictedKeys == nil || *second.EvictedKeys != 0 {
		t.Fatalf("second check: %+v", second)
	}
}

func TestStatusPagesReportRatesFromTheSecondCheck(t *testing.T) {
	var nginxHits, fpmHits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nginx_status":
			fmt.Fprintf(w, "Active connections: 3\nserver accepts handled requests\n %d %d %d\nReading: 0 Writing: 1 Waiting: 2\n", 100, 100, 1000+nginxHits.Add(1)*50)
		case "/fpm-status":
			if _, ok := r.URL.Query()["json"]; !ok {
				http.Error(w, "missing json", http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, `{"pool":"www","listen queue":4,"idle processes":1,"active processes":9,"total processes":10,"max children reached":%d,"slow requests":0}`, fpmHits.Add(1)*2)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	checker := NewIntegrationChecker(IntegrationConfig{NginxStatusURL: server.URL + "/nginx_status", PHPFPMStatusURL: server.URL + "/fpm-status"})
	first := checker.Collect(context.Background())
	if !first.Nginx.Up || first.Nginx.Active != 3 || first.Nginx.RequestsPerSecond != nil {
		t.Fatalf("first nginx: %+v", first.Nginx)
	}
	if !first.PHPFPM.Up || first.PHPFPM.Pool != "www" || first.PHPFPM.ListenQueue != 4 || first.PHPFPM.MaxChildrenReached != nil {
		t.Fatalf("first php-fpm: %+v", first.PHPFPM)
	}

	second := checker.Collect(context.Background())
	if second.Nginx.RequestsPerSecond == nil || *second.Nginx.RequestsPerSecond <= 0 || *second.Nginx.Dropped != 0 {
		t.Fatalf("second nginx: %+v", second.Nginx)
	}
	if second.PHPFPM.MaxChildrenReached == nil || *second.PHPFPM.MaxChildrenReached != 2 {
		t.Fatalf("second php-fpm: %+v", second.PHPFPM)
	}
}

func TestUnreachableIntegrationsAreReportedDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	checker := NewIntegrationChecker(IntegrationConfig{NginxStatusURL: server.URL, RedisAddress: "127.0.0.1:1"})
	result := checker.Collect(context.Background())
	if result.Nginx.Up || result.Nginx.Error != "status page answered 403" {
		t.Fatalf("nginx: %+v", result.Nginx)
	}
	if result.Redis.Up || result.Redis.Error != "not reachable" {
		t.Fatalf("redis: %+v", result.Redis)
	}
}

func readRESP(reader *bufio.Reader) []string {
	header, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(header, "*") {
		return nil
	}
	var count int
	fmt.Sscanf(header, "*%d", &count)
	parts := make([]string, 0, count)
	for i := 0; i < count; i++ {
		var size int
		line, _ := reader.ReadString('\n')
		fmt.Sscanf(line, "$%d", &size)
		part := make([]byte, size+2)
		if _, err := io.ReadFull(reader, part); err != nil {
			return nil
		}
		parts = append(parts, string(part[:size]))
	}

	return parts
}
