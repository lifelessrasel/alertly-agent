package collect

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
)

func TestParseCPULine(t *testing.T) {
	times := parseCPULine("cpu  100 5 50 800 20 0 10 15 7 0")

	if times.total != 1000 || times.idle != 820 {
		t.Fatalf("got total %d idle %d, want 1000 and 820", times.total, times.idle)
	}
}

func TestParseCPUStatReadsEachCore(t *testing.T) {
	content := "cpu  200 0 0 800 0 0 0 0\ncpu0 150 0 0 350 0 0 0 0\ncpu1 50 0 0 450 0 0 0 0\nintr 12345\n"

	aggregate, cores := parseCPUStat(bufio.NewScanner(strings.NewReader(content)))

	if aggregate.total != 1000 || len(cores) != 2 || cores[0].total != 500 || cores[1].idle != 450 {
		t.Fatalf("got %+v and %+v", aggregate, cores)
	}
	if percent, ok := busyPercent(cpuTimes{idle: 100, total: 200}, cpuTimes{idle: 150, total: 300}); !ok || percent != 50 {
		t.Fatalf("got %v %v, want 50 true", percent, ok)
	}
	if _, ok := busyPercent(cpuTimes{total: 300}, cpuTimes{total: 300}); ok {
		t.Fatal("expected no reading without elapsed time")
	}
}

func TestParseListeningSockets(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   112        0 20001 1 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20002 1 0
   2: 0A00000A:0016 0B00000A:D431 01 00000000:00000000 00:00000000 00000000     0        0 20003 1 0`
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 20004 1 0`
	udp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when ref pointer drops
  10: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 20005 2 0 0
  11: 0A00000A:9C40 0B00000A:0035 01 00000000:00000000 00:00000000 00000000   101        0 20006 2 0 0`

	got := append(parseListeningSockets(tcp, "tcp"), parseListeningSockets(tcp6, "tcp")...)
	got = append(got, parseListeningSockets(udp, "udp")...)

	want := []socketEntry{
		{address: "127.0.0.1", port: 3306, inode: "20001"},
		{address: "0.0.0.0", port: 22, inode: "20002"},
		{address: "::1", port: 80, inode: "20004"},
		{address: "127.0.0.53", port: 53, inode: "20005"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRankProcessesKeepsBusiestByCPUAndMemory(t *testing.T) {
	all := []TopProcess{
		{Name: "idle-cache", MemoryBytes: 900},
		{Name: "busy", CPUPercent: 80, MemoryBytes: 10},
		{Name: "medium", CPUPercent: 20, MemoryBytes: 20},
		{Name: "tiny", CPUPercent: 1, MemoryBytes: 1},
	}

	top := rankProcesses(all, 1)

	if len(top) != 2 || top[0].Name != "busy" || top[1].Name != "idle-cache" {
		t.Fatalf("got %+v, want busy then idle-cache", top)
	}
}

func TestProcessHelpers(t *testing.T) {
	if uid := statusUID("Name:\tnginx\nUid:\t33\t33\t33\t33\n"); uid != "33" {
		t.Fatalf("got uid %q, want 33", uid)
	}
	if users := readUsers("root:x:0:0::/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n"); users["33"] != "www-data" {
		t.Fatalf("got %v", users)
	}
	if !isKernelThread("2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0") || isKernelThread("1 (systemd) S 0 1 1 0 -1 4194560 0 0") {
		t.Fatal("unexpected kernel thread detection")
	}
}

func TestParseMeminfo(t *testing.T) {
	values := parseMeminfo("MemTotal:        2048 kB\nMemAvailable:    1024 kB\nHugePages_Total:       4\n")

	want := map[string]uint64{"MemTotal": 2048 * 1024, "MemAvailable": 1024 * 1024, "HugePages_Total": 4}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("got %v, want %v", values, want)
	}
}

func TestParseDiskstatsKeepsWholePhysicalDisks(t *testing.T) {
	content := `   8       0 sda 100 0 2000 50 200 0 4000 80 0 120 130 0 0 0 0
   8       1 sda1 90 0 1800 45 190 0 3800 75 0 110 120 0 0 0 0
   7       0 loop0 10 0 20 1 0 0 0 0 0 1 1 0 0 0 0
 253       0 dm-0 50 0 900 30 100 0 2000 40 0 60 70 0 0 0 0
 259       0 nvme0n1 5 0 64 1 6 0 128 2 0 3 3 0 0 0 0`
	whole := map[string]bool{"sda": true, "loop0": true, "dm-0": true, "nvme0n1": true}

	disks := parseDiskstats(content, func(name string) bool { return whole[name] })

	want := map[string]diskCounters{
		"sda":     {readSectors: 2000, writeSectors: 4000, ioMillis: 120},
		"nvme0n1": {readSectors: 64, writeSectors: 128, ioMillis: 3},
	}
	if !reflect.DeepEqual(disks, want) {
		t.Fatalf("got %v, want %v", disks, want)
	}
}

func TestParseNetDevSkipsLoopback(t *testing.T) {
	content := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 5000 10 0 0 0 0 0 0 5000 10 0 0 0 0 0 0
  eth0: 123456 100 0 0 0 0 0 0 654321 90 0 0 0 0 0 0`

	counters := parseNetDev(content)

	want := map[string]netCounters{"eth0": {rx: 123456, tx: 654321}}
	if !reflect.DeepEqual(counters, want) {
		t.Fatalf("got %v, want %v", counters, want)
	}
}

func TestParseMountsSortsAndUnescapes(t *testing.T) {
	content := "/dev/sdb1 /mnt/my\\040disk ext4 ro,relatime 0 0\n/dev/sda1 / ext4 rw,relatime 0 0\n"

	mounts := parseMounts(content)

	want := []mountEntry{
		{device: "/dev/sda1", path: "/", fsType: "ext4"},
		{device: "/dev/sdb1", path: "/mnt/my disk", fsType: "ext4", readOnly: true},
	}
	if !reflect.DeepEqual(mounts, want) {
		t.Fatalf("got %+v, want %+v", mounts, want)
	}
}

func TestParseProcStatHandlesParenthesesInName(t *testing.T) {
	name, ticks := parseProcStat("1234 (my (odd) app) S 1 1234 1234 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 1 0")

	if name != "my (odd) app" || ticks != 300 {
		t.Fatalf("got %q and %d ticks, want \"my (odd) app\" and 300", name, ticks)
	}
}

func TestUnitState(t *testing.T) {
	cases := map[[2]string]string{
		{"loaded", "active"}:      "running",
		{"loaded", "activating"}:  "running",
		{"loaded", "failed"}:      "failed",
		{"loaded", "inactive"}:    "stopped",
		{"not-found", "inactive"}: "missing",
	}

	for input, want := range cases {
		if got := unitState(input[0], input[1]); got != want {
			t.Errorf("unitState(%q, %q) = %q, want %q", input[0], input[1], got, want)
		}
	}
}

func TestOptionalUintTreatsSentinelsAsUnset(t *testing.T) {
	if optionalUint("[not set]") != nil || optionalUint("18446744073709551615") != nil {
		t.Fatal("expected unset values to be nil")
	}
	if value := optionalUint("4096"); value == nil || *value != 4096 {
		t.Fatalf("got %v, want 4096", value)
	}
}

func TestDetectedServiceFilter(t *testing.T) {
	for name, want := range map[string]bool{
		"nginx": true, "php8.3-fpm": true, "postgresql@16-main": true, "systemd-journald": false, "getty@tty1": false,
	} {
		if got := isInterestingService(name); got != want {
			t.Errorf("isInterestingService(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestContainerCPUAndMemory(t *testing.T) {
	var stats dockerStats
	stats.PreCPUStats.CPUUsage.TotalUsage = 1_000
	stats.PreCPUStats.SystemCPUUsage = 10_000
	stats.CPUStats.CPUUsage.TotalUsage = 3_000
	stats.CPUStats.SystemCPUUsage = 20_000

	if percent, ok := containerCPUPercent(stats); !ok || percent != 20 {
		t.Fatalf("got %v %v, want 20 true", percent, ok)
	}
	if memory := containerMemory(1000, map[string]uint64{"inactive_file": 300}); memory != 700 {
		t.Fatalf("got %d, want 700", memory)
	}
}

func TestZombiesNameTheirParents(t *testing.T) {
	state, ppid := procStateAndParent("4242 (php-fpm: pool www) Z 900 4242 4242 0 -1 4194564 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0")
	if state != "Z" || ppid != 900 {
		t.Fatalf("got state %q parent %d", state, ppid)
	}

	got := zombies([]processSample{
		{pid: 900, name: "php-fpm"},
		{pid: 901, ppid: 900, zombie: true, name: "php-fpm"},
		{pid: 902, ppid: 900, zombie: true, name: "php-fpm"},
		{pid: 903, ppid: 1, zombie: true, name: "sh"},
		{pid: 1, name: "systemd"},
		{pid: 904, ppid: 1, name: "nginx"},
	})
	want := &Zombies{Count: 3, Parents: []string{"php-fpm", "systemd"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
