package collect

import (
	"bufio"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// CPU is the busy share of all cores, and of each core.
type CPU struct {
	Percent float64   `json:"percent"`
	Cores   []float64 `json:"cores,omitempty"`
}

// Memory is RAM usage; used is total minus available.
type Memory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

// Swap is swap usage.
type Swap struct {
	TotalBytes uint64 `json:"total_bytes"`
	UsedBytes  uint64 `json:"used_bytes"`
}

// DiskIO is throughput summed over physical disks; utilization is the busiest disk.
type DiskIO struct {
	ReadBytesPerSec    uint64  `json:"read_bytes_per_sec"`
	WriteBytesPerSec   uint64  `json:"write_bytes_per_sec"`
	UtilizationPercent float64 `json:"utilization_percent"`
}

// Network is throughput summed over physical interfaces.
type Network struct {
	RxBytesPerSec uint64 `json:"rx_bytes_per_sec"`
	TxBytesPerSec uint64 `json:"tx_bytes_per_sec"`
}

// Filesystem is a mounted block-device filesystem.
type Filesystem struct {
	Mount       string `json:"mount"`
	Device      string `json:"device,omitempty"`
	FSType      string `json:"fs_type,omitempty"`
	TotalBytes  uint64 `json:"total_bytes"`
	UsedBytes   uint64 `json:"used_bytes"`
	InodesTotal uint64 `json:"inodes_total"`
	InodesUsed  uint64 `json:"inodes_used"`
	ReadOnly    *bool  `json:"read_only,omitempty"`
}

// Interface is a network interface with its addresses and throughput.
type Interface struct {
	Name          string   `json:"name"`
	MAC           string   `json:"mac,omitempty"`
	Addresses     []string `json:"addresses"`
	RxBytesPerSec uint64   `json:"rx_bytes_per_sec"`
	TxBytesPerSec uint64   `json:"tx_bytes_per_sec"`
}

type cpuTimes struct {
	idle, total uint64
}

type diskCounters struct {
	readSectors, writeSectors, ioMillis uint64
}

type netCounters struct {
	rx, tx uint64
}

// System keeps the previous counters needed to turn /proc totals into rates.
type System struct {
	lastAt   time.Time
	cpu      cpuTimes
	cores    []cpuTimes
	disks    map[string]diskCounters
	networks map[string]netCounters
}

// NewSystem creates a collector and records the first counters, so the next sample has rates.
func NewSystem() *System {
	s := &System{}
	s.cpu, s.cores, _ = readCPUTimes()
	s.disks = readDiskstats()
	s.networks = readNetDev()
	s.lastAt = time.Now()

	return s
}

// Rates returns CPU, disk, and network usage since the previous call.
func (s *System) Rates() (*CPU, *DiskIO, *Network, []Interface) {
	now := time.Now()
	elapsed := now.Sub(s.lastAt).Seconds()
	s.lastAt = now

	var cpu *CPU
	if times, cores, err := readCPUTimes(); err == nil {
		if percent, ok := busyPercent(s.cpu, times); ok {
			cpu = &CPU{Percent: percent}
			if len(cores) == len(s.cores) && len(cores) > 1 {
				cpu.Cores = make([]float64, len(cores))
				for i := range cores {
					cpu.Cores[i], _ = busyPercent(s.cores[i], cores[i])
				}
			}
		}
		s.cpu, s.cores = times, cores
	}

	disks := readDiskstats()
	var diskIO *DiskIO
	if elapsed > 0 && len(disks) > 0 {
		diskIO = &DiskIO{}
		for name, current := range disks {
			previous, ok := s.disks[name]
			if !ok {
				continue
			}
			diskIO.ReadBytesPerSec += rate(previous.readSectors, current.readSectors, elapsed) * 512
			diskIO.WriteBytesPerSec += rate(previous.writeSectors, current.writeSectors, elapsed) * 512
			busy := clampPercent(float64(delta(previous.ioMillis, current.ioMillis)) / (elapsed * 10))
			diskIO.UtilizationPercent = math.Max(diskIO.UtilizationPercent, busy)
		}
	}
	s.disks = disks

	counters := readNetDev()
	var network *Network
	var interfaces []Interface
	if elapsed > 0 {
		physical := physicalInterfaces(counters)
		network = &Network{}
		for name, current := range counters {
			previous, ok := s.networks[name]
			if !ok {
				continue
			}
			rx, tx := rate(previous.rx, current.rx, elapsed), rate(previous.tx, current.tx, elapsed)
			if physical[name] {
				network.RxBytesPerSec += rx
				network.TxBytesPerSec += tx
			}
		}
		interfaces = listInterfaces(counters, s.networks, elapsed)
	}
	s.networks = counters

	return cpu, diskIO, network, interfaces
}

// Load returns the 1, 5, and 15 minute load averages.
func Load() []float64 {
	fields := strings.Fields(readFile("/proc/loadavg"))
	if len(fields) < 3 {
		return nil
	}

	load := make([]float64, 3)
	for i := range load {
		load[i], _ = strconv.ParseFloat(fields[i], 64)
	}

	return load
}

// MemoryUsage returns RAM and swap usage.
func MemoryUsage() (*Memory, *Swap) {
	info, err := readMeminfo()
	if err != nil {
		return nil, nil
	}

	available, ok := info["MemAvailable"]
	if !ok {
		available = info["MemFree"] + info["Buffers"] + info["Cached"]
	}
	total := info["MemTotal"]

	return &Memory{TotalBytes: total, UsedBytes: total - min(available, total), AvailableBytes: available},
		&Swap{TotalBytes: info["SwapTotal"], UsedBytes: info["SwapTotal"] - min(info["SwapFree"], info["SwapTotal"])}
}

// ProcessCount counts the processes in /proc.
func ProcessCount() uint64 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	var count uint64
	for _, entry := range entries {
		if isPID(entry.Name()) {
			count++
		}
	}

	return count
}

// Uptime returns the seconds since boot.
func Uptime() uint64 {
	return uptimeSeconds()
}

var realFilesystems = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"jfs": true, "reiserfs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "bcachefs": true,
}

// Filesystems lists mounted disk filesystems. Network and virtual filesystems are skipped.
//
// The agent's systemd sandbox (ProtectSystem=strict) remounts everything read-only in the agent's
// own mount namespace, so /proc/self/mounts would report every disk as read-only. The host's
// mount table is read from PID 1 instead; without it, the read-only flag is left out.
func Filesystems() []Filesystem {
	content, hostView := readFile("/proc/1/mounts"), true
	if content == "" {
		content, hostView = readFile("/proc/self/mounts"), false
	}
	mounts := parseMounts(content)
	seen := map[string]bool{}
	filesystems := make([]Filesystem, 0, len(mounts))

	for _, mount := range mounts {
		if !realFilesystems[mount.fsType] || seen[mount.device] || len(filesystems) >= 64 {
			continue
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mount.path, &stat); err != nil || stat.Blocks == 0 {
			continue
		}
		seen[mount.device] = true

		blockSize := uint64(stat.Bsize)
		filesystem := Filesystem{
			Mount:       truncate(mount.path, 255),
			Device:      truncate(mount.device, 255),
			FSType:      truncate(mount.fsType, 32),
			TotalBytes:  stat.Blocks * blockSize,
			UsedBytes:   (stat.Blocks - min(stat.Bfree, stat.Blocks)) * blockSize,
			InodesTotal: stat.Files,
			InodesUsed:  stat.Files - min(stat.Ffree, stat.Files),
		}
		if hostView {
			filesystem.ReadOnly = &mount.readOnly
		}
		filesystems = append(filesystems, filesystem)
	}

	return filesystems
}

type mountEntry struct {
	device, path, fsType string
	readOnly             bool
}

// parseMounts reads /proc/mounts, shortest mount path first so bind mounts lose to the original.
func parseMounts(content string) []mountEntry {
	var mounts []mountEntry
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		options := "," + fields[3] + ","
		mounts = append(mounts, mountEntry{
			device:   unescapeMount(fields[0]),
			path:     unescapeMount(fields[1]),
			fsType:   fields[2],
			readOnly: strings.Contains(options, ",ro,"),
		})
	}

	for i := 1; i < len(mounts); i++ {
		for j := i; j > 0 && len(mounts[j].path) < len(mounts[j-1].path); j-- {
			mounts[j], mounts[j-1] = mounts[j-1], mounts[j]
		}
	}

	return mounts
}

// unescapeMount decodes the octal escapes /proc/mounts uses for spaces and tabs.
func unescapeMount(value string) string {
	if !strings.Contains(value, `\`) {
		return value
	}

	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+3 < len(value) {
			if code, err := strconv.ParseUint(value[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(code))
				i += 3
				continue
			}
		}
		out.WriteByte(value[i])
	}

	return out.String()
}

// busyPercent is the non-idle share of the time between two readings.
func busyPercent(previous, current cpuTimes) (float64, bool) {
	if current.total <= previous.total {
		return 0, false
	}
	total := current.total - previous.total
	idle := delta(previous.idle, current.idle)

	return clampPercent(100 * float64(total-min(idle, total)) / float64(total)), true
}

func readCPUTimes() (cpuTimes, []cpuTimes, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, nil, err
	}
	defer file.Close()

	aggregate, cores := parseCPUStat(bufio.NewScanner(file))

	return aggregate, cores, nil
}

// parseCPUStat reads the aggregate "cpu" line and the "cpuN" lines that follow it.
func parseCPUStat(scanner *bufio.Scanner) (cpuTimes, []cpuTimes) {
	var aggregate cpuTimes
	var cores []cpuTimes
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu") {
			break
		}
		if strings.HasPrefix(line, "cpu ") {
			aggregate = parseCPULine(line)
		} else if len(cores) < 1024 {
			cores = append(cores, parseCPULine(line))
		}
	}

	return aggregate, cores
}

// parseCPULine parses the aggregate "cpu" line of /proc/stat. Guest time is already part of user time.
func parseCPULine(line string) cpuTimes {
	fields := strings.Fields(line)
	var times cpuTimes
	for i, field := range fields {
		if i == 0 || i > 8 {
			continue
		}
		value, _ := strconv.ParseUint(field, 10, 64)
		times.total += value
		if i == 4 || i == 5 {
			times.idle += value
		}
	}

	return times
}

func readMeminfo() (map[string]uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil, err
	}

	return parseMeminfo(string(data)), nil
}

// parseMeminfo returns /proc/meminfo values in bytes.
func parseMeminfo(content string) map[string]uint64 {
	values := map[string]uint64{}
	for _, line := range strings.Split(content, "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] == "kB" {
			value *= 1024
		}
		values[key] = value
	}

	return values
}

func readDiskstats() map[string]diskCounters {
	return parseDiskstats(readFile("/proc/diskstats"), func(name string) bool {
		_, err := os.Stat("/sys/block/" + name)
		return err == nil
	})
}

// parseDiskstats keeps whole physical disks. Partitions, loop, RAM, device-mapper, and md devices
// are skipped because their I/O is already counted on the underlying disk.
func parseDiskstats(content string, isWholeDisk func(string) bool) map[string]diskCounters {
	disks := map[string]diskCounters{}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 13 {
			continue
		}
		name := fields[2]
		if hasAnyPrefix(name, "loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd") || !isWholeDisk(name) {
			continue
		}
		readSectors, _ := strconv.ParseUint(fields[5], 10, 64)
		writeSectors, _ := strconv.ParseUint(fields[9], 10, 64)
		ioMillis, _ := strconv.ParseUint(fields[12], 10, 64)
		disks[name] = diskCounters{readSectors: readSectors, writeSectors: writeSectors, ioMillis: ioMillis}
	}

	return disks
}

func readNetDev() map[string]netCounters {
	return parseNetDev(readFile("/proc/net/dev"))
}

// parseNetDev reads byte counters from /proc/net/dev, skipping the loopback interface.
func parseNetDev(content string) map[string]netCounters {
	counters := map[string]netCounters{}
	for _, line := range strings.Split(content, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		fields := strings.Fields(rest)
		if name == "lo" || len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		counters[name] = netCounters{rx: rx, tx: tx}
	}

	return counters
}

func isVirtualInterface(name string) bool {
	return hasAnyPrefix(name, "veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "vxlan", "kube", "lxc", "tap", "dummy")
}

// physicalInterfaces picks the interfaces whose traffic counts toward the server total: those backed
// by a device, or every non-virtual interface when none are (some containers and VPS hosts).
func physicalInterfaces(counters map[string]netCounters) map[string]bool {
	physical := map[string]bool{}
	for name := range counters {
		if _, err := os.Stat("/sys/class/net/" + name + "/device"); err == nil {
			physical[name] = true
		}
	}
	if len(physical) == 0 {
		for name := range counters {
			if !isVirtualInterface(name) {
				physical[name] = true
			}
		}
	}

	return physical
}

func listInterfaces(counters, previous map[string]netCounters, elapsed float64) []Interface {
	system, err := net.Interfaces()
	if err != nil {
		return nil
	}

	interfaces := make([]Interface, 0, len(system))
	for _, iface := range system {
		if iface.Flags&net.FlagLoopback != 0 || isVirtualInterface(iface.Name) || len(interfaces) >= 64 {
			continue
		}

		item := Interface{Name: truncate(iface.Name, 64), Addresses: []string{}}
		if len(iface.HardwareAddr) == 6 {
			item.MAC = iface.HardwareAddr.String()
		}
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if len(item.Addresses) < 16 {
					item.Addresses = append(item.Addresses, truncate(addr.String(), 64))
				}
			}
		}
		if current, ok := counters[iface.Name]; ok {
			if last, ok := previous[iface.Name]; ok {
				item.RxBytesPerSec = rate(last.rx, current.rx, elapsed)
				item.TxBytesPerSec = rate(last.tx, current.tx, elapsed)
			}
		}
		interfaces = append(interfaces, item)
	}

	return interfaces
}

// delta is current minus previous, or 0 when the counter was reset.
func delta(previous, current uint64) uint64 {
	if current < previous {
		return 0
	}

	return current - previous
}

func rate(previous, current uint64, seconds float64) uint64 {
	if seconds <= 0 {
		return 0
	}

	return uint64(float64(delta(previous, current)) / seconds)
}

func clampPercent(value float64) float64 {
	if math.IsNaN(value) || value < 0 {
		return 0
	}

	return math.Round(math.Min(value, 100)*100) / 100
}

func hasAnyPrefix(value string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	return false
}

func isPID(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

func truncate(value string, length int) string {
	if len(value) <= length {
		return value
	}

	return value[:length]
}
