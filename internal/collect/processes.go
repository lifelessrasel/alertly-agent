package collect

import (
	"encoding/hex"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TopProcess is a group of processes with the same name and user. Only names are reported:
// command lines and environments can hold secrets.
type TopProcess struct {
	Name        string  `json:"name"`
	User        string  `json:"user,omitempty"`
	Count       uint64  `json:"count"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryBytes uint64  `json:"memory_bytes"`
}

// Zombies are exited processes their parent hasn't reaped. Parents names the processes that should reap them.
type Zombies struct {
	Count   uint64   `json:"count"`
	Parents []string `json:"parents,omitempty"`
}

// ListeningPort is a socket accepting connections or datagrams.
type ListeningPort struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Address  string `json:"address,omitempty"`
	Process  string `json:"process,omitempty"`
}

const (
	topProcessesPerRanking = 10
	maxZombieParents       = 10
	maxListeningPorts      = 100
)

// Processes keeps per-process CPU counters between samples.
type Processes struct {
	lastAt   time.Time
	ticks    map[int]uint64
	pageSize uint64
	users    map[string]string
}

// NewProcesses creates a process collector and records the first counters.
func NewProcesses() *Processes {
	p := &Processes{pageSize: uint64(os.Getpagesize()), users: readUsers(readFile("/etc/passwd"))}
	p.ticks = map[int]uint64{}
	for _, process := range p.scan() {
		p.ticks[process.pid] = process.cpuTicks
	}
	p.lastAt = time.Now()

	return p
}

type processSample struct {
	pid      int
	ppid     int
	zombie   bool
	name     string
	uid      string
	cpuTicks uint64
	rssBytes uint64
	sockets  []string
}

// Top returns the busiest process groups by CPU and by memory, the listening ports and the zombie processes.
func (p *Processes) Top() ([]TopProcess, []ListeningPort, *Zombies) {
	now := time.Now()
	elapsed := now.Sub(p.lastAt).Seconds()
	p.lastAt = now

	processes := p.scan()
	ticks := make(map[int]uint64, len(processes))
	groups := map[[2]string]*TopProcess{}
	socketOwners := map[string]string{}

	for _, process := range processes {
		ticks[process.pid] = process.cpuTicks
		for _, inode := range process.sockets {
			socketOwners[inode] = process.name
		}

		user := p.users[process.uid]
		if user == "" {
			user = process.uid
		}
		key := [2]string{process.name, user}
		group, ok := groups[key]
		if !ok {
			group = &TopProcess{Name: truncate(process.name, 64), User: truncate(user, 32)}
			groups[key] = group
		}
		group.Count++
		group.MemoryBytes += process.rssBytes
		if previous, ok := p.ticks[process.pid]; ok && elapsed > 0 {
			group.CPUPercent += float64(delta(previous, process.cpuTicks)) / clockTicks / elapsed * 100
		}
	}
	p.ticks = ticks

	all := make([]TopProcess, 0, len(groups))
	for _, group := range groups {
		group.CPUPercent = float64(int64(group.CPUPercent*10+0.5)) / 10
		all = append(all, *group)
	}

	return rankProcesses(all, topProcessesPerRanking), listeningPorts(socketOwners), zombies(processes)
}

// zombies counts the zombie processes and names their parents.
func zombies(processes []processSample) *Zombies {
	names := make(map[int]string, len(processes))
	for _, process := range processes {
		names[process.pid] = process.name
	}

	result := &Zombies{}
	for _, process := range processes {
		if !process.zombie {
			continue
		}
		result.Count++
		parent := truncate(names[process.ppid], 64)
		if parent != "" && len(result.Parents) < maxZombieParents && !containsString(result.Parents, parent) {
			result.Parents = append(result.Parents, parent)
		}
	}

	return result
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}

	return false
}

// rankProcesses keeps the top n groups by CPU plus the top n by memory, busiest CPU first.
func rankProcesses(all []TopProcess, n int) []TopProcess {
	sort.Slice(all, func(i, j int) bool {
		if all[i].MemoryBytes != all[j].MemoryBytes {
			return all[i].MemoryBytes > all[j].MemoryBytes
		}
		return all[i].Name < all[j].Name
	})
	keep := map[[2]string]bool{}
	for i := 0; i < len(all) && i < n; i++ {
		keep[[2]string{all[i].Name, all[i].User}] = true
	}

	sort.SliceStable(all, func(i, j int) bool { return all[i].CPUPercent > all[j].CPUPercent })
	top := make([]TopProcess, 0, n*2)
	for i, process := range all {
		if i < n || keep[[2]string{process.Name, process.User}] {
			top = append(top, process)
		}
	}

	return top
}

func (p *Processes) scan() []processSample {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	processes := make([]processSample, 0, len(entries))
	for _, entry := range entries {
		if !isPID(entry.Name()) {
			continue
		}
		pid, _ := strconv.Atoi(entry.Name())
		dir := "/proc/" + entry.Name()

		stat := readFile(dir + "/stat")
		if stat == "" {
			continue
		}
		name, ticks := parseProcStat(stat)
		if name == "" || isKernelThread(stat) {
			continue
		}

		state, ppid := procStateAndParent(stat)
		process := processSample{pid: pid, ppid: ppid, zombie: state == "Z", name: name, cpuTicks: ticks, uid: statusUID(readFile(dir + "/status"))}
		if fields := strings.Fields(readFile(dir + "/statm")); len(fields) > 1 {
			pages, _ := strconv.ParseUint(fields[1], 10, 64)
			process.rssBytes = pages * p.pageSize
		}
		process.sockets = socketInodes(dir + "/fd")
		processes = append(processes, process)
	}

	return processes
}

// procStateAndParent returns the state letter and parent PID from a /proc/<pid>/stat line.
func procStateAndParent(stat string) (string, int) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return "", 0
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 2 {
		return "", 0
	}
	ppid, _ := strconv.Atoi(fields[1])

	return fields[0], ppid
}

// isKernelThread reports whether a /proc/<pid>/stat line belongs to a kernel thread (PF_KTHREAD).
func isKernelThread(stat string) bool {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return false
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 7 {
		return false
	}
	flags, _ := strconv.ParseUint(fields[6], 10, 64)

	return flags&0x00200000 != 0
}

// statusUID returns the real user ID from /proc/<pid>/status.
func statusUID(status string) string {
	for _, line := range strings.Split(status, "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if fields := strings.Fields(rest); len(fields) > 0 {
				return fields[0]
			}
		}
	}

	return ""
}

// readUsers maps user IDs to names from /etc/passwd.
func readUsers(passwd string) map[string]string {
	users := map[string]string{}
	for _, line := range strings.Split(passwd, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 2 && fields[0] != "" {
			if _, exists := users[fields[2]]; !exists {
				users[fields[2]] = fields[0]
			}
		}
	}

	return users
}

// socketInodes lists the socket inodes a process holds. Other users' descriptors aren't readable,
// so their ports are reported without a process name.
func socketInodes(fdDir string) []string {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}

	var inodes []string
	for _, entry := range entries {
		target, err := os.Readlink(fdDir + "/" + entry.Name())
		if err != nil {
			continue
		}
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			inodes = append(inodes, strings.TrimSuffix(inode, "]"))
		}
	}

	return inodes
}

type socketEntry struct {
	address string
	port    int
	inode   string
}

func listeningPorts(owners map[string]string) []ListeningPort {
	seen := map[string]bool{}
	ports := []ListeningPort{}
	for _, source := range []struct{ protocol, path string }{
		{"tcp", "/proc/net/tcp"}, {"tcp", "/proc/net/tcp6"}, {"udp", "/proc/net/udp"}, {"udp", "/proc/net/udp6"},
	} {
		for _, socket := range parseListeningSockets(readFile(source.path), source.protocol) {
			key := source.protocol + "|" + socket.address + "|" + strconv.Itoa(socket.port)
			if seen[key] || len(ports) >= maxListeningPorts {
				continue
			}
			seen[key] = true
			ports = append(ports, ListeningPort{
				Protocol: source.protocol,
				Port:     socket.port,
				Address:  socket.address,
				Process:  truncate(owners[socket.inode], 64),
			})
		}
	}

	sort.SliceStable(ports, func(i, j int) bool {
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}
		return ports[i].Protocol < ports[j].Protocol
	})

	return ports
}

// parseListeningSockets reads /proc/net/{tcp,udp}[6]. TCP sockets in LISTEN state and unconnected
// UDP sockets bound to a port count as listening.
func parseListeningSockets(content, protocol string) []socketEntry {
	var sockets []socketEntry
	for i, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 10 {
			continue
		}
		state := fields[3]
		if protocol == "tcp" && state != "0A" {
			continue
		}
		if protocol == "udp" && (state != "07" || !strings.HasSuffix(fields[2], ":0000")) {
			continue
		}

		address, port, ok := parseSocketAddress(fields[1])
		if !ok || port == 0 {
			continue
		}
		sockets = append(sockets, socketEntry{address: address, port: port, inode: fields[9]})
	}

	return sockets
}

// parseSocketAddress decodes "0100007F:0035": the address is stored as 32-bit words in host (little-endian) order.
func parseSocketAddress(value string) (string, int, bool) {
	hexAddress, hexPort, ok := strings.Cut(value, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(hexAddress)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}

	ip := make(net.IP, len(raw))
	for word := 0; word < len(raw); word += 4 {
		for b := 0; b < 4; b++ {
			ip[word+b] = raw[word+3-b]
		}
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	return ip.String(), int(port), true
}
