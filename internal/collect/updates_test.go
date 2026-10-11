package collect

import "testing"

func TestParseAptSimulation(t *testing.T) {
	output := `Reading package lists...
Building dependency tree...
The following packages will be upgraded:
  libssl3 openssl curl
Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-security [amd64])
Inst openssl [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-security [amd64])
Inst curl [7.81.0-1ubuntu1.16] (7.81.0-1ubuntu1.18 Ubuntu:22.04/jammy-updates [amd64])
Conf libssl3 (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-security [amd64])`

	if pending, security := parseAptSimulation(output); pending != 3 || security != 2 {
		t.Fatalf("got %d pending and %d security, want 3 and 2", pending, security)
	}
}

func TestParseDnfCheckUpdate(t *testing.T) {
	output := `
kernel.x86_64                          5.14.0-427.el9            baseos
openssl-libs.x86_64                    1:3.0.7-27.el9            baseos

Obsoleting Packages
grub2-tools.x86_64                     1:2.06-77.el9             baseos
`

	if count := parseDnfCheckUpdate(output); count != 2 {
		t.Fatalf("got %d, want 2", count)
	}
}

func TestParseDnfSecurityList(t *testing.T) {
	output := `RHSA-2024:1234 Important/Sec. openssl-libs-1:3.0.7-27.el9.x86_64
RHSA-2024:1235 Moderate/Sec.  openssl-libs-1:3.0.7-27.el9.x86_64
RHSA-2024:1300 Important/Sec. kernel-5.14.0-427.el9.x86_64`

	if count := parseDnfSecurityList(output); count != 2 {
		t.Fatalf("got %d, want 2", count)
	}
}
