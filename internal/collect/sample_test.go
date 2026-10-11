package collect

import "testing"

func TestSwitchesStayOnUnlessTurnedOff(t *testing.T) {
	var none Switches
	if !none.On("processes") {
		t.Error("everything should be on before the dashboard sends switches")
	}

	switches := Switches{"processes": false, "ports": true}
	if switches.On("processes") {
		t.Error("processes were turned off")
	}
	if !switches.On("ports") || !switches.On("docker") {
		t.Error("kinds turned on or not mentioned should stay on")
	}
}
