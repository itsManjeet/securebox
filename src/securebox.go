package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// SecureBoxConfig type
type SecureBoxConfig struct {
	Name     string   `json:"name"`
	Roots    string   `json:"roots"`
	Shared   []string `json:"shared"`
	Unshared []string `json:"unshared"`
	MaxPIDS  string   `json:"maxpids"`
	Startup  []string `json:"startup"`
}

func main() {

	configFileData, err := ioutil.ReadFile("securebox.json")
	if err != nil {
		log.Println(err.Error())
	}

	var boxConfig SecureBoxConfig
	err = json.Unmarshal(configFileData, &boxConfig)
	if err != nil {
		log.Println(err)
	}

	fmt.Println(boxConfig.Startup)

	switch os.Args[1] {
	case "run":
		parent(boxConfig)

	case "child":
		child(boxConfig)

	default:
		panic("[run|child] to start docker")
	}
}

func parent(boxConfig SecureBoxConfig) {
	log.Printf("executing: %v\n", boxConfig.Startup)

	cmd := exec.Command(
		"/proc/self/exe", append([]string{"child"}, boxConfig.Startup...)...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cloneflags := generateflags(boxConfig.Shared)
	unshareflags := generateflags(boxConfig.Unshared)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:   cloneflags,
		Unshareflags: unshareflags,
	}

	cmd.Run()
}

func child(boxConfig SecureBoxConfig) {

	log.Printf("running inside new UTS namespace: %v\n", boxConfig.Startup)
	log.Printf("PID: %d\n", os.Getpid())

	setupCG(boxConfig)

	syscall.Sethostname([]byte("securebox"))

	log.Println("switching roots")

	if err := syscall.Chroot("roots"); err != nil {
		log.Println("error while switching root", err)
		os.Exit(1)
	}
	if err := syscall.Chdir("/"); err != nil {
		log.Println("error while switching dir", err)
		os.Exit(1)
	}

	syscall.Mount("proc", "proc", "proc", 0, "")

	cmd := exec.Command(boxConfig.Startup[0], boxConfig.Startup[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Run()
}

func setupCG(boxConfig SecureBoxConfig) {

	cgroups := "/sys/fs/cgroup/"
	pids := filepath.Join(cgroups, "pids")
	os.Mkdir(filepath.Join(pids, "securebox"), 0755)

	log.Println("settings max pids", boxConfig.MaxPIDS)
	ioutil.WriteFile(filepath.Join(pids, "securebox/pids.max"),
		[]byte(boxConfig.MaxPIDS), 0700)

	ioutil.WriteFile(filepath.Join(pids, "securebox/notify_on_release"),
		[]byte("1"), 0700)

	ioutil.WriteFile(filepath.Join(pids,
		"securebox/cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0700)

}

func generateflags(data []string) uintptr {
	var flag uintptr = 0
	for _, ns := range data {
		switch ns {
		case "uts":
			flag = flag | syscall.CLONE_NEWUTS
		case "pid":
			flag = flag | syscall.CLONE_NEWPID
		case "ns":
			flag = flag | syscall.CLONE_NEWNS
		case "ipc":
			flag = flag | syscall.CLONE_NEWIPC
		case "net":
			flag = flag | syscall.CLONE_NEWNET
		case "user":
			flag = flag | syscall.CLONE_NEWUSER
		}
	}

	return flag
}
