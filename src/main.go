package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// Host ..
type Host struct {
	Hostname string `json:"hostname"`
	Port     string `json:"port"`
	User     string `json:"user"`
}

// RemoteHostIO ..
type RemoteHostIO struct {
	ip      io.Writer
	op, er  io.Reader
	isValid bool
}

// RemoteHost ..
type RemoteHost struct {
	hostIO   RemoteHostIO
	hostInfo Host
}

func readHostsFile(path string) []Host {
	var hostList []Host
	jsonFile, err := os.Open(path)
	if err != nil {
		panic("Error reading the host file")
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal([]byte(byteValue), &hostList)
	return hostList
}

func showHosts(hostList []Host) {
	for _, host := range hostList {
		fmt.Printf("Host: %s User: %s Port: %s\n", host.Hostname, host.User, host.Port)
	}
}
func getCredentials() string {
	fmt.Printf("Enter Password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))

	password := string(bytePassword)
	//clear Enter Password from terminal
	fmt.Printf("\033[2K\r")
	return password
}

func connectClient(host Host, password string, c chan *ssh.Client) {
	config := &ssh.ClientConfig{
		User: host.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", host.Hostname+":"+host.Port, config)
	fmt.Printf("%s ", host.Port)
	if err != nil {
		fmt.Printf("[*]Error connecting host %s, ignoring.\n", host.Hostname)
		c <- nil
		return
	}
	c <- client
}

func initConnections(hostList []Host) []*ssh.Client {
	var clientList []*ssh.Client
	var password string = getCredentials()
	counter := len(hostList)
	var c = make(chan *ssh.Client, len(hostList))
	fmt.Printf("[*]Connecting to %d hosts: ", len(hostList))

	for _, host := range hostList {
		go connectClient(host, password, c)
	}
	for counter > 0 {
		rec := <-c
		clientList = append(clientList, rec)
		counter--
	}
	fmt.Printf("\n[*]Successfully Connected to %d hosts, launching shell\n", len(clientList))
	return clientList
}

func getShell(host Host, client *ssh.Client, c chan RemoteHost) {
	if client == nil {
		errIO := RemoteHostIO{nil, nil, nil, false}
		c <- RemoteHost{errIO, host}
		return
	}
	valid := true
	session, err := client.NewSession()
	if err != nil {
		valid = false
	}
	fd := int(os.Stdin.Fd())
	w, h, err := terminal.GetSize(fd)
	if err != nil {
		panic("error terminal get size")
	}
	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-color"
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.ECHOCTL:       0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty(term, h, w, modes); err != nil {
		session.Close()
		valid = false
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		valid = false
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		valid = false
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		valid = false
	}
	err = session.Shell()
	if err != nil {
		valid = false
	}
	if !valid {
		errIO := RemoteHostIO{nil, nil, nil, false}
		c <- RemoteHost{hostIO: errIO, hostInfo: host}
		return

	}
	rio := RemoteHostIO{ip: stdin, op: stdout, er: stderr, isValid: true}
	c <- RemoteHost{hostIO: rio, hostInfo: host}
}

func getSessions(clientList []*ssh.Client, hostList []Host) []RemoteHost {
	var hostSessions []RemoteHost
	c := make(chan RemoteHost, len(clientList))
	counter := len(clientList)
	for i, client := range clientList {
		go getShell(hostList[i], client, c)
	}
	for counter > 0 {
		rHost := <-c
		if rHost.hostIO.isValid {
			hostSessions = append(hostSessions, rHost)
		}
		counter--
	}
	return hostSessions
}

func getAllRemoteStdin(rhList []RemoteHost) []io.Writer {
	var list []io.Writer
	for _, host := range rhList {
		list = append(list, host.hostIO.ip)
	}
	return list
}

func preProcess(b []byte) {
	if int(b[0]) == 37 {
		print("Bye")
		b[0] = '%'
		//os.Exit(0)
	}
	//fmt.Println(b)
}
func main() {

	fmt.Println("[*]Welcome to mssh")
	pathPtr := flag.String("file", "hosts.json", "path to file")
	flag.Parse()
	hostList := readHostsFile(*pathPtr)
	clientList := initConnections(hostList)
	hostSessions := getSessions(clientList, hostList)
	remoteStdinList := getAllRemoteStdin(hostSessions)
	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(fd, state)
	for {
		for _, rhost := range hostSessions {

			go io.Copy(os.Stdout, rhost.hostIO.op)
			break
		}
		var b []byte = make([]byte, 1)
		mw := io.MultiWriter(remoteStdinList...)
		for {
			os.Stdin.Read(b)
			//preProcess(b)
			io.WriteString(mw, string(b))

		}

	}

}
