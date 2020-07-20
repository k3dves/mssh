package main

import (
	"bufio"
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
	fmt.Printf("\r")
	return password
}
func createClients(hostList []Host) []*ssh.Client {
	var clientList []*ssh.Client
	var password string = getCredentials()
	for _, host := range hostList {
		config := &ssh.ClientConfig{
			User: host.User,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		client, err := ssh.Dial("tcp", host.Hostname+":"+host.Port, config)
		if err != nil {
			fmt.Printf("[*]Error connecting host %s, ignoring.", host.Hostname)
		}
		clientList = append(clientList, client)
	}
	fmt.Printf("[*]Successfully Connected to %d hosts\n", len(clientList))
	return clientList
}

func getShell(connection *ssh.Client) (io.WriteCloser, io.Reader, io.Reader, error) {
	session, err := connection.NewSession()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Failed to create session: %s", err)
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		session.Close()
		return nil, nil, nil, fmt.Errorf("request for pseudo terminal failed: %s", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Unable to setup stdin for session: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Unable to setup stdout for session: %v", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Unable to setup stderr for session: %v", err)
	}
	err = session.Shell()
	if err != nil {
		return nil, nil, nil, err
	}
	return stdin, stdout, stderr, err
}

func main() {
	var stdinList []io.Writer
	var stdoutList, stderrList []io.Reader
	//b1 := &bytes.Buffer{}
	fmt.Println("[*]Welcome to mssh")
	pathPtr := flag.String("file", "hosts.json", "path to file")
	flag.Parse()
	hosts := readHostsFile(*pathPtr)
	clientList := createClients(hosts)
	//fmt.Println("[*]Connected to clients, spwaning shell:")
	for _, client := range clientList {
		stdin, stdout, stderr, err := getShell(client)
		if err != nil {
			panic(err)
		}
		stdinList = append(stdinList, stdin)
		stdoutList = append(stdoutList, stdout)
		stderrList = append(stderrList, stderr)

	}
	for {
		for _, r := range stdoutList {

			go io.Copy(os.Stdout, r)
			break
		}
		// CombinedShellOutput := io.MultiReader(stdoutList...)
		// fmt.Print(CombinedShellOutput)
		// go io.Copy(os.Stdout, CombinedShellOutput)
		//CombinedShellError := io.MultiReader(stderrList...)
		//go io.Copy(os.Stderr, CombinedShellError)
		reader := bufio.NewReader(os.Stdin)
		str, _ := reader.ReadString('\n')
		mw := io.MultiWriter(stdinList...)
		fmt.Fprintf(mw, str)

	}

}
