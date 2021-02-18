package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/spf13/pflag"
)

var (
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
)

func main() { //nolint:funlen,cyclop
	config := struct {
		ListenAddr     string
		Port           uint
		KeyFile        string
		ShowHelp       bool
		ShowVersion    bool
		DockerEndpoint string
		Cmd            string
	}{}

	pflag.StringVarP(&config.DockerEndpoint, "host", "H", "unix:///var/run/docker.sock", "docker host socket")
	pflag.StringVarP(&config.ListenAddr, "listen_addr", "l", "0.0.0.0", "Listening Address")
	pflag.UintVarP(&config.Port, "port", "p", 2232, "Listening Port")
	pflag.StringVarP(&config.KeyFile, "server_key", "i", "/etc/ssh/ssh_host_rsa_key", "Key file for docker-sshd")
	pflag.StringVarP(&config.Cmd, "command", "c", "/bin/bash", "default exec command")
	pflag.BoolVarP(&config.ShowHelp, "help", "h", false, "Print help and exit")

	pflag.BoolVar(&config.ShowVersion, "version", false, "Print version and exit")

	pflag.Parse()

	if config.ShowHelp {
		pflag.PrintDefaults()

		return
	} else if config.ShowVersion {
		log.Println("Beta version")

		return
	}

	client, err := docker.NewClient(config.DockerEndpoint)
	if err != nil {
		logger.Fatalln("Cannot connect to docker %w", err)
	}

	if err := client.Ping(); err != nil {
		logger.Println("WARNING ping docker failed")
	}

	server := &ssh.ServerConfig{ //nolint:exhaustivestruct
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// TODO: IAM?
			return nil, nil
		},
	}

	privateBytes, err := ioutil.ReadFile(config.KeyFile)
	if err != nil {
		logger.Fatalln(err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		logger.Fatalln(err)
	}

	server.AddHostKey(private)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ListenAddr, config.Port))
	if err != nil {
		logger.Fatalln("failed to listen for connection: %w", err)
	}
	defer listener.Close()

	logger.Printf("Docker-sshd started, Listening %s:%d", config.ListenAddr, config.Port)

	for {
		c, err := listener.Accept()
		if err != nil {
			logger.Printf("failed to accept connection: %v", err)

			continue
		}

		logger.Printf("connection accepted: %v", c.RemoteAddr())

		go func() {
			sshConn, chans, reqs, err := ssh.NewServerConn(c, server)
			if err != nil {
				logger.Printf("failed to establish ssh connection: %v", err)

				return
			}

			exec, err := client.CreateExec(docker.CreateExecOptions{ //nolint:exhaustivestruct
				Container:    sshConn.User(),
				AttachStdin:  true,
				AttachStdout: true,
				AttachStderr: true,
				Tty:          true,
				Cmd:          []string{config.Cmd},
			})
			if err != nil {
				logger.Printf("failed to create docker exec: %v", err)
				sshConn.Close()

				return
			}

			go handleRequests(reqs)
			// Accept all channels
			go handleChannels(client, exec.ID, chans)
		}()
	}
}

func handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.Type == "keepalive@openssh.com" {
			err := req.Reply(true, nil)
			if err != nil {
				panic(err)
			}

			continue
		}

		logger.Printf("received out-of-band request: %+v", req)
	}
}

func handleChannels(client *docker.Client, execID string, chans <-chan ssh.NewChannel) { //nolint:funlen,gocognit,cyclop
	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Since we're handling the execution of a shell, we expect a
		// channel type of "session". However, there are also: "x11", "direct-tcpip"
		// and "forwarded-tcpip" channel types.
		if t := newChannel.ChannelType(); t != "session" {
			err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			if err != nil {
				panic(err)
			}

			continue
		}

		// At this point, we have the opportunity to reject the client's
		// request for another logical connection
		channel, requests, err := newChannel.Accept()
		if err != nil {
			logger.Printf("could not accept channel (%s)", err)

			continue
		}

		go func() {
			err := client.StartExec(execID, docker.StartExecOptions{ //nolint:exhaustivestruct
				Detach:       false,
				OutputStream: channel,
				ErrorStream:  channel,
				InputStream:  channel,
				RawTerminal:  false,
			})

			// this call block until exec done
			exitStatus := -1

			if err == nil {
				exec, err := client.InspectExec(execID)

				if err == nil {
					exitStatus = exec.ExitCode
				}
			}

			_, err = channel.SendRequest("exit-status", false, ssh.Marshal(&struct{ uint32 }{uint32(exitStatus)}))
			if err != nil {
				panic(err)
			}

			channel.Close()

			logger.Printf("session closed")
		}()

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		// https://tools.ietf.org/html/rfc4254#
		// TODO more implementations

		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false

				switch req.Type {
				case "shell":
					if len(req.Payload) == 0 {
						ok = true
					}

				case "pty-req":
					// Responding 'ok' here will let the client
					// know we have a pty ready for input
					ok = true

					msg := struct {
						Term   string
						Width  uint32
						Height uint32
					}{}

					err := ssh.Unmarshal(req.Payload, &msg)
					if err != nil {
						panic(err)
					}

					err = client.ResizeExecTTY(execID, int(msg.Height), int(msg.Width))
					if err != nil {
						panic(err)
					}

					logger.Printf("pty-req '%v' %v * %v", msg.Term, msg.Height, msg.Width)

				case "window-change":
					msg := struct {
						Width  uint32
						Height uint32
					}{}

					err := ssh.Unmarshal(req.Payload, &msg)
					if err != nil {
						panic(err)
					}

					err = client.ResizeExecTTY(execID, int(msg.Height), int(msg.Width))
					if err != nil {
						panic(err)
					}

					logger.Printf("windows-changed %v * %v", msg.Height, msg.Width)

					// find way for this
					// case "env":

					//	msg := struct {
					//		Name  string
					//		Value string
					//	}{}

					//	ssh.Unmarshal(req.Payload, &msg)

					//    fmt.Println(msg)
				default:
					logger.Printf("unhandled req type %v", req.Type)
				}

				if req.WantReply {
					err := req.Reply(ok, nil)
					if err != nil {
						panic(err)
					}
				}
			}
		}(requests)
	}
}
