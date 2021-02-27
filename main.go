package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/docker/docker/api/types"
	dockerClient "github.com/docker/docker/client"
	unofficialDockerClient "github.com/fsouza/go-dockerclient"
	"github.com/spf13/pflag"
)

const (
	IAM_CLIENT_ID = "IAM_CLIENT_ID"
	USERNAME      = "USERNAME"
)

var (
	logger                     = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	noValidUserContainerString = errors.New("Not a valid user.container string")
	noMatchFound               = errors.New("No match found")
	dockerImageFilter          = ""
)

// splitUserContainer splits the user field of the ssh command into the
// username and container name: eg. ssh username.containername@localhost
// username.containername -> [username, containername].
func splitUserContainer(str string) (client string, container string, err error) {
	if strings.Count(str, ".") != 1 {
		err = noValidUserContainerString
	} else {
		parts := strings.Split(str, ".")
		if len(parts) != 2 {
			err = noValidUserContainerString
		} else {
			client = parts[0]
			container = parts[1]
		}
	}

	return client, container, err
}

// checkContainerName verify if the passed str string is contained in the list
// names of the container.
func checkContainerName(str string, names []string) bool {
	for _, name := range names {
		if name[1:] == str {
			return true
		}
	}

	return false
}

// matchContainer checks a container with a specific docker image (dockerImageFilter)
// with a USERNAME of the ssh user passed and the requested container name,
// e.g. username.containerName (the target variable).
func matchContainer(target string) error { //nolint:cyclop
	targetUser, targetContainer, err := splitUserContainer(target) // username.containerName
	if err != nil {
		return fmt.Errorf("matchContainer: %w", err)
	}

	fmt.Printf("Finding %s:%s with filter %s\n", targetUser, targetContainer, dockerImageFilter)

	ctx := context.Background()
	cli, err := dockerClient.NewClientWithOpts(dockerClient.FromEnv, dockerClient.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("matchContainer: %w", err)
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return fmt.Errorf("matchContainer: %w", err)
	}

	for _, container := range containers {
		fmt.Println(container.ID, container.Names, container.Image)
		if strings.Contains(container.Image, dockerImageFilter) && checkContainerName(targetContainer, container.Names) {
			inspect, err := cli.ContainerInspect(ctx, container.ID)
			if err != nil {
				return fmt.Errorf("matchContainer: %w", err)
			}

			curIAMClientID := ""
			curUsername := ""

			for _, envVar := range inspect.Config.Env {
				switch {
				case strings.Contains(envVar, IAM_CLIENT_ID):
					curIAMClientID = strings.Split(envVar, "=")[1]
				case strings.Contains(envVar, USERNAME):
					curUsername = strings.Split(envVar, "=")[1]
				}
			}

			if curUsername != "" && curUsername == targetUser {
				// TODO: use the IAMClientID to retrieve the user key
				fmt.Printf("IAMClientID -> %s\n", curIAMClientID)

				return nil
			}
		}
	}

	return noMatchFound
}

func main() { //nolint:funlen,cyclop,gocognit
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
	pflag.StringVarP(&dockerImageFilter, "dockerImageFilter", "d", "dodasts/ml_infn", "default docker image to search for")
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

	server := &ssh.ServerConfig{ //nolint:exhaustivestruct
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// TODO: IAM
			// From match container it could be returned the IAMClientID to retrieve the user key
			// and check the identity given through ssh
			err := matchContainer(conn.User())

			fmt.Printf("match:%w\n", err)

			if err != nil {
				return nil, err
			}

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

	// Start the SSH server
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ListenAddr, config.Port))
	if err != nil {
		logger.Fatalln("failed to listen for connection: %w", err)
	}
	defer listener.Close()

	logger.Printf("Docker-sshd started, Listening %s:%d", config.ListenAddr, config.Port)

	// Loop to accept the SSH connections
	for {
		c, err := listener.Accept()
		if err != nil {
			logger.Printf("failed to accept connection: %v", err)

			continue
		}

		logger.Printf("connection accepted: %v", c.RemoteAddr())

		// Manage the accepted SSH connection
		go func() {
			sshConn, chans, reqs, err := ssh.NewServerConn(c, server)
			if err != nil {
				log.Fatal("failed to handshake: ", err)

				panic(err)
			}

			log.Printf("%+v | User:%s\n", sshConn, sshConn.User())

			// log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])

			// The incoming Request channel must be serviced but there is no
			// necessity to handle the reqs for the current program target
			go ssh.DiscardRequests(reqs)

			// Service the incoming Channel chans.
			for newChannel := range chans {
				log.Printf("channel: %+v\n", newChannel)
				// Manage only session channels.
				//
				// Channels have a type, depending on the application level
				// protocol intended. In the case of a shell, the type is
				// "session" and ServerShell may be used to present a simple
				// terminal interface.
				if newChannel.ChannelType() != "session" {
					err := newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
					if err != nil {
						panic(err)
					}

					continue
				}

				channel, requests, err := newChannel.Accept()
				if err != nil {
					log.Fatalf("Could not accept channel: %v", err)
				}

				log.Printf("channel accepted: %+v\n", channel)
				log.Printf("requests: %+v\n", requests)

				// Sessions have out-of-band requests such as "shell",
				// "pty-req" and "env".
				// TODO: better session management e.g. shell tty resize
				go func(in <-chan *ssh.Request) {
					for req := range in {
						log.Printf("req: %+v\n", req)

						switch req.Type {
						case "pty-req":
							req.Reply(true, nil)
						case "env":
							req.Reply(true, nil)
						case "shell":
							req.Reply(true, nil)
						default:
							log.Printf("unhandled req type %v", req.Type)
							req.Reply(true, nil)
						}
					}
				}(requests)

				// Prepare the connection to the container
				_, targetContainer, err := splitUserContainer(sshConn.User())
				if err != nil {
					panic(err)
				}

				// Create Docker client
				unofficialClient, err := unofficialDockerClient.NewClient(config.DockerEndpoint)
				if err != nil {
					log.Fatalln("Cannot connect to docker %w", err)
				}

				// Exec a command (/bin/bash as default) attaching the std streams and creating the TTY
				exec, err := unofficialClient.CreateExec(unofficialDockerClient.CreateExecOptions{ //nolint:exhaustivestruct
					Container:    targetContainer,
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

				// Start tre previous exec and attach the streams to the ssh channel for user interaction
				err = unofficialClient.StartExec(exec.ID, unofficialDockerClient.StartExecOptions{ //nolint:exhaustivestruct
					Detach:       false,
					OutputStream: channel,
					ErrorStream:  channel,
					InputStream:  channel,
					RawTerminal:  false,
				})

				// this call block until exec done
				exitStatus := -1

				if err == nil {
					exec, err := unofficialClient.InspectExec(exec.ID)

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

				//--------------------------------------------------------------
				// Working solution using official API
				// - Note: works only if the container already has a tty
				//
				// The flow is the following:
				// - Start a Docker client with the official API
				// - Create an exec command with bash to crete a TTY
				//
				// From here, there are two flow:
				// 1. If you use ContainerExecStart with the official API you can
				//    only attach to the output reader and not send any input
				//
				// 2. If you already have a valid TTY wish an opened shell, you
				//    can use ContainerAttach to attach the streams and manage the
				//    user input and output through the SSH connection
				//--------------------------------------------------------------

				/*
					ctx := context.Background()
					cli, err := dockerClient.NewClientWithOpts(dockerClient.FromEnv, dockerClient.WithAPIVersionNegotiation())
					if err != nil {
						panic(err)
					}

					// log.Printf("container exec create")
					// exec, err := cli.ContainerExecCreate(ctx, targetContainer, dockerTypes.ExecConfig{
					// 	AttachStdin:  true,
					// 	AttachStdout: true,
					// 	AttachStderr: true,
					// 	Detach:       true,
					// 	Tty:          true,
					// 	Cmd:          []string{config.Cmd},
					// })
					// if err != nil {
					// 	logger.Printf("failed to create docker exec: %v", err)
					// 	sshConn.Close()

					// 	return
					// }

					// log.Printf("container exec start")
					// err = cli.ContainerExecStart(ctx, exec.ID, types.ExecStartCheck{
					// 	Detach: true,
					// 	Tty:    true,
					// })
					// if err != nil {
					// 	panic(err)
					// }

					// inspectExec, err := cli.ContainerExecInspect(ctx, exec.ID)
					// if err != nil {
					// 	panic(err)
					// }

					// log.Printf("Exec running: %t -> pid: %d -> exit code: %d", inspectExec.Running, inspectExec.Pid, inspectExec.ExitCode)

					log.Printf("container attach")
					hijackConn, err := cli.ContainerAttach(ctx, targetContainer, types.ContainerAttachOptions{
						Stream: true,
						Stdin:  true,
						Stdout: true,
						Stderr: true,
					})
					// hijackConn, err := cli.ContainerExecAttach(ctx, exec.ID, types.ExecStartCheck{
					// 	Detach: true,
					// 	Tty:    true,
					// })
					if err != nil {
						panic(err)
					}

					go func() {
						defer hijackConn.Close()

						for {
							// log.Printf("wait read from output...")
							curByte, err := hijackConn.Reader.ReadByte()
							if err != nil {
								panic(err)
							}

							_, err = channel.Write([]byte{curByte})
							if err != nil {
								panic(err)
							}
						}
					}()

					go func() {
						defer hijackConn.Conn.Close()

						log.Printf("Start to read input...")
						hijackConn.Conn.Write([]byte("clear\n"))

						for {
							buffer := make([]byte, 1)

							// log.Printf("wait read from input...")
							_, err := channel.Read(buffer)
							if err != nil {
								panic(err)
							}

							// log.Printf("DATA[%d] %v", n, buffer)

							hijackConn.Conn.Write(buffer)
						}
					}()
				*/
				//--------------------------------------------------------------
			}
		}()
	}
}
