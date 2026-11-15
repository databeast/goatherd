package cmd

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/databeast/goatherd/collector"
	"github.com/databeast/goatherd/internal/coordination"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func tlsFlags(command *cobra.Command) {
	command.Flags().String("tls-cert", "", "PEM certificate file")
	command.Flags().String("tls-key", "", "PEM private key file")
	command.Flags().String("tls-ca", "", "PEM certificate authority file")
}

func tlsOptions(cmd *cobra.Command, server bool) (credentials.TransportCredentials, error) {
	cert, err := cmd.Flags().GetString("tls-cert")
	if err != nil {
		return nil, err
	}
	key, err := cmd.Flags().GetString("tls-key")
	if err != nil {
		return nil, err
	}
	ca, err := cmd.Flags().GetString("tls-ca")
	if err != nil {
		return nil, err
	}
	var config *tls.Config
	if cert == "" && key == "" && ca == "" {
		config, err = coordination.EmbeddedTLSConfig(server)
	} else if cert == "" || key == "" || ca == "" {
		return nil, fmt.Errorf("--tls-cert, --tls-key and --tls-ca must be supplied together")
	} else {
		config, err = coordination.TLSConfig(cert, key, ca, server)
	}
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(config), nil
}

func connectCoordinator(cmd *cobra.Command) (*grpc.ClientConn, error) {
	addr, err := cmd.Flags().GetString("coordinator")
	if err != nil {
		return nil, err
	}
	if addr == "" {
		return nil, fmt.Errorf("--coordinator is required")
	}
	creds, err := tlsOptions(cmd, false)
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
}

func writeCoordinatorReports(w io.Writer, response *coordination.ReportsResponse) error {
	return coordination.WriteReportsJSON(w, response)
}

func runCoordinator(cmd *cobra.Command, _ []string) error {
	creds, err := tlsOptions(cmd, true)
	if err != nil {
		return err
	}
	addr, err := cmd.Flags().GetString("listen")
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	service := coordination.NewServer()
	server := grpc.NewServer(grpc.Creds(creds))
	coordination.RegisterCoordinatorServer(server, service)
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Coordinator listening on %s\n", listener.Addr()); err != nil {
		server.Stop()
		<-done
		return err
	}
	select {
	case err = <-done:
		if err != nil {
			return fmt.Errorf("coordinator server: %w", err)
		}
		return nil
	case <-ctx.Done():
		server.Stop()
		if err := <-done; err != nil {
			return fmt.Errorf("coordinator server: %w", err)
		}
		evidenceDump, err := cmd.Flags().GetBool("evidence")
		if err != nil {
			return err
		}
		return service.WriteReports(cmd.OutOrStdout(), evidenceDump)
	}
}

func runCoordinatorReports(cmd *cobra.Command, _ []string) error {
	conn, err := connectCoordinator(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()
	evidenceDump, err := cmd.Flags().GetBool("evidence")
	if err != nil {
		return err
	}
	stream, err := coordination.NewCoordinatorClient(conn).StreamReports(cmd.Context(), &coordination.ReportsRequest{Evidence: evidenceDump})
	if err != nil {
		return fmt.Errorf("retrieve reports: %w", err)
	}
	return writeReportsStream(cmd.OutOrStdout(), stream)
}

func writeReportsStream(w io.Writer, stream coordination.Coordinator_StreamReportsClient) error {
	received := false
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			if !received {
				return fmt.Errorf("coordinator returned an empty reports stream")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("retrieve reports: %w", err)
		}
		if len(chunk.Data) == 0 {
			return fmt.Errorf("coordinator returned an empty reports chunk")
		}
		received = true
		n, err := w.Write(chunk.Data)
		if err != nil {
			return fmt.Errorf("write reports: %w", err)
		}
		if n != len(chunk.Data) {
			return io.ErrShortWrite
		}
	}
}
func runCoordinatorInventory(cmd *cobra.Command, _ []string) error {
	conn, err := connectCoordinator(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()
	stream, err := coordination.NewCoordinatorClient(conn).Inventory(cmd.Context(), &coordination.InventoryRequest{})
	if err != nil {
		return fmt.Errorf("retrieve inventory: %w", err)
	}
	return writeInventoryStream(cmd.OutOrStdout(), stream)
}

func writeInventoryStream(w io.Writer, stream coordination.Coordinator_InventoryClient) error {
	received := false
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			if !received {
				return fmt.Errorf("coordinator returned an empty inventory")
			}
			_, err = fmt.Fprintln(w)
			return err
		}
		if err != nil {
			return fmt.Errorf("retrieve inventory: %w", err)
		}
		if len(chunk.Data) == 0 {
			return fmt.Errorf("coordinator returned an empty inventory chunk")
		}
		received = true
		n, err := w.Write(chunk.Data)
		if err != nil {
			return fmt.Errorf("write inventory: %w", err)
		}
		if n != len(chunk.Data) {
			return io.ErrShortWrite
		}
	}
}

func runRemoteCollector(cmd *cobra.Command, _ []string) error {
	conn, err := connectCoordinator(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()
	name, err := cmd.Flags().GetString("capture-point")
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("--capture-point is required")
	}
	filename, err := cmd.Flags().GetString("pcap")
	if err != nil {
		return err
	}
	iface, err := cmd.Flags().GetString("interface")
	if err != nil {
		return err
	}
	maxHops, err := cmd.Flags().GetUint8("max-hops")
	if err != nil {
		return err
	}
	macText, err := cmd.Flags().GetString("upstream-mac")
	if err != nil {
		return err
	}
	var mac net.HardwareAddr
	if macText != "" {
		mac, err = net.ParseMAC(macText)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
			return fmt.Errorf("invalid unicast Ethernet upstream MAC %q", macText)
		}
	}
	stream, err := coordination.NewCoordinatorClient(conn).Collect(cmd.Context())
	if err != nil {
		return fmt.Errorf("open observation stream: %w", err)
	}
	sink, err := collector.NewRemoteSink(stream, name, maxHops, mac)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	captureErr := collector.Observe(ctx, filename, iface, sink)
	result, streamErr := sink.Close()
	if captureErr != nil {
		if streamErr != nil {
			return fmt.Errorf("capture: %v; stream: %w", captureErr, streamErr)
		}
		return captureErr
	}
	if streamErr != nil {
		return streamErr
	}
	_, err = fmt.Fprintf(cmd.ErrOrStderr(), "Coordinator accepted %d observations\n", result.Observations)
	return err
}
