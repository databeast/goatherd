package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/databeast/goatherd/collector"
	"github.com/databeast/goatherd/internal/coordination"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func tlsFlags(command *cobra.Command) {
	command.Flags().String("tls-cert", "", "PEM certificate")
	command.Flags().String("tls-key", "", "PEM private key")
	command.Flags().String("tls-ca", "", "PEM certificate authority")
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
	if cert == "" || key == "" || ca == "" {
		return nil, fmt.Errorf("--tls-cert, --tls-key and --tls-ca are required")
	}
	config, err := coordination.TLSConfig(cert, key, ca, server)
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

type coordinatorReport struct {
	CapturePoint string          `json:"capture_point"`
	Report       json.RawMessage `json:"report,omitempty"`
	Error        string          `json:"error,omitempty"`
}

func writeCoordinatorReports(w io.Writer, response *coordination.ReportsResponse) error {
	reports := make([]coordinatorReport, 0, len(response.Reports))
	for _, report := range response.Reports {
		reports = append(reports, coordinatorReport{CapturePoint: report.CapturePoint, Report: report.ReportJson, Error: report.Error})
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(reports)
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
		reports, err := service.Reports(context.Background(), &coordination.ReportsRequest{})
		if err != nil {
			return err
		}
		return writeCoordinatorReports(cmd.OutOrStdout(), reports)
	}
}

func runCoordinatorReports(cmd *cobra.Command, _ []string) error {
	conn, err := connectCoordinator(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
	defer cancel()
	reports, err := coordination.NewCoordinatorClient(conn).Reports(ctx, &coordination.ReportsRequest{})
	if err != nil {
		return fmt.Errorf("retrieve reports: %w", err)
	}
	return writeCoordinatorReports(cmd.OutOrStdout(), reports)
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
