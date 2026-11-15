package coordination

import (
	"fmt"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestConcurrentCaptureRegistration(t *testing.T) {
	server := NewServer()
	const count = 64
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := server.register(&Registration{CapturePoint: fmt.Sprintf("point-%d", i)})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(server.points) != count || server.nextID != count {
		t.Fatalf("registered %d points, next ID %d", len(server.points), server.nextID)
	}
}

func TestConcurrentDuplicateRegistration(t *testing.T) {
	server := NewServer()
	const count = 16
	var wg sync.WaitGroup
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := server.register(&Registration{CapturePoint: "same"})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if status.Code(err) != codes.AlreadyExists {
			t.Fatal(err)
		}
	}
	if successes != 1 || len(server.points) != 1 {
		t.Fatalf("got %d successes and %d points", successes, len(server.points))
	}
}
