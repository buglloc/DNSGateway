package commands

import (
	"context"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var startCmd = &cobra.Command{
	Use:           "start",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Starts server",
	RunE: func(_ *cobra.Command, _ []string) error {
		runtime, err := cfg.NewRuntime()
		if err != nil {
			return fmt.Errorf("create runtime: %w", err)
		}

		instance, err := runtime.NewListener()
		if err != nil {
			return fmt.Errorf("create gateway: %w", err)
		}

		errChan := make(chan error, 1)
		okChan := make(chan struct{})
		go func() {
			err := instance.ListenAndServe()
			if err != nil {
				errChan <- err
				return
			}

			close(okChan)
		}()

		stopChan := make(chan os.Signal, 1)
		signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-stopChan:
			log.Info().Msg("shutting down gracefully by signal")

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			return instance.Shutdown(ctx)
		case err := <-errChan:
			log.Error().Err(err).Msg("start failed")
			return err
		case <-okChan:
		}
		return nil
	},
}
