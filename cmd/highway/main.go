package main

import (
	"bytes"
	"flag"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"

	"git.gammaspectra.live/P2Pool/monero-highway/internal/highway"
	"github.com/goccy/go-yaml"
)

func main() {

	configPath := flag.String("config", "highway.yaml", "path to config file")

	flag.Parse()

	if buildInfo, _ := debug.ReadBuildInfo(); buildInfo != nil {
		slog.Info("Monero Highway", "version", buildInfo.Main.Version, "go", buildInfo.GoVersion, "os", runtime.GOOS, "arch", runtime.GOARCH, "cpu", runtime.NumCPU())
	}

	config := highway.Configuration{
		State: highway.DefaultStateConfig,
	}

	configData, err := os.ReadFile(*configPath)
	if err != nil {
		slog.Error("Error reading config file", "path", *configPath, "error", err)
		panic(err)
	}

	if err = yaml.NewDecoder(bytes.NewReader(configData), yaml.UseJSONUnmarshaler()).Decode(&config); err != nil {
		slog.Error("Error parsing config file", "path", *configPath, "error", err)
		panic(err)
	}

	slog.Info("Loaded config file", "path", *configPath)

	consensusId := config.State.Id()

	{
		// obscure consensus id
		consensusIdBuf := []byte(consensusId.String())
		const obscureN = 10
		for i := range consensusIdBuf[obscureN : len(consensusIdBuf)-obscureN] {
			consensusIdBuf[obscureN+i] = '*'
		}
		slog.Info("Consensus state",
			"id", string(consensusIdBuf),
			"keep-depth", config.State.KeepDepth,
			"checkpoint-depth", config.State.CheckpointDepth,
			"checkpoint-separation", config.State.CheckpointSeparation,
			"checkpoint-keep-count", config.State.CheckpointKeepCount,
			"checkpoint-last-epochs", config.State.CheckpointLastEpochs,
		)
	}

	if len(config.FixedCheckpoints) > 0 {
		slog.Info("Loaded fixed checkpoints", "count", len(config.FixedCheckpoints))
	}

	if err = config.Verify(); err != nil {
		slog.Error("Error verifying config file", "path", *configPath, "error", err)
		panic(err)
	}

}
