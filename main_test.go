package main

import (
	"flag"
	"os"
	"os/exec"
	"testing"

	"github.com/confluentinc/bincover"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var configPath = flag.String("bin-c", "", "path to config file")

func TestMainMethod(t *testing.T) {
	log.Infof("Testing")

	const binPath = "./cs-cloud-firewall-bouncer_instr-bin"
	// 1. Running a `go test` command to compile the instrumented binary.
	buildTestCmd := exec.Command("./compile_instr_bin.sh")
	output, err := buildTestCmd.CombinedOutput()
	if err != nil {
		log.Println(output)
		panic(err)
	}
	// 2. Initializing a `CoverageCollector`
	collector := bincover.NewCoverageCollector("integration.out", true)
	// 3. Calling `collector.Setup()` once before running all of the tests
	err = collector.Setup()
	require.NoError(t, err)

	defer func() {
		// 5. Calling `collector.TearDown()` after all the tests have finished
		err := collector.TearDown()
		if err != nil {
			panic(err)
		}
		err = os.Remove(binPath)
		if err != nil {
			panic(err)
		}
	}()

	// 4. Running each test with the instrumented binary by calling `collector.RunBinary(binPath, mainTestName, env, args)`
	outputBin, exitCode, err := collector.RunBinary(binPath, "TestBincoverRunMain", []string{}, []string{"-c", *configPath})
	log.Infof("Finish test with %s: %d", outputBin, exitCode)
	require.NoError(t, err)

}
