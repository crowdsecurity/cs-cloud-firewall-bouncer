package main

import (
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"testing"

	"github.com/confluentinc/bincover"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var configPath = flag.String("bin-c", "config.yaml", "path to config file")

func TestMainMethod(t *testing.T) {
	log.Infof("Testing")

	c := make(chan os.Signal)
	signal.Notify(c)

	const binPath = "./cs-cloud-firewall-bouncer_instr-bin"
	// 1. Running a `go test` command to compile your instrumented binary.
	// This could also be done outside of the test suite, in a Makefile, for example.
	buildTestCmd := exec.Command("./compile-test.sh")
	output, err := buildTestCmd.CombinedOutput()
	if err != nil {
		log.Println(output)
		panic(err)
	}
	// 2. Initializing a `CoverageCollector`
	collector := bincover.NewCoverageCollector("integration.out", true)
	// 3. Calling `collector.Setup()` once before running all of your tests
	err = collector.Setup()
	require.NoError(t, err)

	go func() {
		<-c

		for sig := range c {
			log.Printf("captured %v, stopping profiler and exiting..", sig)
		}
		// 5. Calling `collector.TearDown()` after all the tests have finished
		err := collector.TearDown()
		if err != nil {
			panic(err)
		}
		// err = os.Remove(binPath)
		// if err != nil {
		// 	panic(err)
		// }
		log.Infof("Bye bye")
		os.Exit(0)
	}()

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
