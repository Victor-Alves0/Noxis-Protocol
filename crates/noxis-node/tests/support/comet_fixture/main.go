// Command comet_fixture creates one short-lived, single-validator CometBFT
// home for the Noxis Unix integration test.  It deliberately uses CometBFT's
// own v0.38 types when calculating the consensus-parameter hash: re-encoding
// that protobuf in the Rust test would make the test validate two copies of a
// potentially divergent encoding instead of the engine boundary itself.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cometbft/cometbft/types"
)

const maximumBlockBytes int64 = 1_048_576

func main() {
	home := flag.String("home", "", "directory to initialize")
	cometBinary := flag.String("comet-binary", "", "pinned CometBFT executable")
	chainID := flag.String("chain-id", "", "non-empty chain id")
	abciAddress := flag.String("abci-address", "", "local ABCI endpoint")
	rpcAddress := flag.String("rpc-address", "", "local RPC endpoint")
	p2pAddress := flag.String("p2p-address", "", "local P2P endpoint")
	flag.Parse()

	for name, value := range map[string]string{
		"home": *home, "comet-binary": *cometBinary, "chain-id": *chainID,
		"abci-address": *abciAddress, "rpc-address": *rpcAddress, "p2p-address": *p2pAddress,
	} {
		if value == "" {
			failf("--%s is required", name)
		}
	}

	command := exec.Command(*cometBinary, "init", "--home", *home)
	if output, err := command.CombinedOutput(); err != nil {
		failf("CometBFT init failed: %v\n%s", err, output)
	}

	genesisPath := filepath.Join(*home, "config", "genesis.json")
	genesis, err := types.GenesisDocFromFile(genesisPath)
	if err != nil {
		failf("cannot read generated genesis: %v", err)
	}
	if len(genesis.Validators) != 1 {
		failf("expected one generated validator, got %d", len(genesis.Validators))
	}
	genesis.ChainID = *chainID
	genesis.InitialHeight = 1
	genesis.ConsensusParams.Block.MaxBytes = maximumBlockBytes
	if err := genesis.SaveAs(genesisPath); err != nil {
		failf("cannot write test genesis: %v", err)
	}

	// Reload through the official parser, so the exact document CometBFT will
	// use is the one that supplies both the validator and the protobuf bytes.
	genesis, err = types.GenesisDocFromFile(genesisPath)
	if err != nil {
		failf("cannot reload test genesis: %v", err)
	}
	parameters := genesis.ConsensusParams.ToProto()
	parameterBytes, err := parameters.Marshal()
	if err != nil {
		failf("cannot marshal CometBFT consensus parameters: %v", err)
	}
	parameterHash := sha256.Sum256(parameterBytes)

	configPath := filepath.Join(*home, "config", "config.toml")
	config, err := os.ReadFile(configPath)
	if err != nil {
		failf("cannot read generated CometBFT config: %v", err)
	}
	rewritten := string(config)
	rewritten = replaceRequired(rewritten, `proxy_app = "tcp://127.0.0.1:26658"`, `proxy_app = "tcp://`+*abciAddress+`"`)
	rewritten = replaceRequired(rewritten, `laddr = "tcp://127.0.0.1:26657"`, `laddr = "tcp://`+*rpcAddress+`"`)
	rewritten = replaceRequired(rewritten, `laddr = "tcp://0.0.0.0:26656"`, `laddr = "tcp://`+*p2pAddress+`"`)
	if err := os.WriteFile(configPath, []byte(rewritten), 0o600); err != nil {
		failf("cannot write local CometBFT config: %v", err)
	}

	fmt.Printf("chain_id=%s\n", genesis.ChainID)
	fmt.Printf("validator_key_hex=%s\n", hex.EncodeToString(genesis.Validators[0].PubKey.Bytes()))
	fmt.Printf("parameters_sha256_hex=%s\n", hex.EncodeToString(parameterHash[:]))
}

func replaceRequired(input, old, replacement string) string {
	if !strings.Contains(input, old) {
		failf("generated CometBFT config no longer contains %q", old)
	}
	return strings.Replace(input, old, replacement, 1)
}

func failf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
