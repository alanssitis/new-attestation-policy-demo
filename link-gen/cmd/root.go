package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	link "github.com/in-toto/attestation/go/predicates/link/v0"
	ita "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	stepname  string
	keypath   string
    outputdir string
	materials []string
	products  []string
)

var rootcmd = &cobra.Command{
	Use:   "link-gen",
	Short: "CLI tool to generate basic links",
	Args:  cobra.MinimumNArgs(0),
	RunE:  run,
}

func init() {
	rootcmd.Flags().StringVarP(&stepname, "name", "n", "", "Name of link metadata.")
	rootcmd.Flags().StringVarP(&keypath, "key", "k", "", "Path of key to sign")
	rootcmd.Flags().StringVarP(&outputdir, "outdir", "o", "./", "Output directory")
	rootcmd.Flags().StringArrayVarP(&materials, "materials", "m", []string{}, "Path of key to sign")
	rootcmd.Flags().StringArrayVarP(&products, "products", "p", []string{}, "Path of key to sign")
	rootcmd.MarkFlagRequired("name")
	rootcmd.MarkFlagRequired("key")
}

func Execute() {
	err := rootcmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

func run(cmd *cobra.Command, fullCmd []string) error {
	materials, err := generateResourceDescriptorFromArtifacts(materials)
	if err != nil {
		return err
	}

	byproductsRaw, err := runCommand(fullCmd)
	if err != nil {
		return err
	}
	byproductsJSON, err := json.Marshal(byproductsRaw)
	if err != nil {
		return err
	}
	byproducts := &structpb.Struct{}
	err = protojson.Unmarshal(byproductsJSON, byproducts)
	if err != nil {
		return err
	}

	predicate := &link.Link{
		Name:       stepname,
		Command:    fullCmd,
		Materials:  materials,
		Byproducts: byproducts,
	}

	predJSON, err := protojson.Marshal(predicate)
	if err != nil {
		return err
	}
	predStruct := &structpb.Struct{}
	err = protojson.Unmarshal(predJSON, predStruct)
	if err != nil {
		return err
	}

	subject, err := generateResourceDescriptorFromArtifacts(products)
	if err != nil {
		return err
	}

	statement := &ita.Statement{
		Type:          ita.StatementTypeUri,
		Subject:       subject,
		PredicateType: "https://in-toto.io/attestation/link/v0.3",
		Predicate:     predStruct,
	}
	statementBytes, err := protojson.Marshal(statement)
	if err != nil {
		return err
	}

    k, err := signerverifier.LoadRSAPSSKeyFromFile(keypath)
	if err != nil {
		return err
	}
    sv, err := signerverifier.NewRSAPSSSignerVerifierFromSSLibKey(k)
	if err != nil {
		return err
	}
    signer, err := dsse.NewEnvelopeSigner(sv)
	if err != nil {
		return err
	}
    envelope, err := signer.SignPayload(context.TODO(), "application/vnd.in-toto+json", statementBytes)
	if err != nil {
		return err
	}
    envelopeJson, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

    if err = os.MkdirAll(outputdir,os.ModePerm); err != nil {
        return err
    }
	linkname := fmt.Sprintf("%s.%.8s.link", stepname, k.KeyID)
	linkpath := filepath.Join(outputdir, linkname)

	return ioutil.WriteFile(linkpath, envelopeJson, 0644)
}

func runCommand(fullCmd []string) (map[string]interface{}, error) {
	cmdByproduct := make(map[string]interface{})

	if len(fullCmd) < 1 {
		return nil, errors.New("should have a command to run for this to work")
	}
	cmd := exec.Command(fullCmd[0], fullCmd[1:]...)

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err = cmd.Start(); err != nil {
		return nil, err
	}

	stderr, err := io.ReadAll(stderrPipe)
	if err != nil {
		return nil, err
	}
	if stderr != nil && len(stderr) > 0 {
		cmdByproduct["stderr"] = string(stderr)
	}
	stdout, err := io.ReadAll(stdoutPipe)
	if err != nil {
		return nil, err
	}
	if stdout != nil && len(stdout) > 0 {
		cmdByproduct["stdout"] = string(stdout)
	}

	return cmdByproduct, nil
}

func generateResourceDescriptorFromArtifacts(artifacts []string) ([]*ita.ResourceDescriptor, error) {
	rds := make([]*ita.ResourceDescriptor, len(artifacts))
	h := sha256.New()
	for i, a := range artifacts {
		contents, err := os.ReadFile(a)
		if err != nil {
			return nil, err
		}
		h.Write(contents)
		rds[i] = &ita.ResourceDescriptor{
			Name:   a,
			Digest: map[string]string{"sha256": hex.EncodeToString(h.Sum(nil))},
		}
		h.Reset()
	}
	return rds, nil
}
