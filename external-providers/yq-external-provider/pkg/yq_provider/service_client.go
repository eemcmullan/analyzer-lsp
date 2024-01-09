package yq_provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"github.com/konveyor/analyzer-lsp/jsonrpc2"
	"github.com/konveyor/analyzer-lsp/lsp/protocol"
	"github.com/konveyor/analyzer-lsp/provider"
	"go.lsp.dev/uri"
	"gopkg.in/yaml.v2"
)

type yqServiceClient struct {
	rpc        *jsonrpc2.Conn
	cancelFunc context.CancelFunc
	log        logr.Logger
	cmd        *exec.Cmd

	config       provider.InitConfig
	capabilities protocol.ServerCapabilities
}

var _ provider.ServiceClient = &yqServiceClient{}

func (p *yqServiceClient) Stop() {
	p.cancelFunc()
	p.cmd.Wait()
}

func (p *yqServiceClient) Evaluate(ctx context.Context, cap string, conditionInfo []byte) (provider.ProviderEvaluateResponse, error) {
	var cond yqCondition
	err := yaml.Unmarshal(conditionInfo, &cond)
	if err != nil {
		return provider.ProviderEvaluateResponse{}, fmt.Errorf("unable to get query info")
	}

	// TODO: update
	query := []string{"image"}

	values, err := p.GetAllValuesForKey(ctx, query)
	if err != nil {
		return provider.ProviderEvaluateResponse{}, fmt.Errorf("can't find any value for query: %v, error=%v", query, err)
	}

	incidents := []provider.IncidentContext{}
	incidentsMap := make(map[string]provider.IncidentContext) // To remove duplicates
	for _, v := range values {
		if v.ImageTag.Value == "latest" {
			u, err := uri.Parse(v.URI)
			if err != nil {
				return provider.ProviderEvaluateResponse{}, err
			}
			lineNumber, _ := strconv.Atoi(v.ImageTag.LineNumber)
			incident := provider.IncidentContext{
				FileURI:    u,
				LineNumber: &lineNumber,
				Variables: map[string]interface{}{
					"imageTag": v.ImageTag.Value,
				},
			}
			b, _ := json.Marshal(incident)
			incidentsMap[string(b)] = incident
		}
	}

	for _, incident := range incidentsMap {
		incidents = append(incidents, incident)
	}

	if len(incidents) == 0 {
		// No results were found.
		return provider.ProviderEvaluateResponse{Matched: false}, nil
	}
	return provider.ProviderEvaluateResponse{
		Matched:   true,
		Incidents: incidents,
	}, nil
}

func (p *yqServiceClient) GetAllValuesForKey(ctx context.Context, query []string) ([]k8sOutput, error) {
	var results []k8sOutput
	var wg sync.WaitGroup
	var mu sync.Mutex

	matchingYAMLFiles, err := provider.FindFilesMatchingPattern(p.config.Location, "*.yaml")
	if err != nil {
		fmt.Printf("unable to find any YAML files: %v\n", err)
	}
	matchingYMLFiles, err := provider.FindFilesMatchingPattern(p.config.Location, "*.yml")
	if err != nil {
		fmt.Printf("unable to find any YML files: %v\n", err)
	}
	matchingYAMLFiles = append(matchingYAMLFiles, matchingYMLFiles...)

	for _, file := range matchingYAMLFiles {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()

			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading YAML file '%s': %v\n", file, err)
				return
			}

			cmd := p.ConstructYQCommand(query)
			result, err := p.ExecuteCmd(cmd, string(data))
			if err != nil {
				p.log.V(5).Error(err, "Error running 'yq' command")
				return
			}
			mu.Lock()
			defer mu.Unlock()

			for _, output := range result {
				var currentResult k8sOutput
				result := strings.Split(strings.TrimSpace(output), "\n")

				tag := strings.SplitAfter(result[0], ":")
				currentResult.ImageTag = k8skey{
					Value:      tag[1],
					LineNumber: result[1],
				}
				absPath, err := filepath.Abs(file)
				if err != nil {
					p.log.V(5).Error(err, "error getting abs path of yaml file")
				}
				fileURL := url.URL{
					Scheme: "file",
					Path:   absPath,
				}

				fileURI := fileURL.String()
				currentResult.URI = fileURI

				results = append(results, currentResult)
			}
		}(file)
	}

	wg.Wait()
	return results, nil
}

func (p *yqServiceClient) ExecuteCmd(cmd *exec.Cmd, input string) ([]string, error) {
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error running command= %s, error= %s, stdError= %v", cmd, err, stderr)
	}

	output := strings.Split(stdout.String(), "---")
	return output, nil
}

func (p *yqServiceClient) ConstructYQCommand(query []string) *exec.Cmd {

	yqCmd := &exec.Cmd{
		Path:   p.cmd.Path,
		Args:   append([]string(nil), p.cmd.Args...),
		Env:    append([]string(nil), p.cmd.Env...),
		Stdin:  p.cmd.Stdin,
		Stdout: p.cmd.Stdout,
		Stderr: p.cmd.Stderr,
	}

	var queryString string

	// TODO better query this is just for PoC
	queryString += fmt.Sprintf(".spec.template.spec.containers[0].image, .spec.template.spec.containers[0].image | line,")
	queryString = strings.TrimSuffix(queryString, ",")

	yqCmd.Args = append(yqCmd.Args, queryString)

	return yqCmd
}
