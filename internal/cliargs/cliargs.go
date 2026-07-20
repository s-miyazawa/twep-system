// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cliargs

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/s-miyazawa/twep-system/internal/cborcodec"
)

const maxNegaPosiInputBytes = 16 * 1024 * 1024

type BuildResult struct {
	Request    cborcodec.Request
	OutputPath string
}

func BuildRequest(command string, argv []string, appInputHex string, appInputFile string, outputFormat string) (BuildResult, error) {
	if command == "" {
		return BuildResult{}, fmt.Errorf("missing command")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return BuildResult{}, fmt.Errorf("get cwd: %w", err)
	}
	var appInput []byte
	if appInputHex != "" && appInputFile != "" {
		return BuildResult{}, fmt.Errorf("--cbor-hex and --cbor-file are mutually exclusive")
	}
	if appInputHex != "" {
		appInput, err = hex.DecodeString(appInputHex)
		if err != nil {
			return BuildResult{}, fmt.Errorf("decode --cbor-hex: %w", err)
		}
	}
	if appInputFile != "" {
		appInput, err = os.ReadFile(appInputFile)
		if err != nil {
			return BuildResult{}, fmt.Errorf("read --cbor-file: %w", err)
		}
	}
	req := cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     cborcodec.NewRequestID(),
		Command:       command,
		Argv:          argv,
		Inferred:      cborcodec.InferArgv(argv),
		AppInput:      appInput,
		Cwd:           cwd,
		Options: cborcodec.RequestOptions{
			OutputFormat: outputFormat,
		},
	}
	var outputPath string
	if command == "negaposi" && appInput == nil {
		inputPath, outPath, err := parseNegaPosiPaths(argv)
		if err != nil {
			return BuildResult{}, err
		}
		if err := validateInputJPEGPath(inputPath); err != nil {
			return BuildResult{}, err
		}
		if err := validateOutputJPEGPath(outPath); err != nil {
			return BuildResult{}, err
		}
		inputBytes, err := os.ReadFile(inputPath)
		if err != nil {
			return BuildResult{}, fmt.Errorf("read input JPEG: %w", err)
		}
		if len(inputBytes) > maxNegaPosiInputBytes {
			return BuildResult{}, fmt.Errorf("input JPEG exceeds %d bytes", maxNegaPosiInputBytes)
		}
		if !looksLikeJPEG(inputBytes) {
			return BuildResult{}, fmt.Errorf("input file is not a JPEG")
		}
		req.Files = map[string][]byte{"input": inputBytes}
		req.Metadata = map[string]any{
			"input_mime":       "image/jpeg",
			"input_path_hint":  inputPath,
			"output_path_hint": outPath,
		}
		outputPath = outPath
	}
	return BuildResult{Request: req, OutputPath: outputPath}, nil
}

func parseNegaPosiPaths(argv []string) (string, string, error) {
	var inputPath string
	var outputPath string
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "-i", "--input":
			i++
			if i >= len(argv) || argv[i] == "" {
				return "", "", fmt.Errorf("negaposi requires an input path after %s", argv[i-1])
			}
			inputPath = argv[i]
		case "-o", "--output":
			i++
			if i >= len(argv) || argv[i] == "" {
				return "", "", fmt.Errorf("negaposi requires an output path after %s", argv[i-1])
			}
			outputPath = argv[i]
		default:
			return "", "", fmt.Errorf("unsupported negaposi argument %q", argv[i])
		}
	}
	if inputPath == "" || outputPath == "" {
		return "", "", fmt.Errorf("negaposi requires -i INPUT.jpg and -o OUTPUT.jpg")
	}
	return inputPath, outputPath, nil
}

func validateInputJPEGPath(path string) error {
	if err := validateJPEGPath(path, "input"); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat input JPEG: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("input path must be a regular file")
	}
	if info.Size() > maxNegaPosiInputBytes {
		return fmt.Errorf("input JPEG exceeds %d bytes", maxNegaPosiInputBytes)
	}
	return nil
}

func validateOutputJPEGPath(path string) error {
	if err := validateJPEGPath(path, "output"); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return fmt.Errorf("output path is a directory")
	}
	return nil
}

func validateJPEGPath(path string, role string) error {
	if path == "" || strings.ContainsRune(path, 0) {
		return fmt.Errorf("%s path is invalid", role)
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".jpg" && ext != ".jpeg" {
		return fmt.Errorf("%s path must end in .jpg or .jpeg", role)
	}
	return nil
}

func looksLikeJPEG(bytes []byte) bool {
	return len(bytes) >= 4 &&
		bytes[0] == 0xff &&
		bytes[1] == 0xd8 &&
		bytes[len(bytes)-2] == 0xff &&
		bytes[len(bytes)-1] == 0xd9
}
