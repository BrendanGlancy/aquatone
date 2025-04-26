package core

import (
	"os"
	"path/filepath"
)

func Asset(name string) ([]byte, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	
	execDir := filepath.Dir(execPath)
	projectDir := execDir
	
	filepath.Walk(execDir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && filepath.Base(path) == "static" {
			projectDir = filepath.Dir(path)
			return filepath.SkipAll
		}
		return nil
	})
	
	return os.ReadFile(filepath.Join(projectDir, name))
}