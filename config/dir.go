package config

import "path/filepath"

var workingDir string

func SetWorkingDir(dir string) {
	workingDir = dir
}
func GetWorkingDir() string {
	return workingDir
}

func GetPathFromWorkingDir(path string) string {
	return filepath.Join(workingDir, path)
}
