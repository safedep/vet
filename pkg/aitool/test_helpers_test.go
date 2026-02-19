package aitool

import (
	"io"
	"os"
)

func mkdir(path string) error {
	return os.MkdirAll(path, 0o755)
}

func statFile(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
