package main

import (
	"fmt"
	"os"
)

func main() {
	filename := "Pls dont delete me.txt"
	content := []byte("Don't Delete This")

	err := os.WriteFile(filename, content, 0644)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}

	fmt.Println("File created:", filename)
}
