package main

import (
	"fmt"
	"os"
)

func main() {
	if err := realMain(); err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
}
