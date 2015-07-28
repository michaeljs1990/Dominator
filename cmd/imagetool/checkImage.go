package main

import (
	"fmt"
	_ "github.com/Symantec/Dominator/proto/imageserver"
	"net/rpc"
	"os"
)

func checkImageSubcommand(client *rpc.Client, args []string) {
	err := checkImage(client, args[0])
	if err != nil {
		fmt.Printf("Error checking image\t%s\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func checkImage(client *rpc.Client, name string) error {
	return nil
}
