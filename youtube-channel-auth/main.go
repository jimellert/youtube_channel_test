package main

import (
	"flag"
	"fmt"
	"log"
)


func main() {
	flag.Parse()

	config, err := readConfig("../client_secrets.json")
    if err != nil {
		fmt.Printf("Cannot read configuration file: %v\n", err)
		return
	}

	fmt.Printf (". . Calling buildOAuthHTTPClient\n")

	_, err = buildOAuthHTTPClient (config)
	if err != nil {
		log.Fatalf("Error building OAuth client: %v", err)
	}
}

