package main

import (
	"flag"
	"log"
	"os"
)

func main() {
	// fptr := flag.String("fpath", "test.txt", "file path to read from")
	flag.Parse()
	args := flag.Args()
	for _, element := range args {
		f, err := os.Open(element)
		if err != nil {
			log.Fatal(err)
		} else{
//            log.Print("touching: ", element)
        }
		if err = f.Close(); err != nil {
			log.Fatal(err)
		}
	}

}
