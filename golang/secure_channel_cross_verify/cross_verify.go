package main

import (
	"fmt"
	"bufio"
	"os"
	sc "secure_channel"
)

func outputForNodejs(prefix string){

	// create writer

	outputFileName := prefix + "cross_verify_output_go.txt"

	outputFile, errOpenFile := os.OpenFile(outputFileName, os.O_CREATE|os.O_WRONLY, 0777)
	if errOpenFile != nil{
		fmt.Println("open file err =", errOpenFile)
		return
	}

	defer outputFile.Close()
	outputWriter := bufio.NewWriter(outputFile)
	
	// output

	data := "Test data 1	Test data 2	Test data 3	Test data 4	Test data 5	Test data 6	Test data 7	Test data 8	Test data 9	Test data 10	Test data 11	Test data 12	Test data 13	Test data 14	Test data 15	Test data 16	Test data 17	Test data 18	Test data 19	Test data 20	Test data 21	Test data 22	Test data 23	Test data 24	Test data 25	Test data 26"

	outputWriter.WriteString("# output by golang, verify by nodejs" + "\n")
	outputWriter.WriteString("# verify need bkeypair.PrivateKey, akeypair.PublicKey, signedData (DataEnc, Hash, Sig)" + "\n")

	benchCount := 10

	for i := 0; i < benchCount; i++ {
		akeypair, _ := sc.GenerateECKeyPair()
		bkeypair, _ := sc.GenerateECKeyPair()
	
		outputWriter.WriteString(bkeypair.PrivateKey + "\n")
		outputWriter.WriteString(akeypair.PublicKey + "\n")
	
		esData, _ := sc.CalEncSignedData(akeypair.PrivateKey, bkeypair.PublicKey, data)
	
		outputWriter.WriteString(esData.DataEnc + "\n")
		outputWriter.WriteString(esData.Hash + "\n")
		outputWriter.WriteString(esData.Sig + "\n")
	}

	// flush to file

	outputWriter.Flush()

	fmt.Println("output finished")
}

func verifyNodejsOutput(prefix string) {

	// create reader

	inputFileName := prefix + "cross_verify_output_nodejs.txt"

	inputFile, errOpenFile := os.OpenFile(inputFileName, os.O_RDONLY, 0777)
	if errOpenFile != nil{
		fmt.Println("open file err =", errOpenFile)
		return
	}

	defer inputFile.Close()
	
	inputReader := bufio.NewScanner(inputFile)
	
	// read and verify

	inputReader.Scan()
	inputReader.Scan() // skip comments

	for {
		if !inputReader.Scan() {
			break
		}
		// bkeypair.PrivateKey, akeypair.PublicKey, signedData (DataEnc, Hash, Sig)
		bPrivateKey := inputReader.Text()
		inputReader.Scan()
		aPublicKey := inputReader.Text()
		inputReader.Scan()
		dataEnc := inputReader.Text()
		inputReader.Scan()
		hash := inputReader.Text()
		inputReader.Scan()
		sig := inputReader.Text()

		encSignedData := &sc.EncSignedData{
			DataEnc: dataEnc,
			Hash: hash,
			Sig: sig,
		}

		data, err := sc.VerifyEncSignedData(bPrivateKey, aPublicKey, encSignedData)

		fmt.Println("------")
		fmt.Println(data)

		if err != nil {
			fmt.Println("failed to verify!")
		}
	}
}

func main() {

	prefixOutput := "03.14_"
	
	outputForNodejs(prefixOutput)


	prefixNodejsOutput := "../../nodejs/03.14_"

	verifyNodejsOutput(prefixNodejsOutput)
}
