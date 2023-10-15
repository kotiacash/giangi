package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

var startTime time.Time
var keyCount int
var mutex sync.Mutex
var foundAddresses = make(map[string]struct{})

func debug(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func printKeyRate() {
	elapsed := time.Since(startTime)
	keyRate := float64(keyCount) / elapsed.Seconds()
	debug("Indirizzi al secondo: %.2f\n", keyRate)
}

func checkAndSaveAddresses(batch []string) {
	for _, word := range batch {
		// Converte la stringa in un array di byte
		data := []byte(word)

		// Calcola l'hash SHA-256 dei dati
		hash := sha256.Sum256(data)

		// Ottieni la chiave privata Bitcoin
		privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), hash[:])

		// Crea la rete Bitcoin "mainnet"
		params := &chaincfg.MainNetParams

		// Ottieni l'indirizzo Bitcoin non compresso
		pubKey := privKey.PubKey()
		address, _ := btcutil.NewAddressPubKey(pubKey.SerializeUncompressed(), params)
		addressStr := address.EncodeAddress()

		mutex.Lock()
		if _, found := foundAddresses[addressStr]; found {
			debug("Indirizzo Bitcoin trovato: %s\n", addressStr)

			// Salva la chiave privata e l'indirizzo in "found.txt"
			foundFile := "found.txt"
			f, err := os.OpenFile(foundFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Printf("Errore nell'apertura del file %s: %v\n", foundFile, err)
				mutex.Unlock()
				return
			}
			// Scrivi la chiave privata e l'indirizzo nel file
			fmt.Fprintf(f, "Chiave privata Bitcoin: %x\n", privKey.D.Bytes())
			fmt.Fprintf(f, "Indirizzo Bitcoin non compresso: %s\n", addressStr)
			f.Close()
		}
		mutex.Unlock()

		keyCount++
	}
}

func main() {
	startTime = time.Now()
	keyCount = 0

	// Leggi gli indirizzi da "indirizzi.txt" e caricali in memoria
	addressFile := "indirizzi.txt"
	file, err := os.Open(addressFile)
	if err != nil {
		fmt.Printf("Errore nell'apertura del file %s: %v\n", addressFile, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		address := scanner.Text()
		foundAddresses[address] = struct{}{}
	}

	// Leggi le stringhe di 22 caratteri da stdin e calcola gli indirizzi
	reader := bufio.NewScanner(os.Stdin)

	var batchSize = 1000 // Modifica la dimensione del batch a tuo piacimento
	batch := make([]string, 0, batchSize)

	// Imposta un timer per visualizzare la velocità ogni 10 secondi
	timer := time.NewTicker(10 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			printKeyRate()
		default:
			if reader.Scan() {
				word := reader.Text()

				// Assicurati che la stringa abbia 22 caratteri (aggiungi un controllo per la lunghezza)
				if len(word) != 22 {
					debug("La stringa deve essere esattamente di 22 caratteri: %s\n", word)
					continue
				}

				batch = append(batch, word)

				if len(batch) == batchSize {
					go checkAndSaveAddresses(batch)
					batch = make([]string, 0, batchSize)
				}
			} else {
				if err := reader.Err(); err != nil {
					debug("Errore nella lettura da stdin: %v\n", err)
				}
				// Attendere il completamento delle ultime goroutine
				if len(batch) > 0 {
					checkAndSaveAddresses(batch)
				}
				printKeyRate()
				return
			}
		}
	}
}
