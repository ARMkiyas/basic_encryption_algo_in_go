/*

classical encryption techniques in Go (Golang) by A.R.M.Kiyas

*/

package main

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// caesar Cipher  encryption method
func CaesarCipher_Encrypt(text string, key int) string {
	// Convert the message to uppercase and remove spaces
	text = strings.ToUpper(strings.ReplaceAll(text, " ", ""))
	cipher := ""
	// Loop through each letter in the message
	for _, letter := range text {
		// Find the index of the letter in the alphabet
		index := strings.IndexRune(alphabet, letter)
		// Add the key to the index and wrap around if necessary
		newIndex := (index + key) % len(alphabet)
		newLetter := rune(alphabet[newIndex])
		cipher += string(newLetter)
	}

	return cipher
}

// caesar Cipher decryption method
func CaesarCipher_Decrypt(cipher string, key int) string {
	// Convert the cipher to uppercase
	cipher = strings.ToUpper(cipher)
	message := ""
	// Loop through each letter in the cipher
	for _, letter := range cipher {
		// Find the index of the letter in the alphabet
		index := strings.IndexRune(alphabet, letter)
		// Subtract the key from the index and wrap around if necessary
		newIndex := (index - key) % len(alphabet)
		// If the new index is negative, add the length of the alphabet to make it positive
		if newIndex < 0 {
			newIndex += len(alphabet)
		}
		// Find the new letter in the alphabet and append it to the plain text
		newLetter := rune(alphabet[newIndex])
		message += string(newLetter)
	}

	return message
}

// vimigere Cipher encryption method
func VigenereCipher_Encrypt(message string, Key string) string {
	message = strings.ToUpper(message)
	message = strings.ReplaceAll(message, " ", "")
	key := strings.ToUpper(Key)

	cipher := ""
	keyPos := 0

	for _, letter := range message {
		index := strings.Index(alphabet, string(letter))
		keyIndex := strings.Index(alphabet, string(key[keyPos]))
		newIndex := (index + keyIndex) % len(alphabet)
		newLetter := string(alphabet[newIndex])
		cipher += newLetter
		keyPos = (keyPos + 1) % len(key)
	}

	return cipher
}

// vimigere Cipher decryption method
func VigenereCipher_Decrypt(cipher string, Key string) string {
	cipher = strings.ToUpper(cipher)
	key := strings.ToUpper(Key)
	message := ""
	keyPos := 0

	for _, letter := range cipher {
		index := strings.Index(alphabet, string(letter))
		keyIndex := strings.Index(alphabet, string(key[keyPos]))
		newIndex := (index - keyIndex + len(alphabet)) % len(alphabet)
		newLetter := string(alphabet[newIndex])
		message += newLetter
		keyPos = (keyPos + 1) % len(key)
	}

	return message
}

// Rail Fence Cipher encryption method
func RailFenceCipher_Encrypt(message string, key int) string {
	// Remove spaces from the message
	message = strings.ReplaceAll(message, " ", "")
	railList := make([]string, key)
	rail := 0
	direction := 1 // 1 for down, -1 for up
	// Loop through each letter in the message
	for _, letter := range message {
		// Append the letter to the current rail
		railList[rail] += string(letter)
		rail += direction
		if rail == 0 || rail == key-1 {
			direction = -direction
		}
	}

	cipher := strings.Join(railList, "")
	return cipher
}

// Rail Fence Cipher decryption method
func RailFenceCipher_Decrypt(cipher string, key int) string {
	rail := make([][]byte, key)
	for i := range rail {
		rail[i] = make([]byte, len(cipher))
		for j := range rail[i] {
			rail[i][j] = '\n'
		}
	}

	dirDown := false
	row, col := 0, 0

	for i := 0; i < len(cipher); i++ {
		rail[row][col] = '*'
		col++

		if row == 0 {
			dirDown = true
		} else if row == key-1 {
			dirDown = false
		}

		if dirDown {
			row++
		} else {
			row--
		}
	}

	index := 0
	for i := 0; i < key; i++ {
		for j := 0; j < len(cipher); j++ {
			if rail[i][j] == '*' && index < len(cipher) {
				rail[i][j] = cipher[index]
				index++
			}
		}
	}

	result := []byte{}
	row, col = 0, 0
	for i := 0; i < len(cipher); i++ {
		result = append(result, rail[row][col])
		col++

		if row == 0 {
			dirDown = true
		} else if row == key-1 {
			dirDown = false
		}

		if dirDown {
			row++
		} else {
			row--
		}
	}

	return string(result)
}

// Columnar Cipher encryption method
func ColumnarCipher_Encrypt(text string, key string) string {
	matrix := [][]string{}
	pointer := 0
	// Number of columns
	col := int(math.Ceil(float64(len(text)) / float64(len(key))))
	// Arranging plain text into matrix
	// In row format
	for i := 0; i < col; i++ {
		temp := []string{}
		for j := 0; j < len(key); j++ {
			// Add the padding character '_' in
			// the empty cell of the matrix
			if pointer == len(text) || pointer > len(text) {
				temp = append(temp, "_")
			} else {
				temp = append(temp, string(text[pointer]))
			}
			pointer++
		}
		matrix = append(matrix, temp)
	}

	// Encryption - reading text in column wise format
	encryptedText := ""
	keyList := strings.Split(key, "")
	sort.Strings(keyList)
	for _, k := range keyList {
		index := strings.Index(key, k)
		for j := 0; j < len(matrix); j++ {
			encryptedText += matrix[j][index]
		}
	}

	return encryptedText
}

// Columnar Cipher decryption method
func ColumnarCipher_Decrypt(text string, key string) string {
	matrix := make([][]byte, len(key))
	pointer := 0
	col := int(math.Ceil(float64(len(text)) / float64(len(key))))

	// Arranging cipher text into matrix
	for i := range matrix {
		matrix[i] = make([]byte, col)
		for j := 0; j < col && pointer < len(text); j++ {
			matrix[i][j] = text[pointer]
			pointer++
		}
	}

	// Decryption - reading msg in column-wise format
	decryptedText := []byte{}
	keyList := []byte(key)
	sort.Slice(keyList, func(i, j int) bool { return keyList[i] < keyList[j] })

	for i := 0; i < col; i++ {
		for _, j := range key {
			index := sort.Search(len(keyList), func(k int) bool { return keyList[k] >= byte(j) })
			if matrix[index][i] != '_' {
				decryptedText = append(decryptedText, matrix[index][i])
			}
		}
	}

	return string(decryptedText)
}

// main method
func main() {

	fmt.Println(VigenereCipher_Encrypt("hallo", "key"))

	for {
		fmt.Println("\nAvailable ciphers:")
		fmt.Println("1. Caesar Cipher")
		fmt.Println("2. Vigenere Cipher")
		fmt.Println("3. Rail Fence Cipher")
		fmt.Println("4. Columnar Cipher")
		fmt.Println("5. Exit")

		var choice string
		fmt.Print("Enter your choice (1-5): ")
		fmt.Scanln(&choice)

		numChoice, err := strconv.Atoi(choice)
		if err != nil {
			fmt.Println("Invalid choice. Please enter a number.")
			continue
		}

		if numChoice == 5 {
			fmt.Println("Exiting...")
			os.Exit(0) // Exit the program
		}

		var encDec string
		fmt.Print("Do you want to encrypt (e) or decrypt (d)? :")
		fmt.Scanln(&encDec)

		if encDec != "e" && encDec != "d" {
			fmt.Println("Invalid choice. Please enter e or d.")
			continue
		}

		var text string
		if encDec == "e" {
			fmt.Print("Enter the text: ")
			fmt.Scanln(&text)
		} else {
			fmt.Print("Enter the cipher: ")
			fmt.Scanln(&text)
		}

		switch numChoice {
		case 1:

			var key int
			fmt.Print("Enter the key (integer): ")
			fmt.Scanln(&key)

			os.Stdout.WriteString("\033[H\033[2J")
			if encDec == "e" {
				fmt.Println("The encrypted text is:", CaesarCipher_Encrypt(text, key))
			} else {
				fmt.Println("The decrypted text is:", CaesarCipher_Decrypt(text, key))
			}

			break

		case 2:

			var key string
			fmt.Print("Enter the key (string): ")
			fmt.Scanln(&key)

			os.Stdout.WriteString("\033[H\033[2J")
			if encDec == "e" {
				fmt.Println("The encrypted cipher text is:", VigenereCipher_Encrypt(text, key))
			} else {
				fmt.Println("The decrypted text is:", VigenereCipher_Decrypt(text, key))
			}
			break
		case 3:

			var key int
			fmt.Print("Enter the key (integer): ")
			fmt.Scanln(&key)

			os.Stdout.WriteString("\033[H\033[2J")
			if encDec == "e" {
				fmt.Println("The encrypted text is:", RailFenceCipher_Encrypt(text, key))
			} else {
				fmt.Println("The decrypted text is:", RailFenceCipher_Decrypt(text, key))
			}
			break
		case 4:

			var key string
			fmt.Print("Enter the key (string): ")
			fmt.Scanln(&key)

			os.Stdout.WriteString("\033[H\033[2J")
			if encDec == "e" {
				fmt.Println("The encrypted text is:", ColumnarCipher_Encrypt(text, key))
			} else {
				fmt.Println("The decrypted text is:", ColumnarCipher_Decrypt(text, key))
			}

			break
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}
