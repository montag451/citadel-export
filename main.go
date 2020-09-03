package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/gomarkdown/markdown"

	"golang.org/x/crypto/ssh/terminal"
)

const baseUrl = "https://thales.citadel.team/_matrix/client/r0"

func getAccessToken(email string, password string) string {
	userInfo := map[string]interface{}{
		"type": "m.login.password",
		"identifier": map[string]string{
			"type":    "m.id.thirdparty",
			"medium":  "email",
			"address": email,
		},
		"password": password,
	}
	body, err := json.Marshal(&userInfo)
	if err != nil {
		log.Fatalf("Unable to get token: %v", err)
	}
	bodyReader := bytes.NewReader(body)
	resp, err := http.Post(baseUrl+"/login", "application/json", bodyReader)
	if err != nil {
		log.Fatalf("Unable to get token: %v", err)
	}
	defer resp.Body.Close()
	var loginResp map[string]string
	err = json.NewDecoder(resp.Body).Decode(&loginResp)
	if err != nil {
		log.Fatalf("Unable to get token: %v", err)
	}
	token, ok := loginResp["access_token"]
	if !ok {
		log.Fatalf(
			"Unable to get token, missing token in response: %v",
			loginResp,
		)
	}
	return token
}

type room struct {
	id   string
	name string
}

func getRooms(token string) []*room {
	req, err := http.NewRequest("GET", baseUrl+"/joined_rooms", nil)
	if err != nil {
		log.Fatalf("Failed to retrieve rooms: %v", err)
	}
	q := req.URL.Query()
	q.Set("access_token", token)
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to retrieve rooms: %v", err)
	}
	defer resp.Body.Close()
	var respJson map[string][]string
	err = json.NewDecoder(resp.Body).Decode(&respJson)
	if err != nil {
		log.Fatalf("Failed to retrieve rooms: %v", err)
	}
	joinedRooms, ok := respJson["joined_rooms"]
	if !ok {
		log.Fatalf("Failed to retrieve rooms, unable to parse response: %v", respJson)
	}
	rooms := make([]*room, len(joinedRooms))
	for i, roomId := range joinedRooms {
		name := getRoomName(token, roomId)
		rooms[i] = &room{id: roomId, name: name}
	}
	return rooms
}

func getRoomName(token string, roomId string) string {
	url := baseUrl + "/rooms/" + roomId + "/messages"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to retrieve room name: %v", err)
	}
	q := req.URL.Query()
	q.Set("access_token", token)
	q.Set("dir", "b")
	q.Set("limit", "1")
	q.Set("filter", `{"types": ["m.room.name"]}`)
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to retrieve room name: %v", err)
	}
	defer resp.Body.Close()
	var respJson map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&respJson)
	if err != nil {
		log.Fatalf("Failed to retrieve room name: %v", err)
	}
	chunk, ok := respJson["chunk"].([]interface{})
	if !ok || len(chunk) == 0 {
		return ""
	}
	message, ok := chunk[0].(map[string]interface{})
	if !ok {
		return ""
	}
	content, ok := message["content"].(map[string]interface{})
	if !ok {
		return ""
	}
	name, ok := content["name"].(string)
	if !ok {
		return ""
	}
	return name
}

func getRoomStart(token string, roomId string) string {
	url := baseUrl + "/rooms/" + roomId + "/messages"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to retrieve room start: %v", err)
	}
	q := req.URL.Query()
	q.Set("access_token", token)
	q.Set("dir", "b")
	q.Set("limit", "1")
	q.Set("filter", `{"types": ["m.room.create"]}`)
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to retrieve room start: %v", err)
	}
	defer resp.Body.Close()
	var respJson map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&respJson)
	if err != nil {
		log.Fatalf("Failed to retrieve room start: %v", err)
	}
	// We go backward (dir=b) so the start of the messages is in
	// the "end" field
	start, ok := respJson["end"].(string)
	if !ok {
		log.Fatalf("Failed to retrieve room start, unable to parse response: %v", respJson)
	}
	return start
}

type message struct {
	sender *userInfo
	date   time.Time
	text   string
}

func getMessages(token string, roomId string) (messages []*message) {
	url := baseUrl + "/rooms/" + roomId + "/messages"
	from := getRoomStart(token, roomId)
	for {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatalf("Failed to retrieve room messages: %v", err)
		}
		q := req.URL.Query()
		q.Set("access_token", token)
		q.Set("dir", "f")
		q.Set("limit", "1000")
		q.Set("filter", `{"types": ["m.room.message"]}`)
		q.Set("from", from)
		req.URL.RawQuery = q.Encode()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("Failed to retrieve room messages: %v", err)
		}
		defer resp.Body.Close()
		var respJson map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&respJson)
		if err != nil {
			log.Fatalf("Failed to retrieve room messages: %v", err)
		}
		errMsg := "Failed to retrieve room messages, unable to parse response: %v"
		chunks, ok := respJson["chunk"].([]interface{})
		if !ok {
			log.Fatalf(errMsg, respJson)
		}
		if len(chunks) == 0 {
			break
		}
		for _, chunk := range chunks {
			msg, ok := chunk.(map[string]interface{})
			if !ok {
				log.Fatalf(errMsg, respJson)
			}
			ts, ok := msg["origin_server_ts"].(float64)
			if !ok {
				log.Fatalf(errMsg, respJson)
			}
			ns := math.Mod(ts, 1000) * math.Pow10(6)
			date := time.Unix(int64(ts/1000), int64(ns))
			sender, ok := msg["sender"].(string)
			if !ok {
				log.Fatalf(errMsg, respJson)
			}
			userInfo := getUserInfo(token, sender)
			content, ok := msg["content"].(map[string]interface{})
			if !ok {
				log.Fatalf(errMsg, respJson)
			}
			msgType, ok := content["msgtype"].(string)
			if !ok {
				log.Fatalf(errMsg, respJson)
			}
			if msgType != "m.text" {
				continue
			}
			msgBody, ok := content["body"].(string)
			if !ok {
				log.Fatalf(errMsg, respJson)
			}
			messages = append(messages, &message{userInfo, date, msgBody})
		}
		end, ok := respJson["end"].(string)
		if !ok {
			log.Fatalf(errMsg, respJson)
		}
		from = end
	}
	return
}

type userInfo struct {
	name  string
	email string
}

var users map[string]*userInfo = map[string]*userInfo{}

func getUserInfo(token string, userId string) *userInfo {
	info, ok := users[userId]
	if ok {
		return info
	}
	url := baseUrl + "/profile/" + userId
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to retrieve user info: %v", err)
	}
	q := req.URL.Query()
	q.Set("access_token", token)
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to retrieve user info: %v", err)
	}
	defer resp.Body.Close()
	var respJson map[string]string
	err = json.NewDecoder(resp.Body).Decode(&respJson)
	if err != nil {
		log.Fatalf("Failed to retrieve user info: %v", err)
	}
	errMsg := "Failed to retrieve user info, unable to parse response: %v"
	name, ok := respJson["displayname"]
	if !ok {
		log.Fatalf(errMsg, respJson)
	}
	address, ok := respJson["address"]
	if !ok {
		log.Fatalf(errMsg, respJson)
	}
	info = &userInfo{name, address}
	users[userId] = info
	return info
}

func getPassword(passwordFile string) string {
	var password []byte
	if passwordFile == "" {
		if !terminal.IsTerminal(syscall.Stdin) {
			log.Fatal("No password file specified and stdin is not a terminal")
		}
		if !terminal.IsTerminal(syscall.Stdout) {
			log.Fatal("No password file specified and stdout is not a terminal, use -output")
		}
		fmt.Print("Password: ")
		var err error
		password, err = terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			log.Fatalf("Failed to read password: %v", err)
		}
		fmt.Println()
	} else {
		f, err := os.Open(passwordFile)
		if err != nil {
			log.Fatalf(
				"Failed to open password file '%s': %v",
				passwordFile,
				err,
			)
		}
		password, err = ioutil.ReadAll(f)
		if err != nil {
			log.Fatalf(
				"Failed to read password file '%s': %v",
				passwordFile,
				err,
			)
		}
	}
	return string(password)
}

func main() {
	email := flag.String("email", "", "email address")
	roomName := flag.String("room", "", "room to export")
	passwordFile := flag.String("password-file", "", "file containing password")
	format := flag.String("format", "html", "output format (html or markdown)")
	output := flag.String("output", "", "output file")
	flag.Parse()
	if *email == "" || *roomName == "" {
		log.Println("Missing required argument")
		flag.Usage()
		os.Exit(1)
	}
	password := getPassword(*passwordFile)
	token := getAccessToken(*email, password)
	rooms := getRooms(token)
	var room *room
	for _, r := range rooms {
		if r.name == *roomName {
			room = r
		}
	}
	if room == nil {
		log.Fatalf("Room '%s' not found", *roomName)
	}
	messages := getMessages(token, room.id)
	var md bytes.Buffer
	for _, msg := range messages {
		mdMsg := fmt.Sprintf("## [%s] %s (%s)\n\n%s\n\n",
			msg.date.Format("2006-01-02 15:04:05"),
			msg.sender.name,
			msg.sender.email,
			msg.text,
		)
		md.WriteString(mdMsg)
	}
	var writer io.Writer
	if *output == "" {
		writer = os.Stdout
	} else {
		var err error
		writer, err = os.Create(*output)
		if err != nil {
			log.Fatal("Failed to open '%s': %v", *output, err)
		}
	}
	var outputBytes []byte
	switch *format {
	case "html":
		outputBytes = markdown.ToHTML(md.Bytes(), nil, nil)
	case "markdown":
		outputBytes = md.Bytes()
	default:
		log.Fatal("Unknown format: %s", *format)
	}
	_, err := writer.Write(outputBytes)
	if err != nil {
		log.Fatal("Failed to write result: %v", err)
	}
}
