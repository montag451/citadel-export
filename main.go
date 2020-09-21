package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cheggaaa/pb"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	baseUrl      = "https://thales.citadel.team/_matrix/client/r0"
	baseMediaUrl = "https://thales.citadel.team/_matrix/media/r0"
	contentDir   = "files"
)

var tmpl *template.Template = template.Must(template.New("").Parse(`
<html>
  <head>
    <meta charset="UTF-8">
  </head>
  <body>
    {{- range . }}
    <h3>[{{ .Date.Format "2006-01-02 15:04:05" }}] {{ .Sender.Name }} ({{ .Sender.Email }})</h3>
    {{ .ParsedContent.MarshalHTML }}
    {{- end }}
  </body>
</html>`))

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
	rooms := make([]*room, 0, len(joinedRooms))
	for _, roomId := range joinedRooms {
		name := getRoomName(token, roomId)
		rooms = append(rooms, &room{id: roomId, name: name})
	}
	return rooms
}

type fileInfo struct {
	name       string
	uniqueName string
	url        string
}

type content interface {
	fileInfo() *fileInfo
	MarshalHTML() template.HTML
}

type contentParser = func(map[string]interface{}) content

var contentParsers map[string]contentParser = map[string]contentParser{
	"m.text":  textContentParser,
	"m.image": imageContentParser,
	"m.file":  fileContentParser,
}

type textContent struct {
	text string
	html string
}

func (c *textContent) fileInfo() *fileInfo {
	return nil
}

func (c *textContent) MarshalHTML() template.HTML {
	var h string
	if c.html != "" {
		h = c.html
	} else {
		h = fmt.Sprintf("<p>%s</p>", html.EscapeString(c.text))
	}
	return template.HTML(h)
}

func textContentParser(m map[string]interface{}) content {
	text, ok := m["body"].(string)
	if !ok {
		log.Fatalf("Failed to parse text message %v", m)
	}
	var html string
	if format, ok := m["format"].(string); ok && format == "org.matrix.custom.html" {
		html, _ = m["formatted_body"].(string)
	}
	return &textContent{text, html}
}

type imageContent struct {
	name string
	url  *url.URL
}

func (c *imageContent) fileInfo() *fileInfo {
	return &fileInfo{
		name:       c.name,
		uniqueName: c.url.Path,
		url:        baseMediaUrl + "/download/" + c.url.Host + c.url.Path,
	}
}

func (c *imageContent) MarshalHTML() template.HTML {
	src := path.Join(contentDir, c.url.Path)
	imgFmt := `<img src="%s" alt="%s" style="max-width:100%%;height:auto"/>`
	return template.HTML(fmt.Sprintf(imgFmt, src, c.name))
}

func imageContentParser(m map[string]interface{}) content {
	name, ok := m["body"].(string)
	if !ok {
		log.Fatalf("Failed to parse image message %v", m)
	}
	urlStr, ok := m["url"].(string)
	if !ok {
		log.Fatalf("Failed to parse image message %v", m)
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		log.Fatalf("Failed to parse image message %v", m)
	}
	return &imageContent{name, u}
}

type fileContent struct {
	name string
	url  *url.URL
}

func (c *fileContent) fileInfo() *fileInfo {
	return &fileInfo{
		name:       c.name,
		uniqueName: c.url.Path,
		url:        baseMediaUrl + "/download/" + c.url.Host + c.url.Path,
	}
}

func (c *fileContent) MarshalHTML() template.HTML {
	href := path.Join(contentDir, c.url.Path)
	return template.HTML(fmt.Sprintf(`<p><a href="%s">%s</a></p>`, href, c.name))
}

func fileContentParser(m map[string]interface{}) content {
	name, ok := m["body"].(string)
	if !ok {
		log.Fatalf("Failed to parse file message %v", m)
	}
	urlStr, ok := m["url"].(string)
	if !ok {
		log.Fatalf("Failed to parse file message %v", m)
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		log.Fatalf("Failed to parse file message %v", m)
	}
	return &fileContent{name, u}
}

type message struct {
	Sender        *userInfo
	Date          time.Time
	ParsedContent content
	rawMessage    map[string]interface{}
	rawContent    map[string]interface{}
}

type result struct {
	messages []*message
	start    string
	end      string
}

func getRoomMessages(token string, roomId string, dir string, limit uint64, types []string) result {
	url := baseUrl + "/rooms/" + roomId + "/messages"
	switch dir {
	case "":
		dir = "b"
	case "b", "f":
	default:
		log.Fatalf("Unknown direction '%s'", dir)
	}
	if limit == 0 {
		limit = 1000
	}
	var from string
	if dir == "f" {
		from = getRoomStart(token, roomId)
	}
	limitStr := strconv.FormatUint(limit, 10)
	var filterStr string
	if len(types) != 0 {
		filter := map[string][]string{
			"types": types,
		}
		tmp, err := json.Marshal(filter)
		if err != nil {
			log.Fatalf("Failed to retrieve room messages: %v", err)
		}
		filterStr = string(tmp)
	}
	messages := make([]*message, 0)
	var start, end string
	for {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatalf("Failed to retrieve room messages: %v", err)
		}
		q := req.URL.Query()
		q.Set("access_token", token)
		q.Set("dir", dir)
		q.Set("limit", limitStr)
		if filterStr != "" {
			q.Set("filter", filterStr)
		}
		if from != "" {
			q.Set("from", from)
		}
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
			rawMsg, ok := chunk.(map[string]interface{})
			if !ok {
				log.Fatalf(errMsg, chunk)
			}
			ts, ok := rawMsg["origin_server_ts"].(float64)
			if !ok {
				log.Fatalf(errMsg, chunk)
			}
			ns := math.Mod(ts, 1000) * math.Pow10(6)
			date := time.Unix(int64(ts/1000), int64(ns))
			sender, ok := rawMsg["sender"].(string)
			if !ok {
				log.Fatalf(errMsg, chunk)
			}
			userInfo := getUserInfo(token, sender)
			rawContent, ok := rawMsg["content"].(map[string]interface{})
			if !ok {
				log.Fatalf(errMsg, chunk)
			}
			var parsedContent content
			if len(rawContent) != 0 {
				msgType, ok := rawContent["msgtype"].(string)
				if ok {
					parser, ok := contentParsers[msgType]
					if ok {
						parsedContent = parser(rawContent)
					}
				}
			}
			msg := &message{
				Sender:        userInfo,
				Date:          date,
				ParsedContent: parsedContent,
				rawMessage:    rawMsg,
				rawContent:    rawContent,
			}
			messages = append(messages, msg)
		}
		if start == "" {
			var ok bool
			start, ok = respJson["start"].(string)
			if !ok {
				log.Fatalf(errMsg, respJson)
			}
		}
		end, ok = respJson["end"].(string)
		if !ok {
			log.Fatalf(errMsg, respJson)
		}
		from = end
	}
	return result{messages, start, end}
}

func getRoomName(token string, roomId string) string {
	res := getRoomMessages(token, roomId, "", 1, []string{"m.room.name"})
	if len(res.messages) == 0 {
		return ""
	}
	message := res.messages[0]
	name, ok := message.rawContent["name"].(string)
	if !ok {
		return ""
	}
	return name
}

func getRoomStart(token string, roomId string) string {
	res := getRoomMessages(token, roomId, "", 1, []string{"m.room.create"})
	if len(res.messages) == 0 {
		log.Fatalf("Failed to retrieve room start")
	}
	// We go backward (dir=b) so the start of the messages is in
	// the "end" field
	return res.end
}

type userInfo struct {
	Name  string
	Email string
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

func downloadFile(token string, info *fileInfo, downloadDir string) {
	fileName := filepath.Join(downloadDir, info.uniqueName)
	f, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("Failed to create file %q", fileName)
	}
	defer f.Close()
	req, err := http.NewRequest("GET", info.url, nil)
	if err != nil {
		log.Fatalf("Failed to download %q: %v", fileName, err)
	}
	q := req.URL.Query()
	q.Set("access_token", token)
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to download %q: %v", fileName, err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		log.Fatalf("Failed to download %q: %v", fileName, err)
	}
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
	outputDir := flag.String("output-dir", "", "output directory")
	flag.Parse()
	if *email == "" || *roomName == "" || *outputDir == "" {
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
	res := getRoomMessages(token, room.id, "f", 0, []string{"m.room.message"})
	downloadDir := filepath.Join(*outputDir, contentDir)
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		log.Fatal("Failed to create download dir")
	}
	outputFileName := filepath.Join(*outputDir, "messages.html")
	output, err := os.Create(outputFileName)
	if err != nil {
		log.Fatalf("Failed to create output file %q: %v", outputFileName, err)
	}
	if err := tmpl.Execute(output, res.messages); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}
	var infos []*fileInfo
	for _, msg := range res.messages {
		content := msg.ParsedContent
		if content == nil {
			continue
		}
		if info := content.fileInfo(); info != nil {
			infos = append(infos, info)
		}
	}
	var wg sync.WaitGroup
	nbWorkers := 20
	ch := make(chan *fileInfo, nbWorkers)
	bar := pb.StartNew(len(infos))
	defer bar.Finish()
	for i := 0; i < nbWorkers; i++ {
		go func() {
			for info := range ch {
				wg.Add(1)
				downloadFile(token, info, downloadDir)
				bar.Increment()
				wg.Done()
			}
		}()
	}
	log.Println("Downloading files...")
	for _, info := range infos {
		ch <- info
	}
	wg.Wait()
}
