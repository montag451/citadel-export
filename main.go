package main

import (
	"bytes"
	"encoding/json"
	"errors"
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

func parseMatrixError(r io.Reader) (code string, message string, err error) {
	var resp struct {
		Errcode string `json:"errcode"`
		Error   string `json:"error"`
	}
	if err = json.NewDecoder(r).Decode(&resp); err != nil {
		return
	}
	if resp.Errcode == "" {
		// If errcode is empty or absent, assume failure to
		// parse response
		err = errors.New("unable to parse response, empty or missing errcode")
		return
	}
	code, message, err = resp.Errcode, resp.Error, nil
	return
}

func request(token string, url string, params url.Values) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to %q: %w", url, err)
	}
	q := req.URL.Query()
	q.Set("access_token", token)
	for key, values := range params {
		for _, value := range values {
			q.Add(key, value)
		}
	}
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to %q: %w", url, err)
	}
	if resp.StatusCode != 200 {
		_, msg, err := parseMatrixError(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to make request to %q, unexpected HTTP code: %d", url, resp.StatusCode)
		}
		return nil, fmt.Errorf("failed to make request to %q: %s", url, msg)
	}
	return resp, nil
}

func getAccessToken(email string, password string) (string, error) {
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
		return "", fmt.Errorf("unable to get token: %w", err)
	}
	bodyReader := bytes.NewReader(body)
	resp, err := http.Post(baseUrl+"/login", "application/json", bodyReader)
	if err != nil {
		return "", fmt.Errorf("unable to get token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		_, msg, err := parseMatrixError(resp.Body)
		if err != nil {
			return "", fmt.Errorf("unable to get token, unexpected HTTP code: %d", resp.StatusCode)
		}
		return "", fmt.Errorf("unable to get token: %s", msg)
	}
	var loginResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return "", fmt.Errorf("unable to get token: %w", err)
	}
	token, ok := loginResp["access_token"]
	if !ok {
		return "", fmt.Errorf("unable to get token, missing token in response: %v", loginResp)
	}
	return token, nil
}

var myId string

func getMyUserId(token string) (string, error) {
	if myId != "" {
		return myId, nil
	}
	resp, err := request(token, baseUrl+"/account/whoami", nil)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve my user ID: %w", err)
	}
	defer resp.Body.Close()
	var respJson map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&respJson); err != nil {
		return "", fmt.Errorf("unable to retrieve my user ID: %w", err)
	}
	id, ok := respJson["user_id"]
	if !ok {
		return "", fmt.Errorf("unable to get my user ID, missing user_id in response: %v", respJson)
	}
	myId = id
	return id, nil
}

type room struct {
	id   string
	name string
}

func getRooms(token string) ([]*room, error) {
	resp, err := request(token, baseUrl+"/joined_rooms", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve rooms: %w", err)
	}
	defer resp.Body.Close()
	var respJson map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&respJson); err != nil {
		return nil, fmt.Errorf("failed to retrieve rooms: %w", err)
	}
	joinedRooms, ok := respJson["joined_rooms"]
	if !ok {
		return nil, fmt.Errorf("failed to retrieve rooms, unable to parse response: %v", respJson)
	}
	rooms := make([]*room, 0, len(joinedRooms))
	for _, roomId := range joinedRooms {
		name, err := getRoomName(token, roomId)
		if err != nil {
			return nil, err
		}
		rooms = append(rooms, &room{id: roomId, name: name})
	}
	return rooms, nil
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

type contentParser = func(map[string]interface{}) (content, error)

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
		h = fmt.Sprintf(`<p style="white-space:pre-wrap">%s</p>`, html.EscapeString(c.text))
	}
	return template.HTML(h)
}

func textContentParser(m map[string]interface{}) (content, error) {
	text, ok := m["body"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse text message, missing %q", "body")
	}
	var html string
	if format, ok := m["format"].(string); ok && format == "org.matrix.custom.html" {
		html, _ = m["formatted_body"].(string)
	}
	return &textContent{text, html}, nil
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

func imageContentParser(m map[string]interface{}) (content, error) {
	errMsg := "failed to parse image message, missing %q"
	name, ok := m["body"].(string)
	if !ok {
		return nil, fmt.Errorf(errMsg, "body")
	}
	urlStr, ok := m["url"].(string)
	if !ok {
		return nil, fmt.Errorf(errMsg, "url")
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image URL %q: %w", urlStr, err)
	}
	return &imageContent{name, u}, nil
}

type fileContent struct {
	name     string
	url      *url.URL
	mimeType string
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
	return template.HTML(fmt.Sprintf(`<p><a href="%s" type="%s">%s</a></p>`, href, c.mimeType, c.name))
}

func fileContentParser(m map[string]interface{}) (content, error) {
	errMsg := "failed to parse file message, missing %q"
	name, ok := m["body"].(string)
	if !ok {
		return nil, fmt.Errorf(errMsg, "body")
	}
	urlStr, ok := m["url"].(string)
	if !ok {
		return nil, fmt.Errorf(errMsg, "url")
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file URL %q: %w", urlStr, err)
	}
	var mimeType string
	if info, ok := m["info"].(map[string]interface{}); ok {
		mimeType, _ = info["mimetype"].(string)
	}
	return &fileContent{name, u, mimeType}, nil
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

func getRoomMessages(token string, roomId string, dir string, types []string) (*result, error) {
	switch dir {
	case "":
		dir = "b"
	case "b", "f":
	default:
		err := fmt.Errorf("unknown direction %q", dir)
		panic(err)
	}
	var from string
	if dir == "f" {
		var err error
		from, err = getRoomStart(token, roomId)
		if err != nil {
			return nil, err
		}
	}
	limit := strconv.FormatUint(1000, 10)
	var filterStr string
	if len(types) != 0 {
		filter := map[string][]string{
			"types": types,
		}
		tmp, err := json.Marshal(filter)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve room messages: %w", err)
		}
		filterStr = string(tmp)
	}
	messages := make([]*message, 0)
	var start, end string
	for {
		q := url.Values{}
		q.Set("dir", dir)
		q.Set("limit", limit)
		if filterStr != "" {
			q.Set("filter", filterStr)
		}
		if from != "" {
			q.Set("from", from)
		}
		resp, err := request(token, baseUrl+"/rooms/"+roomId+"/messages", q)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve room messages: %w", err)
		}
		defer resp.Body.Close()
		var respJson map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&respJson); err != nil {
			return nil, fmt.Errorf("failed to retrieve room messages: %w", err)
		}
		errMsg := "failed to retrieve room messages, unable to parse response: %v"
		chunks, ok := respJson["chunk"].([]interface{})
		if !ok {
			return nil, fmt.Errorf(errMsg, respJson)
		}
		if len(chunks) == 0 {
			break
		}
		for _, chunk := range chunks {
			rawMsg, ok := chunk.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf(errMsg, respJson)
			}
			ts, ok := rawMsg["origin_server_ts"].(float64)
			if !ok {
				return nil, fmt.Errorf(errMsg, respJson)
			}
			ns := math.Mod(ts, 1000) * math.Pow10(6)
			date := time.Unix(int64(ts/1000), int64(ns))
			sender, ok := rawMsg["sender"].(string)
			if !ok {
				return nil, fmt.Errorf(errMsg, respJson)
			}
			userInfo, err := getUserInfo(token, sender)
			if err != nil {
				return nil, err
			}
			rawContent, ok := rawMsg["content"].(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf(errMsg, respJson)
			}
			var parsedContent content
			if len(rawContent) != 0 {
				if msgType, ok := rawContent["msgtype"].(string); ok {
					if parser, ok := contentParsers[msgType]; ok {
						parsedContent, err = parser(rawContent)
						if err != nil {
							return nil, err
						}
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
				return nil, fmt.Errorf(errMsg, respJson)
			}
		}
		end, ok = respJson["end"].(string)
		if !ok {
			return nil, fmt.Errorf(errMsg, respJson)
		}
		from = end
	}
	return &result{messages, start, end}, nil
}

func getRoomName(token string, roomId string) (string, error) {
	res, err := getRoomMessages(token, roomId, "", []string{"m.room.name"})
	if err != nil {
		return "", err
	}
	if len(res.messages) == 0 {
		// Private chat, look for the first membership message
		// not related to our id
		myId, err := getMyUserId(token)
		if err != nil {
			return "", err
		}
		res, err := getRoomMessages(token, roomId, "f", []string{"m.room.member"})
		if err != nil {
			return "", err
		}
		if len(res.messages) == 0 {
			return "", nil
		}
		for _, msg := range res.messages {
			userId, ok := msg.rawMessage["user_id"].(string)
			if !ok {
				return "", errors.New("failed to retrieve room name, no user_id found")
			}
			if userId == myId {
				continue
			}
			name, ok := msg.rawContent["displayname"].(string)
			if !ok {
				return "", errors.New("failed to retrieve room name, no displayname found")
			}
			return name, nil
		}
		// No membership messages not related to our id found...
		return "", nil
	}
	message := res.messages[0]
	name, ok := message.rawContent["name"].(string)
	if !ok {
		return "", errors.New("failed to retrieve room name, no name found")
	}
	return name, nil
}

func getRoomStart(token string, roomId string) (string, error) {
	t := "m.room.create"
	res, err := getRoomMessages(token, roomId, "", []string{t})
	if err != nil {
		return "", err
	}
	if len(res.messages) == 0 {
		return "", fmt.Errorf("failed to retrieve room start, no message with type %q found", t)
	}
	// We go backward (dir=b) so the start of the messages is in
	// the "end" field
	return res.end, nil
}

type userInfo struct {
	Name  string
	Email string
}

var users map[string]*userInfo = map[string]*userInfo{}

func getUserInfo(token string, userId string) (*userInfo, error) {
	info, ok := users[userId]
	if ok {
		return info, nil
	}
	resp, err := request(token, baseUrl+"/profile/"+userId, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user info: %w", err)
	}
	defer resp.Body.Close()
	var respJson map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&respJson); err != nil {
		return nil, fmt.Errorf("failed to retrieve user info: %w", err)
	}
	errMsg := "failed to retrieve user info, unable to parse response: %v"
	name, ok := respJson["displayname"]
	if !ok {
		return nil, fmt.Errorf(errMsg, respJson)
	}
	address, ok := respJson["address"]
	if !ok {
		return nil, fmt.Errorf(errMsg, respJson)
	}
	info = &userInfo{name, address}
	users[userId] = info
	return info, nil
}

func downloadFile(token string, info *fileInfo, downloadDir string) (err error) {
	fileName := filepath.Join(downloadDir, info.uniqueName)
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			err = nil
			return
		}
		err = fmt.Errorf("failed to create file %q: %w", fileName, err)
		return
	}
	defer func() {
		f.Close()
		if err != nil {
			if err := os.Remove(fileName); err != nil {
				errMsg := fmt.Sprintf("failed to remove %q", fileName)
				panic(errMsg)
			}
		}
	}()
	resp, err := request(token, info.url, nil)
	if err != nil {
		err = fmt.Errorf("failed to download %q: %w", fileName, err)
		return
	}
	defer resp.Body.Close()
	if _, err = io.Copy(f, resp.Body); err != nil {
		err = fmt.Errorf("failed to download %q: %w", fileName, err)
		return
	}
	return
}

func getPassword(passwordFile string) (string, error) {
	var password []byte
	if passwordFile == "" {
		if !terminal.IsTerminal(syscall.Stdin) {
			return "", errors.New("no password file specified and stdin is not a terminal")
		}
		if !terminal.IsTerminal(syscall.Stdout) {
			return "", errors.New("no password file specified and stdout is not a terminal")
		}
		fmt.Print("Password: ")
		var err error
		password, err = terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()
	} else {
		f, err := os.Open(passwordFile)
		if err != nil {
			return "", fmt.Errorf("failed to open password file %q: %w", passwordFile, err)
		}
		password, err = ioutil.ReadAll(f)
		if err != nil {
			return "", fmt.Errorf("failed to read password file %q: %w", passwordFile, err)
		}
	}
	return string(password), nil
}

func downloadFiles(token string, infos []*fileInfo, downloadDir string) []error {
	nbWorkers := 20
	done := make(chan struct{}, nbWorkers)
	infoChan := make(chan *fileInfo, nbWorkers)
	errChan := make(chan error)
	defer close(errChan)
	bar := pb.StartNew(len(infos))
	defer bar.Finish()
	for i := 0; i < nbWorkers; i++ {
		go func() {
			defer func() {
				done <- struct{}{}
			}()
			for info := range infoChan {
				errChan <- downloadFile(token, info, downloadDir)
				bar.Increment()
			}
		}()
	}
	go func() {
		defer close(infoChan)
		for _, info := range infos {
			infoChan <- info
		}
	}()
	errors := make([]error, 0, len(infos))
	for i := 0; i < nbWorkers; {
		select {
		case err := <-errChan:
			if err != nil {
				errors = append(errors, err)
			}
		case <-done:
			i++
		}
	}
	return errors
}

func main() {
	email := flag.String("email", "", "email address")
	roomName := flag.String("room", "", "room to export")
	passwordFile := flag.String("password-file", "", "file containing password")
	outputDir := flag.String("output-dir", "", "output directory")
	flag.Parse()
	if *email == "" || *roomName == "" || *outputDir == "" {
		log.Println("missing required argument")
		flag.Usage()
		os.Exit(1)
	}
	password, err := getPassword(*passwordFile)
	if err != nil {
		log.Fatal(err)
	}
	token, err := getAccessToken(*email, password)
	if err != nil {
		log.Fatal(err)
	}
	rooms, err := getRooms(token)
	if err != nil {
		log.Fatal(err)
	}
	var room *room
	for _, r := range rooms {
		if r.name == *roomName {
			room = r
		}
	}
	if room == nil {
		log.Fatalf("room '%s' not found", *roomName)
	}
	res, err := getRoomMessages(token, room.id, "f", []string{"m.room.message"})
	if err != nil {
		log.Fatal(err)
	}
	downloadDir := filepath.Join(*outputDir, contentDir)
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		log.Fatal("failed to create download dir")
	}
	outputFileName := filepath.Join(*outputDir, "messages.html")
	output, err := os.Create(outputFileName)
	if err != nil {
		log.Fatalf("failed to create output file %q: %v", outputFileName, err)
	}
	if err := tmpl.Execute(output, res.messages); err != nil {
		log.Fatalf("failed to write output: %v", err)
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
	if len(infos) > 0 {
		log.Println("downloading files...")
		for _, err := range downloadFiles(token, infos, downloadDir) {
			log.Println(err)
		}
	}
}
