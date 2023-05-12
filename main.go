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
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/windows"
)

const (
	baseURL      = "https://thales.citadel.team/_matrix/client/r0"
	baseMediaURL = "https://thales.citadel.team/_matrix/media/r0"
	contentDir   = "files"

	colorReset = "\033[0m"

	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

var tmpl = template.Must(template.New("").Parse(`
<html>
  <head>
    <meta charset="UTF-8">
  </head>
  <body>
    {{ range . }}
    <h3>[{{ .Date.Format "2006-01-02 15:04:05" }}] {{ .Sender.Name }} ({{ .Sender.Email }})</h3>
    {{ if .ParsedContent }}
    {{ .ParsedContent.MarshalHTML }}
    {{ else }}
    ** UNHANDLED MESSAGE TYPE **
    {{ end }}
    {{ end }}
  </body>
</html>`))

type matrixError struct {
	Errcode string `json:"errcode"`
	MError  string `json:"error"`
}

func (e matrixError) Error() string {
	return e.MError
}

func parseMatrixError(r io.Reader) (mError matrixError, err error) {
	if err = json.NewDecoder(r).Decode(&mError); err != nil {
		return
	}
	if mError.Errcode == "" {
		// If errcode is empty or absent, assume failure to
		// parse response
		err = errors.New("unable to parse response, empty or missing errcode")
		return
	}
	return
}

func request(token string, url string, params url.Values) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("request to %q failed: %w", url, err)
	}
	q := req.URL.Query()
	for key, values := range params {
		for _, value := range values {
			q.Add(key, value)
		}
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %q failed: %w", url, err)
	}
	if resp.StatusCode != 200 {
		mError, err := parseMatrixError(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("request to %q failed, unexpected HTTP code: %d", url, resp.StatusCode)
		}
		return nil, fmt.Errorf("request to %q failed: %w", url, mError)
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
	resp, err := http.Post(baseURL+"/login", "application/json", bodyReader)
	if err != nil {
		return "", fmt.Errorf("unable to get token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		mError, err := parseMatrixError(resp.Body)
		if err != nil {
			return "", fmt.Errorf("unable to get token, unexpected HTTP code: %d", resp.StatusCode)
		}
		return "", fmt.Errorf("unable to get token: %w", mError)
	}
	var loginResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return "", fmt.Errorf("unable to get token: %w", err)
	}
	token, ok := loginResp["access_token"]
	if !ok {
		return "", fmt.Errorf("unable to get token, missing token in response: %v", loginResp)
	}
	log.Println(colorCyan, "TOKEN: Bearer", token, colorReset)
	return token, nil
}

var myID string

func getMyUserID(token string) (string, error) {
	if myID != "" {
		return myID, nil
	}
	resp, err := request(token, baseURL+"/account/whoami", nil)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve my user ID: %w", err)
	}
	defer resp.Body.Close()
	var respJSON map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&respJSON); err != nil {
		return "", fmt.Errorf("unable to retrieve my user ID: %w", err)
	}
	id, ok := respJSON["user_id"]
	if !ok {
		return "", fmt.Errorf("unable to get my user ID, missing user_id in response: %v", respJSON)
	}
	myID = id
	return id, nil
}

type room struct {
	id   string
	name string
}

func getRooms(token string, roomID string, roomName string, myID string) ([]*room, error) {
	resp, err := request(token, baseURL+"/joined_rooms", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve rooms: %w", err)
	}
	defer resp.Body.Close()
	var respJSON map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&respJSON); err != nil {
		return nil, fmt.Errorf("failed to retrieve rooms: %w", err)
	}
	joinedRooms, ok := respJSON["joined_rooms"]
	if !ok {
		return nil, fmt.Errorf("failed to retrieve rooms, unable to parse response: %v", respJSON)
	}
	rooms := make([]*room, 0, len(joinedRooms))
	if roomID == "*" || roomName == "*" {
		log.Println(colorRed, "/!\\ IMPORTANT NOTICE: ALL ROOMS found will exported /!\\", colorReset)
	}

	if roomName == "*" {
		//NOTICE: If wilcard in room name, wilcard in room ID to simplify the code
		roomID = "*"
	}

	for _, joinedroomID := range joinedRooms {
		name, err := getRoomName(token, joinedroomID, myID)

		if roomID == "*" || joinedroomID == roomID || name == roomName {
			if err != nil {
				if itemExists([3]string{"EMPTY_ROOM", "NO_MEMBERS"}, err.Error()) {
					log.Println(colorPurple, "----> EMPTY ROOM IGNORED", colorReset, "{ ID: "+joinedroomID+"}")
					continue
				}
				if itemExists([2]string{"NO_NAME", "NO_USERID"}, err.Error()) {
					log.Println(colorPurple, "----> ROOM IGNORED", colorReset, "due to no name, no user id { ID: "+joinedroomID+"}")
					continue
				}
				if itemExists([1]string{"ONLY_YOU"}, err.Error()) {
					log.Println(colorPurple, "----> ROOM IGNORED", colorReset, "because only messages from you { ID: "+joinedroomID+"}")
					continue
				}

				return nil, err
			}
			rooms = append(rooms, &room{id: joinedroomID, name: name})
			log.Println(colorYellow, "---->", colorReset, "ROOM found { ID:", joinedroomID, ", Name:", colorCyan, name, colorReset, "}")
		}
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

type contentParser func(map[string]interface{}) (content, error)

var contentParsers = map[string]contentParser{
	"m.text":  textContentParser,
	"m.image": imageContentParser,
	"m.file":  fileContentParser,
	"m.video": videoContentParser,
	"m.audio": audioContentParser,
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

func itemExists(arrayType interface{}, item interface{}) bool {
	arr := reflect.ValueOf(arrayType)

	if arr.Kind() != reflect.Array {
		panic("Invalid data-type")
	}

	for i := 0; i < arr.Len(); i++ {
		if arr.Index(i).Interface() == item {
			return true
		}
	}

	return false
}

type mediaContent struct {
	name     string
	url      *url.URL
	mimeType string
}

func (c *mediaContent) fileInfo() *fileInfo {
	return &fileInfo{
		name:       c.name,
		uniqueName: c.url.Path + "_" + c.name,
		url:        baseMediaURL + "/download/" + c.url.Host + c.url.Path,
	}
}

func mediaContentParser(msgType string, m map[string]interface{}) (*mediaContent, error) {
	errMsg := fmt.Sprintf("failed to parse %q message, missing %%q", msgType)
	name, ok := m["body"].(string)
	if !ok {
		return nil, fmt.Errorf(errMsg, "body")
	}
	urlStr, ok := m["url"].(string)
	if !ok {
		return nil, fmt.Errorf(errMsg, "url")
	}
	url, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s URL %q: %w", msgType, urlStr, err)
	}
	var mimeType string
	if info, ok := m["info"].(map[string]interface{}); ok {
		mimeType, _ = info["mimetype"].(string)
	}
	return &mediaContent{name, url, mimeType}, nil
}

type imageContent struct {
	*mediaContent
}

func (c *imageContent) MarshalHTML() template.HTML {
	src := path.Join(contentDir, c.fileInfo().uniqueName)
	imgFmt := `<img src="%s" alt="%s" style="max-width:100%%;height:auto"/>`
	return template.HTML(fmt.Sprintf(imgFmt, src, c.name))
}

func imageContentParser(m map[string]interface{}) (content, error) {
	mc, err := mediaContentParser("image", m)
	if err != nil {
		return nil, err
	}
	return &imageContent{mc}, nil
}

type fileContent struct {
	*mediaContent
}

func (c *fileContent) MarshalHTML() template.HTML {
	href := path.Join(contentDir, c.fileInfo().uniqueName)
	return template.HTML(fmt.Sprintf(`<p><a href="%s" target="_blank" type="%s">%s</a></p>`, href, c.mimeType, c.name))
}

func fileContentParser(m map[string]interface{}) (content, error) {
	mc, err := mediaContentParser("file", m)
	if err != nil {
		return nil, err
	}
	return &fileContent{mc}, nil
}

type videoContent struct {
	*mediaContent
}

func (c *videoContent) MarshalHTML() template.HTML {
	src := path.Join(contentDir, c.fileInfo().uniqueName)
	htmlFmt := `<video src="%s" type="%s" controls=""></video>`
	return template.HTML(fmt.Sprintf(htmlFmt, src, c.mimeType))
}

func videoContentParser(m map[string]interface{}) (content, error) {
	mc, err := mediaContentParser("video", m)
	if err != nil {
		return nil, err
	}
	return &videoContent{mc}, nil
}

type audioContent struct {
	*mediaContent
}

func (c *audioContent) MarshalHTML() template.HTML {
	src := path.Join(contentDir, c.fileInfo().uniqueName)
	htmlFmt := `<audio src="%s" type="%s" controls=""></audio>`
	return template.HTML(fmt.Sprintf(htmlFmt, src, c.mimeType))
}

func audioContentParser(m map[string]interface{}) (content, error) {
	mc, err := mediaContentParser("audio", m)
	if err != nil {
		return nil, err
	}
	return &audioContent{mc}, nil
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

func getRoomMessages(token string, roomID string, dir string, types []string) (*result, error) {
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
		from, err = getRoomStart(token, roomID)
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

		resp, err := request(token, baseURL+"/rooms/"+roomID+"/messages", q)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve room messages: %w", err)
		}
		defer resp.Body.Close()
		var respJSON map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&respJSON); err != nil {
			return nil, fmt.Errorf("failed to retrieve room messages: %w", err)
		}
		errMsg := "failed to retrieve room messages, unable to parse response: %v"
		chunks, ok := respJSON["chunk"].([]interface{})
		if !ok {
			return nil, fmt.Errorf(errMsg, respJSON)
		}
		if len(chunks) == 0 {
			break
		}
		for _, chunk := range chunks {
			rawMsg, ok := chunk.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf(errMsg, respJSON)
			}
			ts, ok := rawMsg["origin_server_ts"].(float64)
			if !ok {
				return nil, fmt.Errorf(errMsg, respJSON)
			}
			ns := math.Mod(ts, 1000) * math.Pow10(6)
			date := time.Unix(int64(ts/1000), int64(ns))
			sender, ok := rawMsg["sender"].(string)
			if !ok {
				return nil, fmt.Errorf(errMsg, respJSON)
			}
			userInfo, err := getUserInfo(token, sender)
			if err != nil {
				return nil, err
			}
			rawContent, ok := rawMsg["content"].(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf(errMsg, respJSON)
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
			start, ok = respJSON["start"].(string)
			if !ok {
				return nil, fmt.Errorf(errMsg, respJSON)
			}
		}
		end, ok = respJSON["end"].(string)
		if !ok {
			return nil, fmt.Errorf(errMsg, respJSON)
		}
		from = end
	}
	return &result{messages, start, end}, nil
}

func getRoomName(token string, roomID string, myID string) (string, error) {
	res, err := getRoomMessages(token, roomID, "f", []string{"m.room.name"})
	if err != nil {
		return "", err
	}

	//NOTICE: PRIVATE CHAT
	if len(res.messages) == 0 {
		//NOTICE: Get the actors of the tchat with details
		res, err := getRoomMessages(token, roomID, "b", []string{"m.room.member"})
		if err != nil {
			return "", err
		}

		//NOTICE: IF no actors consider as EMPTY room with reason "no members"
		if len(res.messages) == 0 {
			return "", errors.New("NO_MEMBERS")
		}

		//NOTICE: DETERMINE THE TARGET based on the sender and the membership
		for _, msg := range res.messages {
			userID, ok := msg.rawMessage["user_id"].(string)
			if !ok {
				return "", errors.New("NO_USERID")
			}

			if (msg.rawMessage["sender"] == myID && msg.rawContent["membership"] == "invite") || (msg.rawMessage["sender"] != myID && msg.rawContent["membership"] == "join") {
				// NOTICE:
				// IF the sender is ME, take the name of the ROOM to the invite SIDE
				// 	OR
				// IF the sender is NOT ME, take the name of the ROOM to the join SIDE
				name, ok := msg.rawContent["displayname"].(string)
				if !ok {
					return "", errors.New("EMPTY_ROOM")
				}
				return name, nil
			}

			if userID == myID {
				continue
			}
		}

		// No membership messages not related to our id found...
		return "", errors.New("ONLY_YOU")
	}

	message := res.messages[0]
	name, ok := message.rawContent["name"].(string)
	if !ok {
		return "", errors.New("NO_NAME")
	}
	return name, nil
}

func getRoomStart(token string, roomID string) (string, error) {
	t := "m.room.create"
	res, err := getRoomMessages(token, roomID, "b", []string{t})
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

func groupRoomsByName(rooms []*room) map[string][]*room {
	m := map[string][]*room{}
	for _, room := range rooms {
		m[room.name] = append(m[room.name], room)
	}
	return m
}

type userInfo struct {
	Name  string
	Email string
}

var users = map[string]*userInfo{}

func getUserInfo(token string, userID string) (*userInfo, error) {
	if info, ok := users[userID]; ok {
		return info, nil
	}
	resp, err := request(token, baseURL+"/profile/"+userID, nil)
	if err != nil {
		var mError matrixError
		if errors.As(err, &mError) {
			info := &userInfo{userID, "UNKNOWN"}
			users[userID] = info
			return info, nil
		}
		return nil, fmt.Errorf("failed to retrieve user info: %w", err)
	}
	defer resp.Body.Close()
	var respJSON map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&respJSON); err != nil {
		return nil, fmt.Errorf("failed to retrieve user info: %w", err)
	}
	name, ok := respJSON["displayname"]
	if !ok {
		name = userID
	}
	address, ok := respJSON["address"]
	if !ok {
		address = "UNKNOWN"
	}
	info := &userInfo{name, address}
	users[userID] = info
	return info, nil
}

func getPassword(passwordFile string) (string, error) {
	var password []byte
	if passwordFile == "" {
		stdin := int(os.Stdin.Fd())
		if !terminal.IsTerminal(stdin) {
			return "", errors.New("no password file specified and stdin is not a terminal")
		}
		stdout := int(os.Stdout.Fd())
		if !terminal.IsTerminal(stdout) {
			return "", errors.New("no password file specified and stdout is not a terminal")
		}
		fmt.Print("Password: ")
		var err error
		password, err = terminal.ReadPassword(stdin)
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
		err = fmt.Errorf("failed to download %q: %w", info.name, err)
		return
	}
	defer resp.Body.Close()
	if _, err = io.Copy(f, resp.Body); err != nil {
		err = fmt.Errorf("failed to download %q: %w", info.name, err)
		return
	}
	return
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

func init() {
	stdout := windows.Handle(os.Stdout.Fd())
	var originalMode uint32

	windows.GetConsoleMode(stdout, &originalMode)
	windows.SetConsoleMode(stdout, originalMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}

func main() {
	email := flag.String("email", "", "email address")
	roomName := flag.String("room-name", "", "name of the room to export (* to get all)")
	roomID := flag.String("room-id", "", "ID of the room to export (* to get all)")
	passwordFile := flag.String("password-file", "", "file containing password")
	outputDir := flag.String("output-dir", "", "output directory")
	reverse := flag.Bool("reverse", false, "export in reverse chronological order")
	flag.Parse()

	if *email == "" || *roomName == "" && *roomID == "" || *outputDir == "" {
		log.Println("Missing required argument [EMAIL: " + *email + ", ROOM NAME: " + *roomName + ", ROOM ID: " + *roomID + ", OUTPUT DIR: " + *outputDir + "]")
		flag.Usage()
		os.Exit(1)
	}

	password, err := getPassword(*passwordFile)
	if err != nil {
		log.Fatal("Failed to get password: ", err)
	}
	log.Println("Getting access token...")
	token, err := getAccessToken(*email, password)
	if err != nil {
		log.Fatal("Failed to get access token: ", err)
	}

	myID, err := getMyUserID(token)
	if err != nil {
		log.Fatal("Failed to get your identifier ", err)
	}

	log.Println("Getting available rooms...")
	rooms, err := getRooms(token, *roomID, *roomName, myID)
	if err != nil {
		log.Fatal("Failed to get available rooms: ", err)
	}

	var room *room
	if *roomName != "" && *roomID != "" {
		log.Println(colorCyan, "INFO: Both flags room-name and room-id has been specified, use room-id", colorReset)
	}

	log.Println("Export each ROOM")
	for _, r := range rooms {
		if r.id == *roomID || *roomID == "*" {
			room = r
		}

		if room == nil {
			log.Fatalf("Room %q not found", *roomName)
		}
		log.Println(colorReset, "... ROOM", colorCyan, room.name, colorReset)

		log.Println("1-", colorReset, "Fetching room messages...")
		var dir string
		if !*reverse {
			dir = "f"
		}

		res, err := getRoomMessages(token, room.id, dir, []string{"m.room.message"})
		if err != nil {
			log.Fatal(colorRed, "----> Failed to fetch messages:", colorReset, err)
		}

		var sanitizedRoomName = strings.TrimSpace(strings.ReplaceAll(room.name, ":", ""))

		downloadDir := filepath.Join(*outputDir, sanitizedRoomName, contentDir)
		if err := os.MkdirAll(downloadDir, 0755); err != nil {
			log.Fatalf(colorRed+"----> Failed to create download dir %q"+colorReset, downloadDir)
		}
		outputFileName := filepath.Join(*outputDir, sanitizedRoomName, "messages.html")
		output, err := os.Create(outputFileName)
		if err != nil {
			log.Fatalf(colorRed+"----> Failed to create output file %q: %v"+colorReset, outputFileName, err)
		}
		if err := tmpl.Execute(output, res.messages); err != nil {
			log.Fatalf(colorRed+"----> Failed to render output file %q: %v"+colorReset, outputFileName, err)
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
		var errors []error
		if len(infos) > 0 {
			log.Println("2-", colorReset, "Downloading files...")
			errors = downloadFiles(token, infos, downloadDir)
		}
		if len(errors) > 0 {
			log.Println(colorRed, "----> Some errors were encountered while downloading files:", colorReset)
			for _, err := range errors {
				fmt.Println(err)
			}
			log.Println(colorRed, "----> Re-run the same command to retry the download of failed files", colorReset)
		} else {
			log.Printf(colorReset+"     "+colorGreen+"Room has been successfully exported to %q\n"+colorReset, *outputDir)
		}
	}
}
