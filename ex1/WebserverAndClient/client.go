package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
    "bytes"
)

type Data struct {
	ID         uint64 `json:"id"`
	Firstname  string
	Secondname string
	Phone      string
}

var (
	data []Data
)

func sendData() {
	data = []Data{
		{ID: 1, Firstname: "Кантемир", Secondname: "Задорожный", Phone: "+380"},
		{ID: 2, Firstname: "Анна", Secondname: "Задорожная", Phone: "+380"},
		{ID: 3, Firstname: "Виктор", Secondname: "Кондратюк", Phone: "+380"},
		{ID: 4, Firstname: "Алекс", Secondname: "Евтушок", Phone: "+380"},
	}

	out, err := json.Marshal(data)
	if err != nil {
		fmt.Println(err.Error())
	}
	reader := bytes.NewReader(out)
	resp, err := http.Post("http://localhost:8181/showData", "application/json", reader)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer resp.Body.Close()

	if body, err := ioutil.ReadAll(resp.Body); err != nil {
		fmt.Println(err.Error())
		return
	} else {
		fmt.Println(string(body))
	}
}

func main() {
	sendData()
}
