package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func showData(w http.ResponseWriter, r *http.Request) {
  var data []interface{}
	if r.URL.Path != "/showData" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}
	if r.Header.Get("content-type") == "application/json" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(err.Error())
		}
		err = json.Unmarshal(body, &data)
		if err != nil {
			fmt.Println(err.Error())
		}
		for _, v := range data {
      		fmt.Println(v)
    	}
	}
}

func main() {
	http.HandleFunc("/showData", showData)
  fmt.Println("Server is listening...")
	if err := http.ListenAndServe(":8181", nil); err != nil {
		fmt.Println("ListenAndServe(): ", err)
	}
}
