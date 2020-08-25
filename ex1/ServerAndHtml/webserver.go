package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"golang.org/x/crypto/bcrypt"
)

type Person struct {
	Email      string
	Password   string
	Hash 	   string
	// Firstname  string
	// SecondName string
}

var cachePeople = map[string]Person{}
var tpl *template.Template

// func init() {
// 	tpl = template.Must(template.ParseGlob("NewSite.html"))
// 	cachePeople["kantemir28@gmail.com"] = Person{"kantemir28@gmail.com", "kant"}
// }

func login(w http.ResponseWriter, r *http.Request) {
	// var request Person
	if r.Method == http.MethodPost {
		eMail := r.FormValue("EMailLog")
		password := r.FormValue("passwordLog")
		user, ok := cachePeople[eMail]
		if !ok {
			http.Error(w, "The user is not registered!", http.StatusForbidden)
			return
		}
		if user.Password != password {
			http.Error(w, "Forbidden, password is incorrect!", http.StatusForbidden)
			return
		}else {
			fmt.Fprintf(w, "%+v\n", "WELCOME TO YOUR ACCOUNT!")
			fmt.Fprintf(w, "E-MAIL : %+v\n", eMail)
		}
	}
}

func signUp(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		eMail := r.FormValue("EMailReg")
		password := r.FormValue("passwordReg")
		hash, _ := HashPassword(password)
		fmt.Println(hash)
		match := CheckPasswordHash(password, hash)
		fmt.Println(match)
		cachePeople[eMail] = Person{Email : eMail, Password : password, Hash: hash}
		fmt.Fprintf(w, "%+v\n", "User is registered succesfully!")
		fmt.Fprintf(w, "E-MAIL : %+v\n Password : %+v\n PasswordHash: %+v\n", eMail, password, hash)
	}
}

func IndexPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		return
	}

	tmpl := template.Must(template.ParseFiles("NewSite.html"))
	if err := tmpl.Execute(w, nil); err != nil {
		fmt.Println("main.go -> IndexPage() -> Execute(): ", err)
	}
}

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

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}
func main() {
	http.HandleFunc("/signUp", signUp)
	http.HandleFunc("/login", login)
	http.HandleFunc("/", IndexPage)
	http.HandleFunc("/showData", showData)
	fmt.Println("Server is listening...")
	if err := http.ListenAndServe(":8180", nil); err != nil {
		fmt.Println("ListenAndServe(): ", err)
	}
}
