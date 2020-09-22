package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	//"github.com/night-codes/mgo-ai"
	"github.com/gin-gonic/gin"
	"html/template"
	"net/http"
	"os"
	"time"
	// "github.com/gorilla/mux"
)

type Person struct {
	//ID       uint64 `json: "id, omitempty"`
	Email    string `bson:"email" form:"email" json:"email"`
	Password string `bson:"password" form:"password" json:"password"`
	Hash     string `json: "hash, omitempty"`
	// ID
	// Firstname  string
	// SecondName string
}

type Admin struct {
	//ID       uint64 `json: "id, omitempty"`
	Email    string `bson:"email" form:"email" json:"email"`
	Password string `bson:"password" form:"password" json:"password"`
	Hash     string `json: "hash, omitempty"`
	// ID
	// Firstname  string
	// SecondName string
}

type Pizza struct {
	Name string `bson:"name" form:"name" json:"name"`
	Size string `bson:"size" form:"size" json:"size"`
}

// type Pizza struct {
// 	// .....
// }

// type Order struct {
// 	Pizzas []Pizza
// 	// Pending time
// 	name string
// }

type Collection struct {
	C *mgo.Collection
}

type Session struct {
	S *mgo.Session
}


// var count uint64 = 0
var session *mgo.Session
var resultsPerson []Person
var resultsAdmins []Admin
var cachePeople = map[string]Person{}
var tpl *template.Template
var database string = "developer"
var resultsPizzas []Pizza
var requestPizza Pizza

// func init() {
// 	tpl = template.Must(template.ParseGlob("NewSite.html"))
// 	cachePeople["kantemir28@gmail.com"] = Person{"kantemir28@gmail.com", "kant"}
// }

var mySigningKey = []byte("MySeretToken")

// func create(c *mgo.Collection) {

// 	err := c.Insert(
// 		&Person{Email: "Dyma@gmail.com", Password: "123", Hash: HashPassword(Password)},
// 	)

// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	fmt.Printf("\n")
// }

func CheckAdminPassword(login, password string) (Admin, error) {
	var admin Admin
	collection := session.DB("developer").C("admins")
	fmt.Printf("Login: %+v\n Password: %+v", login, password)
	err := collection.Find(bson.M{"email": login}).One(&admin)
	fmt.Printf("Admin %+v\n", admin)
	if err != nil {
		fmt.Println("CheckUserPassword() ->", err.Error())
		return Admin{}, err
	}
	if CheckPasswordHash(password, admin.Hash) == true {
		fmt.Println("CheckAdminPassword() ->", password, admin.Hash)
		return admin, nil
	} else {
		return admin, fmt.Errorf("Error: Wrong password or login for this account!")
	}
}

func CheckUserPassword(login, password string) (Person, error) {
	var person Person
	collection := session.DB("developer").C("people")
	fmt.Printf("Login: %+v\n Password: %+v", login, password)
	err := collection.Find(bson.M{"email": login}).One(&person)
	fmt.Printf("Person %+v\n", person)
	if err != nil {
		fmt.Println("CheckUserPassword() ->", err.Error())
		return Person{}, err
	}
	if CheckPasswordHash(password, person.Hash) == true {
		fmt.Println("CheckUserPassword() ->", password, person.Hash)
		return person, nil
	} else {
		return person, fmt.Errorf("Error: Wrong password or login for this account!")
	}
}

func CheckUserInDb(login, password string) (Person, error) {
	var person Person
	hash, err := HashPassword(password)
	if err != nil {
		fmt.Println("HashPassword() ->", err.Error())
		return person, err
	}
	collection := session.DB("developer").C("people")
	err = collection.Find(bson.M{"email": login}).One(&person)
	if err != nil {
		person := Person{
			Email:    login,
			Password: password,
			Hash:     hash,
		}
		return person, nil
	}
	return Person{}, fmt.Errorf("User was not found!")
}

func CheckAdminInDb(login, password string) (Admin, error) {
	var admin Admin
	hash, err := HashPassword(password)
	if err != nil {
		fmt.Println("HashPassword() ->", err.Error())
		return admin, err
	}
	collection := session.DB("developer").C("admins")
	err = collection.Find(bson.M{"email": login}).One(&admin)
	if err != nil {
		admin := Admin{
			Email:    login,
			Password: password,
			Hash:     hash,
		}
		return admin, nil
	}
	return Admin{}, fmt.Errorf("User was not found!")
}

func CreateToken(userName string, userPassword string) (string, error) {
	var err error
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", "jdnfksdmfksd") //this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_name"] = userName
	atClaims["user_password"] = userPassword
	atClaims["exp"] = time.Now().Add(time.Minute * 15)
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return "", err
	}
	return token, nil
}

func readPeople(c *mgo.Collection) {
	query := c.Find(bson.M{})
	err := query.All(&resultsPerson)
	if err != nil {
		fmt.Println("query.All() ->", err)
		return
	}
	for _, value := range resultsPerson {
		fmt.Println(value)
	}

	fmt.Printf("\n")
}

func readAdmins(c *mgo.Collection) {
	query := c.Find(bson.M{})
	err := query.All(&resultsAdmins)
	if err != nil {
		fmt.Println("query.All() ->", err)
		return
	}
	for _, value := range resultsAdmins {
		fmt.Println(value)
	}

	fmt.Printf("\n")
}

func readPizzas(c *mgo.Collection) {
	query := c.Find(bson.M{})
	err := query.All(&resultsPizzas)
	if err != nil {
		fmt.Println("query.All() ->", err)
		return
	}
	for _, value := range resultsPizzas {
		fmt.Println(value)
	}

	fmt.Printf("\n")
	return
}

func bootstrapPizza(s *mgo.Session) *mgo.Collection {
	s.DB(database).DropDatabase()
	c := s.DB(database).C("pizza")
	index := mgo.Index{
		Key:        []string{"name"},
		Unique:     true,
		Background: true,
	}
	err := c.EnsureIndex(index)
	if err != nil {
		fmt.Println("EnsureIndex() ->", err.Error())
		return nil
	}

	return c
}

func bootstrapPeople(s *mgo.Session) *mgo.Collection {
	s.DB(database).DropDatabase()
	c := s.DB(database).C("people")
	index := mgo.Index{
		Key:        []string{"email"},
		Unique:     true,
		Background: true,
	}
	err := c.EnsureIndex(index)
	if err != nil {
		fmt.Println("EnsureIndex() ->", err.Error())
		return nil
	}

	return c
}

func bootstrapAdmins(s *mgo.Session) *mgo.Collection {
	s.DB(database).DropDatabase()
	c := s.DB(database).C("admins")
	index := mgo.Index{
		Key:        []string{"email"},
		Unique:     true,
		Background: true,
	}
	err := c.EnsureIndex(index)
	if err != nil {
		fmt.Println("EnsureIndex() ->", err.Error())
		return nil
	}

	return c
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func loginAdmin(c *gin.Context) {
	c.Request.ParseForm()
	eMail := c.PostForm("EMailLog")
	password := c.PostForm("passwordLog")
	token, err := CreateToken(eMail, password)
	if err != nil {
		token = "nil"
		fmt.Println("CreateToken() ->", err.Error())
		return
	} else {
		fmt.Println(http.StatusOK, "Token: %+v\n", token)
	}
	admin, err := CheckAdminPassword(eMail, password)
	if err != nil {
		token = "nil"
		c.HTML(http.StatusForbidden, "GG: %+v\n", err.Error())
		return
	} else {
		fmt.Println(http.StatusOK, "Admin: %+v\n", admin)
		// cookie, err := c.Cookie("token")
		// if err != nil {
		// c.SetCookie("token", token, 3600, "/", "localhost", false, false)
		c.HTML(http.StatusOK, "accountAdmin.html", gin.H{
			"email": eMail,
			"token": token,
			"admin": admin,
		})
		// c.String(http.StatusOK, "Cookie: %+v\n", cookie)
		// }
	}

}

func loginUser(c *gin.Context) {
	c.Request.ParseForm()
	eMail := c.PostForm("EMailLog")
	password := c.PostForm("passwordLog")
	token, err := CreateToken(eMail, password)
	if err != nil {
		token = "nil"
		fmt.Println("CreateToken() ->", err.Error())
		return
	} else {
		fmt.Println(http.StatusOK, "Token: %+v\n", token)
	}
	person, err := CheckUserPassword(eMail, password)
	if err != nil {
		token = "nil"
		c.HTML(http.StatusForbidden, "GG: %+v\n", err.Error())
		return
	} 
	fmt.Println(http.StatusOK, "Person: %+v\n", person)
	c.SetCookie("token", token, 3600, "/", "localhost", false, false)
	c.HTML(http.StatusOK, "accountUser.html", gin.H{
			"email":  eMail,
	})
		// c.String(http.StatusOK, "Cookie: %+v\n", cookie)
		// }
}

func (people *Collection) signUpUsers(c *gin.Context) {
	c.Request.ParseForm()
	// var person Person
	p := people.C
	eMail := c.PostForm("EMailReg")
	password := c.PostForm("passwordReg")
	user, err := CheckUserInDb(eMail, password)
	if err != nil {
		c.String(http.StatusForbidden, "User is already exist!", err.Error())
		return
	} else {
		fmt.Println("CheckUserInDb() ->", user)
	}
	hash, _ := HashPassword(password)
	fmt.Println(hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println(match)
	err = p.Insert(
		&Person{Email: eMail, Password: password, Hash: hash},
	)
	if err != nil {
		fmt.Println(err)
		return
	} else {
		fmt.Println("ok!")
	}
	c.String(http.StatusOK, "%+v\n", "User is registered succesfully!")
	c.String(http.StatusOK, "E-MAIL : %+v\n Password : %+v\n PasswordHash: %+v\n", eMail, password, hash)
	readPeople(p)
}

func (people *Collection) signUpAdmins(c *gin.Context) {
	c.Request.ParseForm()
	// var person Person
	p := people.C
	eMail := c.PostForm("EMailReg")
	password := c.PostForm("passwordReg")
	admin, err := CheckAdminInDb(eMail, password)
	if err != nil {
		c.String(http.StatusForbidden, "Admin is already exist!", err.Error())
		return
	} else {
		fmt.Println("CheckAdminInDb() ->", admin)
	}
	hash, _ := HashPassword(password)
	fmt.Println(hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println(match)
	err = p.Insert(
		&Admin{Email: eMail, Password: password, Hash: hash},
	)
	if err != nil {
		fmt.Println(err)
		return
	} else {
		fmt.Println("ok!")
	}
	c.String(http.StatusOK, "%+v\n", "Admin is registered succesfully!")
	c.String(http.StatusOK, "E-MAIL : %+v\n Password : %+v\n PasswordHash: %+v\n", eMail, password, hash)
	readAdmins(p)
}

func showData(c *gin.Context) {
	var data interface{}
	c.BindJSON(&data)
	c.JSON(200, data)
	fmt.Println("DATA", data)
}

func (pizza *Collection) orderPizza(c *gin.Context){
	p := pizza.C
	err := c.BindJSON(&requestPizza)
	if err != nil {
		fmt.Println("orderPizza() ->", err.Error())
		return
	}
	err = p.Insert(
		&Pizza{Name: requestPizza.Name, Size: requestPizza.Size},
	)
	if err != nil {
		fmt.Println(err)
		return
	} else {
		fmt.Println("ok!", requestPizza.Name, requestPizza.Size)
	}
	resultsPizzas = append(resultsPizzas, requestPizza)
}

func CheckTokenValidation(c *gin.Context) {
  _, err := c.Cookie("token")
  if err != nil {
    c.HTML(200, "/user", gin.H{
      "title": "authorisation", //IGNORE THIS
    })
    return
  }
  return
}

func logout(c *gin.Context) {
	// Clear the cookie
	c.SetCookie("token", "", -1, "", "", false, true)
	c.Set("isLoggedIn", false)
	// Redirect to the home page
	fmt.Println("Redirecting to /log-in from logout")
	c.Redirect(http.StatusFound, "/")
}

func main() {
	var err error
	session, err = mgo.Dial("mongodb://localhost:27017/" + database)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Cleanup
	defer session.Close()
	var cAdmins = bootstrapAdmins(session)
	var cPeople = bootstrapPeople(session)
	var cPizza 	= bootstrapPizza(session)
	admins := &Collection{C: cAdmins}
	people := &Collection{C: cPeople}
	pizza  := &Collection{C: cPizza}
	readPeople(cPeople)
	readAdmins(cAdmins)
	readPizzas(cPizza)
	r := gin.Default()
	r.Use(gin.Recovery(), gin.Logger())
	r.LoadHTMLGlob("templates/*.html")
	r.Static("/user/css", "./templates")
	r.Static("./css", "./templates")
	r.GET("/page", func(c *gin.Context) {
		c.HTML(http.StatusOK, "page.html", gin.H{
			"title": "test",
		})
	})
	r.POST("/showData", showData)
	routeAdmins := r.Group("/admin")
	{
		routeAdmins.GET("/", func(c *gin.Context) {
			c.HTML(http.StatusOK, "Admin.html", gin.H{
				"title": "test",
			})
		})
		routeAdmins.POST("/signUp", admins.signUpAdmins)
		routeAdmins.POST("/login", loginAdmin)
	}
	routeUser := r.Group("/user")
	{
		routeUser.GET("/", func(c *gin.Context) {
			c.HTML(http.StatusOK, "User.html", gin.H{
				"title": "test",
			})
		})
		routeUser.POST("/signUp", people.signUpUsers)
		routeUser.POST("/login", loginUser)
		routeUser.Use(CheckTokenValidation)
		routeUser.GET("/logOut", logout)
		routeUser.GET("/pizza", func(c *gin.Context) {
			c.HTML(http.StatusOK, "pizza.html", gin.H{
				"title": "test",
			})
		})
		routeUser.GET("/getPizza", func(c *gin.Context) {
			c.JSON(200, resultsPizzas)
			fmt.Println("routerUser.GET() ->", requestPizza)
		})
		routeUser.POST("/orderPizza", pizza.orderPizza)
	}
	err1 := r.Run()
	if err1 != nil {
		panic(err1)
	}
}