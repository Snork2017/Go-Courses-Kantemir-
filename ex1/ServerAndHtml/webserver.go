package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"time"
)

type Person struct {
	//ID       uint64 `json: "id, omitempty"`
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"password"`
	Hash     string `json: "hash, omitempty"`
	// ID
	// Firstname  string
	// SecondName string
}

type Admin struct {
	//ID       uint64 `json: "id, omitempty"`
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"password"`
	Hash     string `json: "hash, omitempty"`
	// ID
	// Firstname  string
	// SecondName string
}

type PizzaAdm struct{
	Name   string   `bson:"name" json:"name"`
	Price  int64	`bson:"price" json:"price,string,omitempty"`
}

var session *mgo.Session
var resultsPerson []Person
var resultsAdmins []Admin
var database string = "developer"
var resultsPizzas []Pizza
var requestPizza Pizza
var resultsOrder []Order
var order Order
var mySigningKey = []byte("MySeretToken")
var pizzaAdm PizzaAdm
var resultsPizzaAdm []PizzaAdm
var jsonPizza Pizza
type Collection struct {
	C *mgo.Collection
}

type Session struct {
	S *mgo.Session
}


type Pizza struct {
	Name   string 	`bson:"name" json:"name"`
	Price  int64	`bson:"price" json:"price,string,omitempty"`
}

type Order struct {
	Pizzas []Pizza    `bson:"pizzas" json:"pizzas"`
	OwnerEmail string `bson:"ownerEmail" json:"ownerEmail"`
}

func (pizza *Collection)deletePizzaFromTrash(c *gin.Context) {
	var p = pizza.C
	var deletePizza string
	err := c.BindJSON(&deletePizza)
	if err != nil {
		fmt.Println("deletePizzaFromTrash() ->", err.Error())
		return
	}
	fmt.Println("deletePizza  ->",	deletePizza)
	filter := bson.M{"pizzas.name" : deletePizza} //////////////////// A MISTAKE
	err = p.Remove(filter)

	if err != nil {
		fmt.Println(err)
		return
	} else {
		for k := range order.Pizzas {
			if order.Pizzas[k].Name == deletePizza {
            	order.Pizzas[k] = order.Pizzas[len(order.Pizzas)-1]
           		order.Pizzas = order.Pizzas[:len(order.Pizzas)-1]
           		break
        	}
			fmt.Println(order.Pizzas[k].Name)
		}	
		fmt.Println("Removed pizza :", filter)
	}
}

func readPizza(c *mgo.Collection, emailCookie string) {
	order = Order{}
	filterPizza := make(map[string]interface{})
	filterPizza["ownerEmail"] = emailCookie
	query := c.Find(filterPizza)
	err := query.One(&order)
	if err != nil {
		fmt.Println("query.All() ->", err)
		return
	}
	for _, value := range order.Pizzas {
		fmt.Println(value)
	}
	fmt.Printf("\n")
}

func (pizza *Collection) pizzaOrder(c *gin.Context){
	p := pizza.C
	emailCookie, err := c.Cookie("email")
	if err != nil {
		fmt.Println("emailCookie() ->", err.Error())
		return 
	} else {
		fmt.Println("emailCookie() -> c.Cookie() -> ", emailCookie)
	}
	err = c.BindJSON(&requestPizza)
	if err != nil {
		fmt.Println("orderPizza() 110 ->", err.Error())
		return
	}
	filterPizza := make(map[string]interface{})
	filterPizza["ownerEmail"] = emailCookie
	err = p.Find(filterPizza).One(&order)
	if err != nil {
		fmt.Println("c.FIND().ONE() ->", err.Error())
		orderPizza := Pizza{
			Name: requestPizza.Name,
			Price: requestPizza.Price,
		}
		pizzas := []Pizza{}
		order.OwnerEmail = emailCookie
		pizzas = append(pizzas, orderPizza)
		order.Pizzas = pizzas
		err = p.Insert(
			&order,
		)
		if err != nil {
			fmt.Println("c.Insert{order} ->", err.Error())
			return 
		}
	} else {
		orderPizza := Pizza{
			Name: requestPizza.Name,
			Price: requestPizza.Price,
		}
		ordPizzas := order.Pizzas
		ordPizzas = append(ordPizzas, orderPizza)
		change := bson.M{
			"$set": bson.M{
				"pizzas": ordPizzas,
			},
		}

		err := p.Update(filterPizza, change)
		if err != nil {
			fmt.Println(err)
			return
		}
		readPizza(p, emailCookie)
		fmt.Println("ORDER", order.OwnerEmail)
		fmt.Println("ORDER", ordPizzas)
	}
	
	if err != nil {
		fmt.Println(err)
		return
	} else {
		fmt.Println("ok!", requestPizza.Name, requestPizza.Price)
	}
	resultsPizzas = append(resultsPizzas, requestPizza)
}

// type Pizza struct {
// 	// .....
// }

// type Order struct {
// 	Pizzas []Pizza
// 	// Pending time
// 	name string
// }




// var count uint64 = 0


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

func readPizzaAdm(c *mgo.Collection) {
	query := c.Find(bson.M{})
	err := query.All(&resultsPizzaAdm)
	if err != nil {
		fmt.Println("query.All() ->", err)
		return
	}
	for _, value := range resultsPizzaAdm{
		fmt.Println(value)
	}

	fmt.Printf("\n")
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

func readOrder(c *mgo.Collection) {
	query := c.Find(bson.M{})
	err := query.All(&resultsOrder)
	if err != nil {
		fmt.Println("query.All() ->", err)
		return
	}
	for _, value := range resultsOrder {
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
}

func bootstrapPizza(s *mgo.Session) *mgo.Collection {
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

func bootstrapOrder(s *mgo.Session) *mgo.Collection {
	c := s.DB(database).C("order")
	index := mgo.Index{
		Key:        []string{"pizzas"},
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

func bootstrapPizzaAdm(s *mgo.Session) *mgo.Collection {
	c := s.DB(database).C("pizzaAdm")
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

func bootstrapAdmins(s *mgo.Session) *mgo.Collection {
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
		c.SetCookie("token", token, 3600, "/", "localhost", false, false)
		c.SetCookie("email", eMail, 3600, "/", "localhost", false, false)
		c.HTML(http.StatusOK, "accountAdmin.html", gin.H{
			"email": eMail,
		})
	}

}

func (people *Collection)loginUser(c *gin.Context) {
	c.Request.ParseForm()
	p := people.C
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
	c.SetCookie("email", eMail, 3600, "/", "localhost", false, false)
	c.HTML(http.StatusOK, "accountUser.html", gin.H{
		"email":  eMail,
	})
	readPizza(p, eMail)
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

func (pizzaAdm *Collection)savePizzaAdmin(c *gin.Context) {
	p := pizzaAdm.C
	err := c.BindJSON(&jsonPizza)
	if err != nil {
		fmt.Println("savePizzaAdmin() =>", err.Error())
		return 
	}
	err = p.Insert(
		&PizzaAdm{Name: jsonPizza.Name, Price: jsonPizza.Price},
	)
	if err != nil {
		fmt.Println(err)
		return
	} else {
		fmt.Println("ok!")
	}
	readPizzaAdm(p)
}

func CheckTokenValidationUsers(c *gin.Context) {
  token, err := c.Cookie("token")
  if err != nil {
  	fmt.Println("c.Cookie() ->", err.Error())
    c.HTML(200, "/user", gin.H{
      "title": "authorisation", //IGNORE THIS
    })
    return
  }else {
  	fmt.Println("c.CookieUser() ->", token)
  }
  return
}

func CheckTokenValidationAdmins(c *gin.Context) {
  token, err := c.Cookie("token")
  if err != nil {
  	fmt.Println("c.Cookie() ->", err.Error())
    c.HTML(200, "/admin", gin.H{
      "title": "authorisation", //IGNORE THIS
    })
    return
  }else {
  	fmt.Println("c.CookieAdmin() ->", token)
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
	var cOrder 	= bootstrapOrder(session)
	var cPizzaAdm = bootstrapPizzaAdm(session)
	admins := &Collection{C: cAdmins}
	people := &Collection{C: cPeople}
	orders  := &Collection{C: cOrder}
	pizza  := &Collection{C: cPizza}
	savePizza := &Collection{C: cPizzaAdm}
	readPeople(cPeople)
	readAdmins(cAdmins)
	readOrder(cOrder)
	readPizzas(cPizza)
	readPizzaAdm(cPizzaAdm)
	fmt.Println("main() -> pizza ->", pizza)
	r := gin.Default()
	r.LoadHTMLGlob("templates/*.html")
	////////////////////////////////////////////////
	r.Static("./admin/png", "./templates")
	r.Static("/user/css", "./templates")
	r.Static("/admin/css", "./templates")
	////////////////////////////////////////////////
	r.GET("/page", func(c *gin.Context) {
		c.HTML(http.StatusOK, "page.html", gin.H{
			"title": "test",
		})
	})
	/////////////////////////////////////// ROUTE ADMIN/////////////////////////////////////////////////
	routeAdmins := r.Group("/admin")
	{
		routeAdmins.GET("/", func(c *gin.Context) {
			c.HTML(http.StatusOK, "Admin.html", gin.H{
				"title": "test",
			})
		})
		routeAdmins.POST("/login", loginAdmin)
		routeAdmins.POST("/signUp", admins.signUpAdmins)
		routeAdmins.Use(CheckTokenValidationAdmins)
		routeAdmins.POST("/sendPizza", savePizza.savePizzaAdmin)
	}
	/////////////////////////////////////// ROUTE USER/////////////////////////////////////////////////
	routeUser := r.Group("/user")
	{

		routeUser.GET("/", func(c *gin.Context) {
			cookieTOKEN, err := c.Cookie("token")
			cookieEMAIL, _   := c.Cookie("email")
			if err != nil {	
				c.HTML(http.StatusOK, "User.html", gin.H{
					"title": "User",
				})
			} else {
				c.HTML(200, "accountUser.html", gin.H{
					"email": cookieEMAIL,
				})
			}
			fmt.Println(cookieTOKEN)
			fmt.Println(cookieEMAIL)
		})
		routeUser.POST("/signUp", people.signUpUsers)
		routeUser.POST("/login", orders.loginUser)
		/////////////////////////////////////////////
		routeUser.Use(CheckTokenValidationUsers)
		routeUser.GET("/logOut", logout)
		routeUser.GET("/pizza", func(c *gin.Context) {

			c.HTML(http.StatusOK, "pizza.html", gin.H{
				"title": "test",
			})
		})
		routeUser.GET("/getPizza", func(c *gin.Context) {
			orderPizzas := order.Pizzas
				c.JSON(200, orderPizzas)
				fmt.Println("getPizza.GET() ->", orderPizzas)

		})
		routeUser.GET("/choosePizzas", func(c *gin.Context) {
			c.JSON(200, resultsPizzaAdm)
			fmt.Println("choosePizzas.GET() ->", resultsPizzaAdm)	

		})
		routeUser.DELETE("/pizzaDelete", orders.deletePizzaFromTrash)
		routeUser.POST("/orderPizza", orders.pizzaOrder)
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	err1 := r.Run()
	if err1 != nil {
		panic(err1)
	}
}