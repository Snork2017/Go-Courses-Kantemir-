package main

import (
	"fmt"
)


type Human struct {
	Name, SurName string
}

type Person struct {
	Name, SurName string
	Age           uint64
	Phone         uint64
	Email         string
}

type Worker struct {
	PersonInfo *Person
}


func (h *Human) happyBday() (string, string, string){
	return "Happy Birthday", h.Name , h.SurName
}

func (w Worker) workerInfo() *Worker{
	 i := Worker{
		PersonInfo:  &Person{
			Name:    "Alex",
			Age:     16,
			SurName: "Evtushok",
			Phone:   380,
			Email:   "***@gmail.com",
		},
	}
	
	return &i
}

func main() {
	// HappyBDAY function
	h := &Human{"Ryan", "Reynolds"}
	fmt.Println(h.happyBday())
	//-------------------------------------
	//Info about Workers
		i := &Worker{}
		fmt.Println(i.workerInfo().PersonInfo)
	//-------------------------------------
}
