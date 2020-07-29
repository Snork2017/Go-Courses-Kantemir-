package main

import (
	"fmt"
	"math"
)

type Person struct {
	Name, SurName string
	Age           uint64
	Phone         uint64
	Email         string
}

type Worker struct {
	PersonInfo Person
}

type Accountant struct {
	Salary     uint64 `json: "salary"`
	SkillLevel string `json: "skill"`
	PersonInfo Person
}

type Builder struct {
	BuiltHouses  uint64  `json: "builtHouses"`
	WorkingHours float64 `json: "workingHours"`
	WorkerInfo   Worker
}

type Cashier struct {
	OnVacation bool    `json: "onVacation"`
	Cash       float64 `json: "amountOfCash"`
	WorkerInfo Worker
}

type Doctor struct {
	CuredPatiens uint64 `json: "curedPatiens"`
	Patients     uint64 `json: "patiens"`
	WorkerInfo   Worker
}

type Cook struct {
	OnPost     bool    `json: "onPost"`
	Costs      float64 `json: "spendings"`
	WorkerInfo Worker
}

type Nums struct {
	X, Y float64
}

type Human struct {
	Name, SurName string
}

func (h *Human) happyBday() (string, string, string){
	return "Happy Birthday", h.Name , h.SurName
}

func (w * Worker) workerInfo() Worker {
	i := Worker{
		PersonInfo: Person{
			Name:    "Alex",
			Age:     16,
			SurName: "Evtushok",
			Phone:   380,
			Email:   "***@gmail.com",
		},
	}
	return i
}

func main() {
	person1 := Worker{
		PersonInfo: Person{
			Name:    "Kantemir",
			Age:     17,
			SurName: "Zadorozhniy",
			Phone:   380996120749,
			Email:   "***@gmail.com",
		},
	}
	accountant1 := Accountant{
		Salary:     	100525.00,
		SkillLevel: 	"middle",
			PersonInfo: Person{
				Name:    	"Kantemir",
				Age:     	17,
				SurName: 	"Zadorozhniy",
				Phone:   	380996120749,
				Email:   	"***@gmail.com",
			},
	}
	pointerAcc1 := & accountant1
	// HappyBDAY function
	h := &Human{"Ryan", "Reynolds"}
	fmt.Println(h.happyBday())
	//-------------------------------------
	//Info about Workers
		i := &Worker{}
		fmt.Println(i.workerInfo())
	//-------------------------------------
	fmt.Println(person1)
	fmt.Println(pointerAcc1)
	// Calling Panic 
	v := &Nums{1, 2}
	v = nil
	fmt.Println(v.abc())
	// ------------------------------------
}
	//Function to find ABC having 2 numbers
func (v Nums) abc() float64 {
	return math.Sqrt(v.X*v.X + v.Y*v.Y)
}
	//-------------------------------------
