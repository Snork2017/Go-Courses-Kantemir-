package main

import (
	"fmt"
)

type Person struct {
	Name, SurName string
	Age           uint64
	Phone         int64
	Email         string
}

type Worker struct {
	PersonInfo Person
}

type Accountant struct {
	Salary     uint64 `json: "salary"`
	SkillLevel string `json: "skill"`
	WorkerInfo Worker
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
	Patients     uint64 `json: "illPatiens"`
	WorkerInfo   Worker
}

type Cook struct {
	OnPost     bool    `json: "onPost"`
	Costs      float64 `json: "spendings"`
	WorkerInfo Worker
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
		Salary:     100525.00,
		SkillLevel: "middle",
		WorkerInfo: Worker{
			PersonInfo: Person{
				Name:    "Kantemir",
				Age:     17,
				SurName: "Zadorozhniy",
				Phone:   380996120749,
				Email:   "***@gmail.com",
			},
		},
	}
	fmt.Println(person1)
	fmt.Println(accountant1)
}
