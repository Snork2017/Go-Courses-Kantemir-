package main

import (
	"fmt"
)

type Worker struct{
	ID uint64
	FirstName string
	Age uint64
	Salary float64
	onVacation bool
}

var (
	workers []Worker
)

func main(){
	workers = []Worker{  
        {ID: 1, FirstName: "Alex", Age: 18, Salary: 55000.00, onVacation: true},    
        {ID: 2, FirstName: "Kantemir", Age: 17, Salary: 45000.00, onVacation: true},    
        {ID: 3, FirstName: "Daymond", Age: 19, Salary: 76000.00, onVacation: false},   
    } 
	fmt.Println(workers[0])
	fmt.Println(workers[1])
	fmt.Println(workers[2])
}
