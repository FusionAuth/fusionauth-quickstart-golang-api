// tag::package-imports[]
package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt"
)

// end::package-imports[]

// tag::verify-key[]
var verifyKey *rsa.PublicKey

// end::verify-key[]

// tag::main[]
func main() {
	fmt.Println("server")
	handleRequests()
}

// end::main[]

// tag::handlers[]
func handleRequests() {
	http.Handle("/make-change", isAuthorized(makeChange))
	http.Handle("/panic", isAuthorized(panic))
	log.Fatal(http.ListenAndServe(":9001", nil))
}

// end::handlers[]

// tag::panic-function[]
func panic(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		fmt.Fprintf(w, "We've called the police!")
	default:
		fmt.Fprintf(w, "Only POST method is supported.")
	}
}

// end::panic-function[]

// tag::make-change-function[]
func makeChange(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		var total = r.URL.Query().Get("total")
		var message = "We can make change using"
		remainingAmount, err := strconv.ParseFloat(total, 64)
		if err != nil {
			fmt.Fprintf(w, "Problem converting the submitted value to a decimal.  Value submitted: "+total)
			return
		}

		coins := make(map[float64]string)
		coins[.25] = "quarters"
		coins[.10] = "dimes"
		coins[.05] = "nickels"
		coins[.01] = "pennies"

		//since a map is an unordered list, we need another list to maintain the order
		denominationOrder := make([]float64, 0, len(coins))
		for value, _ := range coins {
			denominationOrder = append(denominationOrder, value)
		}

		//then we order the list
		sort.Slice(denominationOrder, func(i, j int) bool {
			return denominationOrder[i] > denominationOrder[j]
		})

		//for each coin in the list, we figure out how many will fit into the remainingAmount
		for counter := range denominationOrder {
			value := denominationOrder[counter]
			coinName := coins[value]
			coinCount := int(remainingAmount / value)
			remainingAmount -= float64(coinCount) * value
			message += " " + strconv.Itoa(coinCount) + " " + coinName
		}

		fmt.Fprintf(w, message)
	default:
		fmt.Fprintf(w, "Only GET method is supported.")
	}

}

// end::make-change-function[]

// tag::authorization[]
func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("Authorization")
		if reqToken != "" {

			splitToken := strings.Split(reqToken, "Bearer ")
			reqToken = splitToken[1]
			token, err := jwt.Parse(reqToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf(("invalid signing method"))
				}
				aud := "e9fdb985-9173-4e01-9d73-ac2d60d1dc8e"
				checkAudience := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
				if !checkAudience {
					return nil, fmt.Errorf(("invalid aud"))
				}
				// verify iss claim
				iss := "http://localhost:9011"
				checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
				if !checkIss {
					return nil, fmt.Errorf(("invalid iss"))
				}

				setPublicKey(token.Header["kid"].(string))
				return verifyKey, nil
			})
			if err != nil {
				fmt.Fprintf(w, err.Error())
			}

			if token.Valid {
				var roles = token.Claims.(jwt.MapClaims)["roles"]
				var validRoles []string

				switch pageToGet := GetFunctionName((endpoint)); pageToGet {
				case "main.panic":
					validRoles = []string{"teller"}
				case "main.makeChange":
					validRoles = []string{"customer", "teller"}
				}

				result := containsRole([]string{roles.([]interface{})[0].(string)}, validRoles)

				if len(result) > 0 {
					endpoint(w, r)
				} else {
					fmt.Fprintf(w, "Proper role not found for user")
				}

			}

		} else {
			fmt.Fprintf(w, "No Authorization Token provided")
		}
	})
}

// end::authorization[]

// tag::set-public-key[]
func setPublicKey(kid string) {
	if verifyKey == nil {
		response, err := http.Get("http://localhost:9011/api/jwt/public-key?kid=" + kid)
		if err != nil {
			log.Fatalln(err)
		}

		responseData, err := io.ReadAll(response.Body)
		if err != nil {
			log.Fatal(err)
		}

		var publicKey map[string]interface{}

		json.Unmarshal(responseData, &publicKey)

		var publicKeyPEM = publicKey["publicKey"].(string)

		var verifyBytes = []byte(publicKeyPEM)
		verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

		if err != nil {
			fmt.Errorf(("problem retreiving public key"))
		}
	}
}

// end::set-public-key[]

// tag::contains-roles[]
// function for finding the intersection of two arrays
func containsRole(roles []string, rolesToCheck []string) []string {
	intersection := make([]string, 0)

	set := make(map[string]bool)

	// Create a set from the first array
	for _, role := range roles {
		set[role] = true // setting the initial value to true
	}

	// Check elements in the second array against the set
	for _, role := range rolesToCheck {
		if set[role] {
			intersection = append(intersection, role)
		}
	}

	return intersection
}

// end::contains-roles[]

// tag::helper[]
func GetFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

// end::helper[]
