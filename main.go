package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gopkg.in/go-playground/validator.v9"
)

type MalformedRequest struct {
	Status int
	Msg    string
}

func (mr *MalformedRequest) Error() string {
	return mr.Msg
}

//CheckError checks for errors (internal server errors) and return appropriate error code
func CheckError(w http.ResponseWriter, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

//InitEndPoint allows this endpoint to be accessed by clients
func InitEndPoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
	}
}

//DecodeJSONBody works like a regular request body decoding but handles all errors appropriately
func DecodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	/*if r.Header.Get("Content-Type") != "" {
		fmt.Println(r.Header.Get("Content-Type"))
		value := r.Header.Get("Content-Type")
		if value != "application/json" {
			msg := "Content-Type header is not application/json"
			return &MalformedRequest{Status: http.StatusUnsupportedMediaType, Msg: msg}
		}
	}*/

	//r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	dec := json.NewDecoder(r.Body)
	//dec.DisallowUnknownFields()

	err := dec.Decode(dst)
	if err != nil {
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError

		switch {
		case errors.As(err, &syntaxError):
			msg := fmt.Sprintf("Request body contains badly-formed JSON (at position %d)", syntaxError.Offset)
			return &MalformedRequest{Status: http.StatusBadRequest, Msg: msg}

		case errors.Is(err, io.ErrUnexpectedEOF):
			msg := fmt.Sprintf("Request body contains badly-formed JSON")
			return &MalformedRequest{Status: http.StatusBadRequest, Msg: msg}

		case errors.As(err, &unmarshalTypeError):
			msg := fmt.Sprintf("Request body contains an invalid value for the %q field (at position %d)", unmarshalTypeError.Field, unmarshalTypeError.Offset)
			return &MalformedRequest{Status: http.StatusBadRequest, Msg: msg}

		case strings.HasPrefix(err.Error(), "json: unknown field "):
			fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
			msg := fmt.Sprintf("Request body contains unknown field %s", fieldName)
			return &MalformedRequest{Status: http.StatusBadRequest, Msg: msg}

		case errors.Is(err, io.EOF):
			msg := "Request body must not be empty"
			return &MalformedRequest{Status: http.StatusBadRequest, Msg: msg}

		case err.Error() == "http: request body too large":
			msg := "Request body must not be larger than 1MB"
			return &MalformedRequest{Status: http.StatusRequestEntityTooLarge, Msg: msg}

		default:
			return err
		}
	}

	err = dec.Decode(&struct{}{})
	if err != io.EOF {
		msg := "Request body must only contain a single JSON object"
		return &MalformedRequest{Status: http.StatusBadRequest, Msg: msg}
	}

	return nil
}

//EncodeJSON returns a pretty json response
func EncodeJSON(w http.ResponseWriter, input interface{}) {
	e := json.NewEncoder(w)
	e.SetIndent(" ", "    ")
	e.Encode(&input)
}

//ValidateStructFromRequestBody validates a struct gotten as a result of decoding the request body with Decode. Must be used with the go validator pkg v9. Note that this is just a helper function, nested structs have to be validated manually in the struct field tags. It returns true if no errors were found
func ValidateStructFromRequestBody(w http.ResponseWriter, input interface{}) bool {
	var validate *validator.Validate = validator.New()
	err := validate.Struct(input)
	if err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			fmt.Println(err)
			return false
		}

		for _, err := range err.(validator.ValidationErrors) {
			if err.Tag() == "required" {
				http.Error(w, "The field "+err.Field()+" at "+err.Namespace()+" is required.", http.StatusBadRequest)
				return false
			} else if err.Tag() == "url" {
				http.Error(w, "The value "+err.Value().(string)+" at "+err.Namespace()+" is not a valid URL.", http.StatusBadRequest)
				return false
			} else {
				http.Error(w, "The field "+err.Field()+" at "+err.Namespace()+" is "+err.Tag(), http.StatusBadRequest)
				return false
			}
		}

	}

	return true
}
