package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gomodule/redigo/redis"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gopkg.in/go-playground/validator.v9"
)

//MalformedRequest represents the structure for error messages associated with a bad request
type MalformedRequest struct {
	Status int
	Msg    string
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type JwtToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

//InitEndpointOptions is used with the InitEndPointWithOptions function
type InitEndpointOptions struct {
	Methods string
	Origin  string
}

//ContextKey defines a custom type for keys in context values
type ContextKey string

func (mr *MalformedRequest) Error() string {
	return mr.Msg
}

//InitEndpointWithOptions is a variant of InitEndpointWithOptions.
func InitEndpointWithOptions(w http.ResponseWriter, r *http.Request, options InitEndpointOptions) {
	w.Header().Set("Access-Control-Allow-Origin", options.Origin)
	w.Header().Set("Access-Control-Allow-Methods", options.Methods)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
	}
}

//DecodeJSONBody works like a regular request body decoding but handles all errors appropriately
func DecodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	if r.Header.Get("Content-Type") != "" {
		fmt.Println(r.Header.Get("Content-Type"))
		value := r.Header.Get("Content-Type")
		if value != "application/json" {
			msg := "Content-Type header is not application/json"
			return &MalformedRequest{Status: http.StatusUnsupportedMediaType, Msg: msg}
		}
	}

	//r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

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
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
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

//CreateToken
func CreateToken(accessTokenSecret string, refreshTokenSecret string, userid string) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	accessUUID := primitive.NewObjectID().Hex()
	td.AccessUuid = accessUUID

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	refreshUUID := primitive.NewObjectID().Hex()

	td.RefreshUuid = refreshUUID

	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userid
	atClaims["exp"] = td.AtExpires

	var err error

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(accessTokenSecret))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token

	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = userid
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(refreshTokenSecret))
	if err != nil {
		return nil, err
	}
	return td, nil
}

//CreateAuth saves the refresh token and access token metadata in a redis store
func CreateAuth(userid string, td *TokenDetails, redisStore redis.Conn) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	_, errAccess := redisStore.Do("SETEX", td.AccessUuid, strconv.Itoa(int(at.Sub(now).Seconds())), userid)
	if errAccess != nil {
		return errAccess
	}
	_, errRefresh := redisStore.Do("SETEX", td.RefreshUuid, strconv.Itoa(int(rt.Sub(now).Seconds())), userid)
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}
