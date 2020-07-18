package main

import (
	"os"
	"fmt"
	"log"
	"time"
	"html"
	"errors"
	"strings"
	"strconv"
	"net/http"

	"golang.org/x/crypto/bcrypt"	
	env "github.com/joho/godotenv"
	"github.com/gin-gonic/gin"	
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"

	
	jwt "github.com/dgrijalva/jwt-go"
)

type Server struct {
	DB     *gorm.DB
	Router *gin.Engine
	// Store  *gormstore.Store
}

type User struct{
	ID                 uint64    `gorm:"primary_key;auto_increment" json:"id"`
	Nickname           string    `gorm:"size:50;not null;unique" json:"nickname" form:"nickname"`
	Email              string    `gorm:"size:100;not null;unique" json:"email" form:"email"`
	Password           string    `gorm:"size:60;not null;" json:"password" form:"password"`
	CreatedAt          time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt          time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
}

func Hash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func (u *User) BeforeSave() error {
	hashedPassword, err := Hash(u.Password)
	if err != nil {
		return err
	}
	u.Password = string(hashedPassword)
	return nil
}

func (u *User) Prepare() {
	u.ID = 0
	u.Nickname = html.EscapeString(strings.TrimSpace(u.Nickname))
	u.Email = html.EscapeString(strings.TrimSpace(u.Email))
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
}

func (s *Server) CreateUser(nickname, email, password string){
	u := User{
		Nickname: nickname,
		Email: email,
		Password: password,
	}
	//!!! do not add !!!
	// u.BeforeSave()
	u.Prepare()
	err := s.DB.Create(&u).Error
	fmt.Println(err)
}

var server = Server{}

func main(){
	var err error
	err = env.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	DbDriver := os.Getenv("DB_DRIV")
	DBURL := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=true", os.Getenv("DB_USER"), os.Getenv("DB_PASS"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME"))
	server.DB, err = gorm.Open(DbDriver, DBURL)
	if err != nil {
		log.Fatalf("Cannot connect to %s database", DbDriver)
	}
	server.DB.AutoMigrate(&User{})
	server.Router = gin.Default()

	// server.CreateUser("test1", "test@test.pl", "1234")
	// server.CreateUser("test2", "test2@test.pl", "zaq1@WSX")

	server.Router.LoadHTMLGlob("templates/*")

	server.Router.GET("/", server.Home)	
	server.Router.POST("/singin", server.SingIn)

	authorized := server.Router.Group("/")
	authorized.Use(isAuthorized())
	{
		authorized.GET("/test", server.Test)
		server.Router.GET("/singout", server.SingOut)
	}

	server.Router.Run(":8080")
}

func (s *Server) Home(c *gin.Context){
	c.HTML(http.StatusOK, "index.gohtml", gin.H{
		"title": "Main website",
	})
}

func (s *Server) Test(c *gin.Context){
	token, err := c.Cookie("session")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "No cookie",
		})
		return
	}

	data, err := s.GetDataFromToken(token)
	if err != nil {		
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
		return
	}
	//test:
	//
	c.JSON(http.StatusOK, data)
	//
}

func (s *Server) SingIn(c *gin.Context){
	var tmpUser, user User
	var err error

	err = c.ShouldBind(&tmpUser)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": err.Error(),
		})
		return
	}

	err = s.DB.Where("email = ?", tmpUser.Email).First(&user).Error
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
		return
	}

	err = VerifyPassword(user.Password, tmpUser.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": err.Error(),
		})
		return
	}

	token, err := CreateToken(user.ID)
	if err != nil {
	   	c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
		})
	   return
	}
	liveTime := 60 * 60 * 1000 // 1 hour
	c.SetCookie("session", token, liveTime, "/", c.Request.Host, false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Login succesfull",
	})
}

func (s *Server) SingOut(c *gin.Context){
	c.SetCookie("session", "", -1, "/", c.Request.Host, false, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "Logout succesfull",
	})
}


func isAuthorized() gin.HandlerFunc {	
	return func (c *gin.Context){
		// _, err := c.Cookie("session")
		token, err := c.Cookie("session")
		if err != nil && TokenValid(token) != nil{
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			return
		}
		c.Next()
	}
}

func CreateToken(userID uint64) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	
	claims["authorized"] = true
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix()

	return token.SignedString([]byte(os.Getenv("API_SECRET")))
}

func TokenValid(tokenString string) error {
	_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("API_SECRET")), nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) GetDataFromToken(tokenString string) (User, error) {
	var err error
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return User{}, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("API_SECRET")), nil
	})
	if err != nil {
		return User{}, err
	}

	var user User
	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		return User{}, errors.New("Token not valid")
	}

	userID, err := strconv.ParseUint(fmt.Sprintf("%.0f", claims["user_id"]), 10, 64)
	if err != nil {
		return User{}, err
	}
	fmt.Println("userid: ", uint64(userID))

	err = s.DB.First(&user, uint64(userID)).Error
	if err != nil {		
		return User{}, err
	}

	return user, nil
}